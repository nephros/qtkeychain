/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"
#include "sailfishsecretsstore_p.h"
#include "plaintextstore_p.h"

#include <QTimer>
#include <QScopedPointer>
#include <QDebug>
#include <QMetaEnum>

//#include <QDBusError>
using namespace QKeychain;

static SailfishSecretStore *secretsStore = new SailfishSecretStore();

enum SailfishSecretStoreError {
    CollectionCreateError,
    CollectionListError,
    CollectionOpenError,
    ManagerError,
    SecretDeleteError,
    SecretFindError,
    SecretListError,
    SecretReadError,
    SecretWriteError,
    SecretUpdateError,
};

static const QMap<enum SailfishSecretStoreError, QString> messages {
        { ManagerError,          QT_TR_NOOP("Secret manager not available!") },

        { CollectionCreateError, QT_TR_NOOP("Create password store")  },
        { CollectionOpenError,   QT_TR_NOOP("Open password store")  },
        { CollectionListError,   QT_TR_NOOP("Find password store") },

        { SecretListError,       QT_TR_NOOP("Enumerate passwords") },
        { SecretFindError,       QT_TR_NOOP("Find password") },
        { SecretDeleteError,     QT_TR_NOOP("Delete password") },
        { SecretReadError,       QT_TR_NOOP("Retrieve password") },
        { SecretWriteError,      QT_TR_NOOP("Store password") },
        { SecretUpdateError,     QT_TR_NOOP("Updating passwords is not supported yet") }
};

static void onErrorChanged()
{
    auto e = secretsStore->lastError();
    // from keychain.h:
    //
    // NoError=0, /**< No error occurred, operation was successful */
    // EntryNotFound, /**< For the given key no data was found */
    // CouldNotDeleteEntry, /**< Could not delete existing secret data */
    // AccessDeniedByUser, /**< User denied access to keychain */
    // AccessDenied, /**< Access denied for other reasons */
    // NoBackendAvailable, /**< No platform-specific keychain service available */
    // NotImplemented, /**< Not implemented on platform */
    // OtherError /**< Something else went wrong (errorString() might provide details) */

    // (some selected) from Sailfish/Secrets/result.h
    QKeychain::Error qe;
    switch (e.errorCode()) {
        case Sailfish::Secrets::Result::NoError:
             qe = QKeychain::NoError;
             break;
        case Sailfish::Secrets::Result::UnknownError:
             qe = QKeychain::OtherError;
             break;

        case Sailfish::Secrets::Result::PermissionsError:
        case Sailfish::Secrets::Result::IncorrectAuthenticationCodeError:
        case Sailfish::Secrets::Result::CollectionIsLockedError:
        case Sailfish::Secrets::Result::SecretsDaemonLockedError:
        case Sailfish::Secrets::Result::SecretsPluginIsLockedError:
             qe = QKeychain::AccessDenied;
             break;

        case Sailfish::Secrets::Result::InteractionViewUserCanceledError:
             qe = QKeychain::AccessDeniedByUser;
             break;
        case Sailfish::Secrets::Result::OperationNotSupportedError:
             qe = QKeychain::NotImplemented;
             break;
        case Sailfish::Secrets::Result::DaemonError:
        case Sailfish::Secrets::Result::SecretManagerNotInitializedError:
        case Sailfish::Secrets::Result::DatabaseError:
        case Sailfish::Secrets::Result::InvalidExtensionPluginError:
            qe = QKeychain::NoBackendAvailable;
            break;
        case Sailfish::Secrets::Result::SecretAlreadyExistsError:
            qe = QKeychain::CouldNotDeleteEntry;
            break;
        default:
            qWarning() << "Unknown error:" << e.errorCode();
            qe = QKeychain::OtherError;
    }
    qDebug() << "Saw an error:"
             << e.errorCode()
             << e.errorMessage()
             << qe;
}

void ReadPasswordJobPrivate::scheduledStart() {

    Sailfish::Secrets::StoredSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection  = secretsStore->formatCollectionName(service);
    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, messages[ManagerError] );
        return;
    }

    if (!secretsStore->getCollection(collection)) {
//        qWarning() << "Failed to list secret collections:" << secretsStore->lastError().errorMessage();
        auto ec = secretsStore->lastError().errorCode();
        auto em = secretsStore->lastError().errorMessage();
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser, messages[CollectionOpenError] + ": " + em);
        } else if (ec == Sailfish::Secrets::Result::CollectionIsLockedError) {
            q->emitFinishedWithError( AccessDenied, messages[CollectionOpenError] + ": " + em);
        } else {
            q->emitFinishedWithError( OtherError, messages[CollectionOpenError] + ": " + em);
        }
        return;
    }

    sid = secretsStore->createIdentifier(collection, key);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to create identifier!"));
        return;
    }
    request = secretsStore->getReadRequest(sid);
    request->startRequest();
    request->waitForFinished();
    if (request->result().code() == Sailfish::Secrets::Result::Failed) {
        auto ec = secretsStore->lastError().errorCode();
        auto em = secretsStore->lastError().errorMessage();
        qWarning() << "Failed to retrieve secret:" << ec << em;
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser,  messages[SecretReadError] + ": " + em);
        } else {
            q->emitFinishedWithError( EntryNotFound, messages[SecretReadError] + ": " + em);
        }
        return;
    } else {
        qDebug() << "Secret data retrieved:"
                 << "type" << request->secret().type() << ","
                 << request->secret().data().length() << "bytes";
        // possible types: Unknown Blob CryptoKey
        // FIXME: is CryptoKey text or binary?
        mode = (request->secret().type() == Sailfish::Secrets::Secret::TypeBlob)
               ? Mode::Binary
               : Mode::Text;
        data = request->secret().data();
        q->emitFinished();
        return;
    }
    q->emitFinishedWithError( OtherError, tr("Unknown error") );
}

/*
void ReadPasswordJobPrivate::fallbackOnError(const QDBusError& err )
{
    PlainTextStore plainTextStore( q->service(), q->settings() );

    if ( q->insecureFallback() && plainTextStore.contains( key ) ) {
        mode = plainTextStore.readMode( key );
        data = plainTextStore.readData( key );

        if ( plainTextStore.error() != NoError )
            q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
        else
            q->emitFinished();
    } else {
        if ( err.type() == QDBusError::ServiceUnknown ) //KWalletd not running
            q->emitFinishedWithError( NoBackendAvailable, tr("No keychain service available") );
        else
            q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
    }
}
*/

void WritePasswordJobPrivate::scheduledStart()
{
    Sailfish::Secrets::StoreSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    Sailfish::Secrets::Secret* secret;
    const QString collection  = secretsStore->formatCollectionName(service);

    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, messages[ManagerError] );
        return;
    }

    /* check for collection, create if necessary */
    if (!secretsStore->getCollection(collection)) {
        auto ec = secretsStore->lastError().errorCode();
        auto em = secretsStore->lastError().errorMessage();
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser,  messages[CollectionCreateError] + ": " + em);
        } else if (ec == Sailfish::Secrets::Result::CollectionIsLockedError) {
                q->emitFinishedWithError( AccessDenied, messages[CollectionCreateError] + ": " + em );
        } else {
            q->emitFinishedWithError( OtherError, messages[CollectionCreateError] + ": " + em );
        }
        return;
    }

    /* check for existing secrets, reuse ID if found: */
    QVector<Sailfish::Secrets::Secret::Identifier> ids;
    if (!secretsStore->listSecrets(service, collection, &ids)) {
        auto ec = secretsStore->lastError().errorCode();
        auto em = secretsStore->lastError().errorMessage();
        QString message(messages[SecretListError] + ": " + em);
        qWarning() << "Could not list secrets:" << em;
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser, message);
        } else if (ec == Sailfish::Secrets::Result::CollectionIsLockedError) {
            q->emitFinishedWithError( AccessDenied, message);
        } else {
            q->emitFinishedWithError( OtherError, message);
        }
        return;
    }
    // update case: use found identifier:
    foreach(auto id, ids) {
        if (id.name() == key) {
            qDebug() << "Want to update secret:"
                     << "Identifier: " << id.name();
            sid = id;
            break;
        }
    }
    if (!sid.isValid()) {
        sid = secretsStore->createIdentifier(collection, key);
        qDebug() << "Creating new secret"
                 << "Identifier:" << sid.name();
    }

    if (!sid.isValid()) {
        qWarning() << "Failed to create valid secret identifier!";
        q->emitFinishedWithError( OtherError, tr("Failed to create identifier!"));
        return;
    }

    secret = new Sailfish::Secrets::Secret();
    secret->setIdentifier(sid);
    secret->setCollectionName(collection);
    secret->setData(data);
    if (this->mode == Mode::Binary)
        secret->setType(Sailfish::Secrets::Secret::TypeBlob);

    request = secretsStore->getWriteRequest(service, secret);
    QObject::connect(request, &Sailfish::Secrets::Request::statusChanged,
                    [=]() {
                        auto ec = request->result().errorCode();
                        auto em = request->result().errorMessage();
                        qDebug() << request->result().code() << ":" << ec;
                        if(request->result().code() == Sailfish::Secrets::Result::Succeeded) {
                            q->emitFinished();
                        } else if (request->result().code() == Sailfish::Secrets::Result::Failed) {
                            qWarning() << "Failed to store secret:" << ec << em;
                            q->emitFinishedWithError( OtherError, messages[SecretWriteError] + ": " + em);
                        }
                    });
    request->startRequest();
    request->waitForFinished();
}

/*
void WritePasswordJobPrivate::fallbackOnError(const QDBusError &err)
{
    if ( !q->insecureFallback() ) {
        q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2").arg( QDBusError::errorString( err.type() ), err.message() ) );
        return;
    }

    PlainTextStore plainTextStore( q->service(), q->settings() );
    plainTextStore.write( key, data, mode );

    if ( plainTextStore.error() != NoError )
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
    else
        q->emitFinished();
}
*/

void DeletePasswordJobPrivate::scheduledStart()
{
    Sailfish::Secrets::DeleteSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection = secretsStore->formatCollectionName(service);

    bool lastEntry = false;

    // delete collection if empty
    QVector<Sailfish::Secrets::Secret::Identifier> ids;
    bool ok = secretsStore->listSecrets(service, collection, &ids);
    if (!ok) {
        q->emitFinishedWithError( OtherError, tr("Could not list secrets") );
        return;
    }
    if (ids.count() == 0) {
        qWarning() << "Found no secrets to delete!";
        q->emitFinishedWithError( EntryNotFound, messages[SecretFindError] + ": " + "Found no secrets to delete!" );
        return;
    }

    lastEntry = ids.count() == 1;

    sid = secretsStore->createIdentifier(collection, key);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        auto em = secretsStore->lastError().errorMessage();
        q->emitFinishedWithError( EntryNotFound, tr("Failed to create identifier!"));
        return;
    }
    request = secretsStore->getDeleteRequest(sid);
    request->startRequest();
    request->waitForFinished();
    if (request->result().code() == Sailfish::Secrets::Result::Failed) {
        auto em = request->result().errorMessage();
        qWarning() << "Failed to delete secret:" << em;
        q->emitFinishedWithError( OtherError, messages[SecretDeleteError] + ": " + em );
        return;
    } else {
        q->emitFinished();
        if (lastEntry) {
            qDebug() << "Last secret deleted, removing collection";
            //QTimer::singleShot(200, [=]() { secretsStore->deleteCollection(collection); });
            secretsStore->deleteCollection(collection);
        }
        return;
    }

    q->emitFinishedWithError( OtherError, tr("Unknown error") );
}

/*
void DeletePasswordJobPrivate::fallbackOnError(const QDBusError &err)
{
    QScopedPointer<QSettings> local( !q->settings() ? new QSettings( q->service() ) : 0 );
    QSettings* actual = q->settings() ? q->settings() : local.data();

    if ( !q->insecureFallback() ) {
        q->emitFinishedWithError( OtherError, tr("Could not open wallet: %1; %2")
                                  .arg( QDBusError::errorString( err.type() ), err.message() ) );
        return;
    }

    actual->remove( key );
    actual->sync();

    q->emitFinished();

}
*/

bool QKeychain::isAvailable()
{
    if  (secretsStore != nullptr) {
        QObject::connect(secretsStore, &SailfishSecretStore::errorChanged,
                         [=]() { onErrorChanged(); });
        return true;
    }
    return false;
}
