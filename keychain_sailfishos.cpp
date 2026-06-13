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

//#include <QDir>
#include <QScopedPointer>
#include <QDebug>

using namespace QKeychain;

class FallbackStore {

public:
    FallbackStore(QKeychain::JobPrivate *j){
        if (j->q->insecureFallback()) {
            valid = true;
            job = j; q=j->q;
//            q->settings()->setPath(QSettings::IniFormat, QSettings::UserScope, this->settingsPath);
        }
    }
    void Read();
    void Write();
    void Delete();
    bool isValid() { return valid; };
protected:
    /*
    const QString settingsPath = QString(QDir::homePath()
                                         + "/.local/share"
                                         + "/" + QCoreApplication::organizationName()
                                         + "/" + QCoreApplication::applicationName());
    */
private:
    QKeychain::JobPrivate* job = nullptr;
    QKeychain::Job* q = nullptr;
    bool valid = false;
};

void FallbackStore::Read()
{
    PlainTextStore plainTextStore( q->service(), q->settings() );

    if ( q->insecureFallback() && plainTextStore.contains( q->key() ) ) {
        job->mode = plainTextStore.readMode( q->key() );
        job->data = plainTextStore.readData( q->key() );

        if ( plainTextStore.error() != NoError )
            q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
        else
            q->emitFinished();
    } else {
        q->emitFinishedWithError( NoBackendAvailable, q->tr("No keychain service available") );
    }
}

void FallbackStore::Write()
{
    if ( !q->insecureFallback() ) {
        q->emitFinishedWithError( NoBackendAvailable, q->tr("No keychain service available") );
        return;
    }

    PlainTextStore plainTextStore( q->service(), q->settings() );
    plainTextStore.write( q->key(), job->data, job->mode );

    if ( plainTextStore.error() != NoError )
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
    else
        q->emitFinished();
}

void FallbackStore::Delete()
{
    if ( !q->insecureFallback() ) {
        q->emitFinishedWithError( NoBackendAvailable, q->tr("No keychain service available") );
        return;
    }

    QScopedPointer<QSettings> local( !q->settings() ? new QSettings( q->service() ) : 0 );
    QSettings* actual = q->settings() ? q->settings() : local.data();

    actual->remove( q->key() );
    actual->sync();

    q->emitFinished();

}


static SailfishSecretStore *secretsStore = new SailfishSecretStore();

enum SailfishSecretStoreOperation {
    CollectionCreate,
    CollectionList,
    CollectionOpen,
    Manager,
    SecretDelete,
    SecretFind,
    SecretList,
    SecretRead,
    SecretWrite,

    Other
};

static const QMap<enum SailfishSecretStoreOperation, QString> messages {
        { Manager,          QT_TR_NOOP("No keychain service available") },

        { CollectionCreate, QT_TR_NOOP("Create password store")  },
        { CollectionOpen,   QT_TR_NOOP("Open password store")  },
        { CollectionList,   QT_TR_NOOP("Find password store") },

        { SecretList,       QT_TR_NOOP("Find password entry") },
        { SecretFind,       QT_TR_NOOP("Find password") },
        { SecretDelete,     QT_TR_NOOP("Remove password") },
        { SecretRead,       QT_TR_NOOP("Retrieve password") },
        { SecretWrite,      QT_TR_NOOP("Store password") },

        { Other,            QT_TR_NOOP("Unknown operation") }
};

static QPair<QKeychain::Error, QString> errorForError(const Sailfish::Secrets::Result r)
{
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
    qDebug()  << Q_FUNC_INFO;
    QKeychain::Error qe;
    QString msg = r.errorMessage();
    auto ec = r.errorCode();
    switch (ec) {
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
        case Sailfish::Secrets::Result::InvalidExtensionPluginError:
            qe = QKeychain::NoBackendAvailable;
            break;
        case Sailfish::Secrets::Result::SecretAlreadyExistsError:
            qe = QKeychain::CouldNotDeleteEntry;
            break;
        /* TODO: Analyze the text, create message */
        case Sailfish::Secrets::Result::DatabaseError:
            msg = QT_TR_NOOP("Database query failed");
            break;
        default:
            qWarning() << "Unknown error:" << ec;
            qe = QKeychain::OtherError;
    }
    return QPair<QKeychain::Error, QString>(qe, msg);
}

static QPair<const QKeychain::Error, QString> formatError(
       const enum SailfishSecretStoreOperation op,
       const Sailfish::Secrets::Result r)
{
    qDebug()  << Q_FUNC_INFO;
    auto details =  errorForError(r);
    return QPair<QKeychain::Error, QString> (
                 details.first,
                 messages[op] + ": " + details.second);
}

static void onErrorChanged()
{
    auto e = secretsStore->lastError();
    qDebug() << "Saw an error:"
             << e.errorCode()
             << e.errorMessage();
}

void ReadPasswordJobPrivate::scheduledStart() {

    Sailfish::Secrets::StoredSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection  = secretsStore->formatCollectionName(service);
    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        FallbackStore fallback(this);
        if (fallback.isValid()) fallback.Read();
        return;
    }

    if (!secretsStore->getCollection(collection)) {
//        qWarning() << "Failed to list secret collections:" << secretsStore->lastError().errorMessage();
//        auto ec = secretsStore->lastError().errorCode();
//        auto em = secretsStore->lastError().errorMessage();
        auto error = formatError(CollectionOpen, secretsStore->lastError());
        q->emitFinishedWithError( error.first, error.second );
        /*
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser, messages[CollectionOpen] + ": " + em);
        } else if (ec == Sailfish::Secrets::Result::CollectionIsLockedError) {
            q->emitFinishedWithError( AccessDenied, messages[CollectionOpen] + ": " + em);
        } else {
            q->emitFinishedWithError( OtherError, messages[CollectionOpen] + ": " + em);
        }
        */
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
        auto error = formatError(SecretRead, request->result());
        q->emitFinishedWithError( error.first, error.second );
        /*
        auto ec = secretsStore->lastError().errorCode();
        auto em = secretsStore->lastError().errorMessage();
        qWarning() << "Failed to retrieve secret:" << ec << em;
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser,  messages[SecretRead] + ": " + em);
        } else {
            q->emitFinishedWithError( EntryNotFound, messages[SecretRead] + ": " + em);
        }
        */
        return;
    } else {
        qDebug() << "Secret data retrieved:"
                 << "type" << request->secret().type() << ","
                 << "mode" << modeToString(mode) << ","
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
    q->emitFinishedWithError( OtherError, q->tr("Unknown error") );
}

void WritePasswordJobPrivate::scheduledStart()
{
    Sailfish::Secrets::StoreSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    Sailfish::Secrets::Secret* secret;
    const QString collection  = secretsStore->formatCollectionName(service);

    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        FallbackStore fallback(this);
        if (fallback.isValid()) fallback.Write();
        //q->emitFinishedWithError( NoBackendAvailable, messages[Manager] );
        return;
    }

    /* check for collection, create if necessary */
    if (!secretsStore->getCollection(collection)) {
        auto error = formatError(CollectionCreate, secretsStore->lastError());
        q->emitFinishedWithError( error.first, error.second );
        /*
        auto ec = secretsStore->lastError().errorCode();
        auto em = secretsStore->lastError().errorMessage();
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser,  messages[CollectionCreate] + ": " + em);
        } else if (ec == Sailfish::Secrets::Result::CollectionIsLockedError) {
                q->emitFinishedWithError( AccessDenied, messages[CollectionCreate] + ": " + em );
        } else {
            q->emitFinishedWithError( OtherError, messages[CollectionCreate] + ": " + em );
        }
        */
        return;
    }

    /* check for existing secrets, reuse ID if found: */
    QVector<Sailfish::Secrets::Secret::Identifier> ids;
    if (!secretsStore->listSecrets(service, collection, &ids)) {
        auto error = formatError(SecretList, secretsStore->lastError());
        q->emitFinishedWithError( error.first, error.second );
        /*
        auto ec = secretsStore->lastError().errorCode();
        auto em = secretsStore->lastError().errorMessage();
        QString message(messages[SecretList] + ": " + em);
        qWarning() << "Could not list secrets:" << em;
        if (ec == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
            q->emitFinishedWithError( AccessDeniedByUser, message);
        } else if (ec == Sailfish::Secrets::Result::CollectionIsLockedError) {
            q->emitFinishedWithError( AccessDenied, message);
        } else {
            q->emitFinishedWithError( OtherError, message);
        }
        */
        return;
    }
    // update case: use found identifier:
    foreach(auto id, ids) {
        if (id.name() == key) {
            // FIXME: for some reason, the backend doesn't recognize the update.
            // So, delete the secret first:
            auto delrequest = secretsStore->getDeleteRequest(id);
            delrequest->startRequest();
            delrequest->waitForFinished();
            // FIXME: handle errors
            break;
        }
    }

    secret = secretsStore->createSecret(collection, key);
    secret->setData(data);
    if (this->mode == Mode::Binary)
        secret->setType(Sailfish::Secrets::Secret::TypeBlob);

    request = secretsStore->getWriteRequest(service, secret);
    QObject::connect(request, &Sailfish::Secrets::Request::statusChanged,
                    [=]() {
                    /*
                        auto ec = request->result().errorCode();
                        auto em = request->result().errorMessage();
                        qDebug() << request->result().code() << ":" << ec;
                     */
                        if(request->result().code() == Sailfish::Secrets::Result::Succeeded) {
                            q->emitFinished();
                        } else if (request->result().code() == Sailfish::Secrets::Result::Failed) {
                            auto error = formatError(SecretWrite, request->result());
                            q->emitFinishedWithError( error.first, error.second );
                            /*
                            qWarning() << "Failed to store secret:" << ec << em;
                            q->emitFinishedWithError( OtherError, messages[SecretWrite] + ": " + em);
                            */
                        }
                    });
    request->startRequest();
    request->waitForFinished();
}

void DeletePasswordJobPrivate::scheduledStart()
{
    Sailfish::Secrets::DeleteSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection = secretsStore->formatCollectionName(service);

    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        FallbackStore fallback(this);
        if (fallback.isValid()) fallback.Delete();
        return;
    }


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
        q->emitFinishedWithError( EntryNotFound, messages[SecretFind] + ": " + "Found no secrets to delete!" );
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
        auto error = formatError(SecretDelete, request->result());
        q->emitFinishedWithError( error.first, error.second );
        /*
        auto em = request->result().errorMessage();
        qWarning() << "Failed to delete secret:" << em;
        q->emitFinishedWithError( OtherError, messages[SecretDelete] + ": " + em );
        */
        return;
    } else {
        q->emitFinished();
        if (lastEntry) {
            qDebug() << "Last secret deleted, removing collection";
            secretsStore->deleteCollection(collection);
        }
        return;
    }

    q->emitFinishedWithError( OtherError, tr("Unknown error") );
}

bool QKeychain::isAvailable()
{
    if  (secretsStore != nullptr) {
        QObject::connect(secretsStore, &SailfishSecretStore::errorChanged,
                         [=]() { onErrorChanged(); });
        qDebug() << "Error handler connected.";
        return true;
    }
    return false;
}
