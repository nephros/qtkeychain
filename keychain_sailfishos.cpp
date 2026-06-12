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

enum SailfishSecretError {
    CollectionCreateError,
    CollectionListError,
    CollectionOpenError,
    IdentifierCreateError,
    ManagerError,
    SecretDeleteError,
    SecretFindError,
    SecretListError,
    SecretReadError,
    SecretWriteError,
    SecretUpdateError,
};

static const QMap<enum SailfishSecretError, QString> messages {
        { ManagerError,          QT_TR_NOOP("Failed to connect to Sailfish Secret manager!") },

        { CollectionCreateError, QT_TR_NOOP("Failed to create password store")  },
        { CollectionOpenError,   QT_TR_NOOP("Failed to open password store")  },
        { CollectionListError,   QT_TR_NOOP("Failed to find a password store named %1") },
        { IdentifierCreateError, QT_TR_NOOP("Failed to identify password for '%1' in store '%2'") },
        { SecretFindError,       QT_TR_NOOP("Failed to delete password for '%1'") },
        { SecretDeleteError,     QT_TR_NOOP("Failed to delete password for '%1' from store %2") },
        { SecretListError,       QT_TR_NOOP("Failed to enumerate passwords") },
        { SecretReadError,       QT_TR_NOOP("Failed to retrieve password for '%1': %2") },
        { SecretWriteError,      QT_TR_NOOP("Failed to store password for '%1': %2") },
        { SecretUpdateError,     QT_TR_NOOP("Updating secrets is not supported yet") }
};


void ReadPasswordJobPrivate::scheduledStart() {

    Sailfish::Secrets::StoredSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection  = secretsStore->formatCollectionName(service);
    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, messages[ManagerError] );
        return;
    }

    QStringList collections;
    bool ok = secretsStore->getCollectionNames(&collections);
    if (!ok) {
        qWarning() << "Failed to list secret collections:" << secretsStore->lastError().errorMessage();
        q->emitFinishedWithError( OtherError, messages[CollectionOpenError] );
        return;
    }
    if (collections.isEmpty() || !collections.contains(collection)) {
        qWarning() << "Failed to find secrets collection!";
        q->emitFinishedWithError( EntryNotFound, messages[CollectionListError].arg(collection) );
        return;
    }

    sid = secretsStore->createIdentifier(collection, key);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( EntryNotFound, messages[IdentifierCreateError].arg(key).arg(collection) );
        return;
    }
    request = secretsStore->getReadRequest(sid);
    request->startRequest();
    // TODO: Use a callback:
    request->waitForFinished();
    if (request->result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to retrieve secret:"
                   << request->result().errorMessage();
        q->emitFinishedWithError( EntryNotFound, messages[SecretReadError].arg(key).arg(request->result().errorMessage()) );
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
    Sailfish::Secrets::Secret secret;
    const QString collection  = secretsStore->formatCollectionName(service);

    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, messages[ManagerError] );
        return;
    }

    /* check for collection, create if necessary */
    if (!secretsStore->getCollection(collection)) {
            if (secretsStore->lastError().errorCode() == Sailfish::Secrets::Result::CollectionIsLockedError) {
                q->emitFinishedWithError( AccessDenied, messages[CollectionCreateError] );
            } else {
                q->emitFinishedWithError( OtherError, messages[CollectionCreateError] );
            }
        return;
    } else {
        /* FIXME/TODO: storing will fail if the collection already has a secret with the same key.
         * So, check for existence before writing.
        */
        QVector<Sailfish::Secrets::Secret::Identifier> ids;
        bool ok = secretsStore->listSecrets(service, collection, &ids);
        if (!ok) {
            qWarning() << "Could not list secrets: " << secretsStore->lastError().errorMessage();
            if (secretsStore->lastError().errorCode() == Sailfish::Secrets::Result::CollectionIsLockedError) {
                q->emitFinishedWithError( AccessDenied, messages[SecretListError] );
            } else {
                q->emitFinishedWithError( OtherError, messages[SecretListError] );
            }
            return;
        }
        // update: use found identifier:
        if(!ids.isEmpty() && (ids.count() == 1) && (ids.first().name() == key)) {
            secret.setIdentifier(Sailfish::Secrets::Secret::Identifier(ids.first()));

        } else { // create new
            sid = secretsStore->createIdentifier(collection, key);
            sid.setName(key);
            secret.setIdentifier(sid);
        }
    }

    /*
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( OtherError, messages[IdentifierCreateError].arg(key).arg(collection) );
        return;
    }
    */

    secret.setData(data);
    secret.setName(key);
    if (this->mode == Mode::Binary)
        secret.setType(Sailfish::Secrets::Secret::TypeBlob);
    if (!QCoreApplication::organizationName().isEmpty())
        secret.setFilterData(QLatin1String("org"), QCoreApplication::organizationName());
    if (!QCoreApplication::applicationName().isEmpty())
        secret.setFilterData(QLatin1String("app"), QCoreApplication::applicationName());
    secret.setFilterData(QLatin1String("service"), service);

    // Request that the secret be securely stored.
    request = secretsStore->getWriteRequest(secret);
    request->startRequest();
    request->waitForFinished();
    if (request->result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to store secret:"
                   << request->result().errorMessage();
        q->emitFinishedWithError( OtherError, messages[SecretWriteError].arg(key).arg(request->result().errorMessage()) );
        return;
    } else {
        q->emitFinished();
        return;
    }
    q->emitFinishedWithError( OtherError, tr("Unknown error") );
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
        q->emitFinishedWithError( EntryNotFound, messages[SecretFindError].arg(key) );
        return;
    }

    lastEntry = ids.count() == 1;

    sid = secretsStore->createIdentifier(collection, key);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( EntryNotFound, messages[SecretDeleteError].arg(key).arg(collection) );
        return;
    }
    request = secretsStore->getDeleteRequest(sid);
    request->startRequest();
    request->waitForFinished();
    if (request->result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to delete secret:"
                   << request->result().errorMessage();
        q->emitFinishedWithError( OtherError, messages[SecretDeleteError].arg(key).arg(collection) );
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
    //return SailfishSecrets::isAvailable();
    return true;
}
