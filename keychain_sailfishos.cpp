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

/*
enum KeyringBackend {
    Backend_SailfishSecrets
};

static KeyringBackend getKeyringBackend()
{
//    static KeyringBackend backend = detectKeyringBackend();
    return Backend_SailfishSecrets;
}
*/

static SailfishSecretStore *secretsStore = new SailfishSecretStore();

void ReadPasswordJobPrivate::scheduledStart() {

    Sailfish::Secrets::StoredSecretRequest* request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection  = secretsStore->cleanString(service);
    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, tr("Failed to connect to secret manager!") );
        return;
    }

    QStringList collections;
    bool found = secretsStore->getCollectionNames(&collections);
    if (!found) {
        qWarning() << "Failed to open secret collection:" << secretsStore->getLastError().errorMessage();
        q->emitFinishedWithError( OtherError, tr("Failed to open secret collection") );
        return;
    }
    if (collections.isEmpty() || !collections.contains(collection)) {
        qWarning() << "Failed to find secrets collection!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to find a secret collection %1").arg(key) );
        return;
    }

    sid = secretsStore->createIdentifier(collection, key);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to retrieve secret with ID %1 from collection %2").arg(key).arg(collection) );
        return;
    }
    request = secretsStore->getReadRequest(sid);
    request->startRequest();
    // TODO: Use a callback:
    request->waitForFinished();
    if (request->result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to retrieve secret:"
                   << request->result().errorMessage();
        q->emitFinishedWithError( EntryNotFound, tr("Failed to retrieve secret: %1").arg(request->result().errorMessage()) );
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
    const QString collection  = secretsStore->cleanString(service);

    if (!secretsStore->isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, tr("Failed to connect to secret manager!") );
        return;
    }


    // check for collection, create if necessary
    QStringList collections;
    bool found = secretsStore->getCollectionNames(&collections);
    if (!found) {
        qWarning() << "Failed to open secret collection!";
        q->emitFinishedWithError( OtherError, tr("Failed to open secret collection") );
        return;
    }
    if (!collections.contains(collection)) {
        auto ok = secretsStore->createCollection(collection);
        if (ok != Sailfish::Secrets::Result::NoError) {
            QMetaEnum metaEnum = QMetaEnum::fromType<Sailfish::Secrets::Result::ErrorCode>();
            qWarning() << "Failed to create secret collection!" << metaEnum.valueToKey(ok);
            q->emitFinishedWithError( OtherError, tr("Failed to create secret collection") );
            return;
        }
    } else {
        /* FIXME/TODO: storing will fail if the collection already has a secret with the same key.
         * So, check for existence before writing.
        */
        QVector<Sailfish::Secrets::Secret::Identifier> ids;
        bool ok = secretsStore->findSecret(service, collection, key, &ids);
        if (!ok) {
            qWarning() << "Could not list secrets: " << secretsStore->getLastError().errorMessage();
            q->emitFinishedWithError( OtherError, tr("Could not list secrets") );
            return;
        }
        if (!ids.isEmpty()) {
            q->emitFinishedWithError( NotImplemented, tr("Updating secrets is not supported") );
        }
    }

    sid = secretsStore->createIdentifier(collection, key);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( OtherError, tr("Failed to create secret with ID %1 from collection %2").arg(key).arg(collection) );
        return;
    }

    secret.setIdentifier(sid);
    secret.setData(data);
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
        q->emitFinishedWithError( OtherError, tr("Failed to store secret: %1").arg(request->result().errorMessage()) );
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
    const QString collection  = secretsStore->cleanString(service);

    bool lastEntry = false;

    // delete collection if empty
    QVector<Sailfish::Secrets::Secret::Identifier> ids;
    bool ok = secretsStore->findSecret(service, collection, key, &ids);
    if (!ok) {
        q->emitFinishedWithError( OtherError, tr("Could not list secrets") );
        return;
    }
    if (ids.count() == 0) {
        qWarning() << "Found no secrets to delete!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to delete secret: no secrets found.") );
        return;
    }

    lastEntry = ids.count() == 1;

    sid = secretsStore->createIdentifier(collection, key);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to delete secret with ID %1 from collection %2").arg(key).arg(collection) );
        return;
    }
    request = secretsStore->getDeleteRequest(sid);
    request->startRequest();
    request->waitForFinished();
    if (request->result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to delete secret:"
                   << request->result().errorMessage();
        q->emitFinishedWithError( OtherError, tr("Failed to delete secret: %1").arg(request->result().errorMessage()) );
        return;
    } else {
        if (lastEntry) {
            qInfo() << "Last secret deleted, removing collection";
            //QTimer::singleShot(200, [=](const QString& c = collection) { deleteCollection(c); });
            //QTimer::singleShot(200, [=]() { deleteCollection(collection); });
            //QTimer::singleShot(200, &secretsStore, SLOT(deleteCollection(collection)));
            if (!qApp->instance()) qWarning() << "No Qt event loop, deletion oneshot will not trigger!";
        }
        q->emitFinished();
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
