/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"
//#include "sailfishsecrets_p.h"
#include "plaintextstore_p.h"

#include <QScopedPointer>
#include <QDebug>
#include <QMetaEnum>

#include <Secrets/secretmanager.h>
#include <Secrets/collectionnamesrequest.h>
#include <Secrets/createcollectionrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/storesecretrequest.h>
#include <Secrets/deletesecretrequest.h>

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

static Sailfish::Secrets::SecretManager manager;

// SQLCipher plugin only accepts alphanumeric collection names:
// Remove non-alphanumeric chars from string
static QString cleanString(const QString &toClean) {
    const QRegExp re(QStringLiteral("[-`~!@#$%^&*()_—+=|:;<>«»,.?/{}\'\"\\[\\]\\\\]"));
    QString toReturn = toClean;
    toReturn.replace(re, "0");
    return toReturn;
}

static Sailfish::Secrets::Result::ErrorCode createCollection(const QString& name)
{
    Sailfish::Secrets::CreateCollectionRequest request;

    const QString cleanName = cleanString(name);
    request.setManager(&manager);
    request.setCollectionName(cleanName);
    int diff = (name.length() - cleanName.length());
    if (diff != 0) {
        qInfo() << "Removed " << diff <<  "non-alphanumeric characters from name";
    }

    //request.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    // not implemented!
    //request.setAccessControlMode(Sailfish::Secrets::SecretManager::SystemAccessControlMode);
    request.setAccessControlMode(Sailfish::Secrets::SecretManager::NoAccessControlMode);
    request.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    request.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockRelock);
    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.setEncryptionPluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);

    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << QString("Failed to create collection '%1 (%2)':").arg(name).arg(cleanName)
                   << request.result().errorMessage();
        return request.result().errorCode();
    }
    qDebug() << "Created new collection named" << cleanName << "for" << name;
    return Sailfish::Secrets::Result::NoError;
}

static QStringList getCollectionNames()
{
    Sailfish::Secrets::CollectionNamesRequest request;
    request.setManager(&manager);
    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to list collections"
                   << request.result().errorMessage();
    }
    return request.collectionNames();
}

static Sailfish::Secrets::Secret::Identifier createIdentifier(const QString &collection, const QString &name, bool standalone=false)
{
    const QString coll = standalone ? "" : collection;
    return Sailfish::Secrets::Secret::Identifier(
        name,
        coll,
        Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
}

void ReadPasswordJobPrivate::scheduledStart() {

    Sailfish::Secrets::StoredSecretRequest request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection  = cleanString(service);
    if (!manager.isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, tr("Failed to connect to secret manager!") );
        return;
    }

    QStringList collections = getCollectionNames();
    if (collections.isEmpty() || !collections.contains(collection)) {
        qWarning() << "Failed to find secrets collection!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to find a secret collection %1").arg(key) );
        return;
    }

    sid = createIdentifier(collection, key, false);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to retrieve secret with ID %1 from collection %2").arg(key).arg(collection) );
        return;
    }
    request.setManager(&manager);
    request.setIdentifier(sid);
    request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    request.startRequest();
    // TODO: Use a callback:
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to retrieve secret:"
                   << request.result().errorMessage();
        q->emitFinishedWithError( EntryNotFound, tr("Failed to retrieve secret: %1").arg(request.result().errorMessage()) );
        return;
    } else {
        qDebug() << "Secret data retrieved:"
                 << "type" << request.secret().type() << ","
                 << request.secret().data().length() << "bytes";
        mode = (request.secret().type() == Sailfish::Secrets::Secret::TypeBlob)
               ? Mode::Text
               : Mode::Binary;
        data = request.secret().data();
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
    Sailfish::Secrets::StoreSecretRequest request;
    Sailfish::Secrets::Secret::Identifier sid;
    Sailfish::Secrets::Secret secret;
    const QString collection  = cleanString(service);

    if (!manager.isInitialized()) {
        qWarning() << "Failed to connect to secret manager!";
        q->emitFinishedWithError( NoBackendAvailable, tr("Failed to connect to secret manager!") );
        return;
    }

    QStringList collections = getCollectionNames();
    if (!collections.contains(collection)) {

        auto ok = createCollection(collection);
        if (ok != Sailfish::Secrets::Result::NoError) {
            QMetaEnum metaEnum = QMetaEnum::fromType<Sailfish::Secrets::Result::ErrorCode>();
            qWarning() << "Failed to create secret collection!" << metaEnum.valueToKey(ok);
            q->emitFinishedWithError( OtherError, tr("Failed to create secret collection") );
            return;
        }
    }

    sid = createIdentifier(collection, key, false);
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
    request.setManager(&manager);
    request.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
    request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    request.setSecret(secret);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to store secret:"
                   << request.result().errorMessage();
        q->emitFinishedWithError( OtherError, tr("Failed to store secret: %1").arg(request.result().errorMessage()) );
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
    //Sailfish::Secrets::DeleteCollectionRequest request;
    Sailfish::Secrets::DeleteSecretRequest request;
    Sailfish::Secrets::Secret::Identifier sid;
    const QString collection  = cleanString(service);

    sid = createIdentifier(collection, key, false);
    if (!sid.isValid()) {
        qWarning() << "Failed to create secret identifier!";
        q->emitFinishedWithError( EntryNotFound, tr("Failed to delete secret with ID %1 from collection %2").arg(key).arg(collection) );
        return;
    }
    request.setManager(&manager);
    //request.setCollectionName(collection);
    request.setIdentifier(sid);
    request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qWarning() << "Failed to delete secret:"
                   << request.result().errorMessage();
        q->emitFinishedWithError( OtherError, tr("Failed to delete secret: %1").arg(request.result().errorMessage()) );
        return;
    } else {
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
