#include "sailfishsecretsstore_p.h"

#include <QDebug>

SailfishSecretStore::SailfishSecretStore()
{
    manager = new Sailfish::Secrets::SecretManager();
}

// SQLCipher plugin only accepts alphanumeric collection names:
// Remove non-alphanumeric chars from string
QString SailfishSecretStore::cleanString(const QString &toClean)
{
    const QRegExp re(QStringLiteral("[-`~!@#$%^&*()_—+=|:;<>«»,.?/{}\'\"\\[\\]\\\\]"));
    QString toReturn = toClean;
    toReturn.replace(re, "0");
    return toReturn;
}

bool SailfishSecretStore::createCollection(const QString& name)
{
    Sailfish::Secrets::CreateCollectionRequest request;

    const QString cleanName = cleanString(name);
    request.setManager(manager);
    request.setCollectionName(cleanName);
    int diff = (name.length() - cleanName.length());
    if (diff != 0) {
        qInfo() << "Removed " << diff <<  "non-alphanumeric characters from name";
    }

    // can not change app call with this:
    //request.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    // not implemented!
    //request.setAccessControlMode(Sailfish::Secrets::SecretManager::SystemAccessControlMode);
    // this will still prompt:
    request.setAccessControlMode(Sailfish::Secrets::SecretManager::NoAccessControlMode);

    request.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    request.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockRelock);
    //request.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockVerifyLock);

    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.setEncryptionPluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);

    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qDebug() << "Error:" << Q_FUNC_INFO << request.result().errorCode();
        lastError = request.result();
        return false;
    }
    qDebug() << "Created new collection named" << cleanName << "for" << name;
    //lastError = Sailfish::Secrets::Result();
    return true;
}

bool SailfishSecretStore::deleteCollection(const QString& name)
{
    Sailfish::Secrets::DeleteCollectionRequest request;

    const QString cleanName = cleanString(name);
    request.setManager(manager);
    request.setCollectionName(cleanName);
    int diff = (name.length() - cleanName.length());
    if (diff != 0) {
        qInfo() << "Removed " << diff <<  "non-alphanumeric characters from name";
    }

    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qDebug() << "Error:" << Q_FUNC_INFO << request.result().errorCode();
        lastError = request.result();
        return false;
    }
    qDebug() << "Deleted collection named" << cleanName << "for" << name;
    return true;
}

// FIXME: This can fail to open the collection for various reasons.
//        e.g. requires device unlock but that's not possible.
bool SailfishSecretStore::getCollectionNames(QStringList* names)
{
    Sailfish::Secrets::CollectionNamesRequest request;
    request.setManager(manager);
    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qDebug() << "Error:" << Q_FUNC_INFO << request.result().errorCode();
        lastError = request.result();
        return false;
    }
    *names = request.collectionNames();
    return true;
}

Sailfish::Secrets::Secret::Identifier SailfishSecretStore::createIdentifier(const QString &collection, const QString &name)
{
    return Sailfish::Secrets::Secret::Identifier(
        name,
        collection,
        Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
}

bool SailfishSecretStore::findSecret(const QString &service, const QString &collection, const QString &key, 
                       QVector<Sailfish::Secrets::Secret::Identifier> *identifiers)
{
    Sailfish::Secrets::FindSecretsRequest request;
    request.setManager(manager);
    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);

    request.setCollectionName(collection);

    Sailfish::Secrets::Secret::FilterData filter; //  QMap<QString,QString>
    if (!QCoreApplication::organizationName().isEmpty())
        filter.insert(QLatin1String("org"), QCoreApplication::organizationName());
    if (!QCoreApplication::applicationName().isEmpty())
        filter.insert(QLatin1String("app"), QCoreApplication::applicationName());
    filter.insert(QLatin1String("service"), service);
    request.setFilter(filter);

    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        qDebug() << "Search used" << filter.count() << "filter parameters";
        qDebug() << "Error:" << Q_FUNC_INFO << request.result().errorCode();
        lastError = request.result();
        return false;
    }
    qDebug() << QString("Found %1 secrets in collection %2").arg(request.identifiers().length()).arg(collection);
    *identifiers = request.identifiers();
    return true;
}


Sailfish::Secrets::StoredSecretRequest* SailfishSecretStore::getReadRequest(const Sailfish::Secrets::Secret::Identifier &sid)
{
    auto *request = new Sailfish::Secrets::StoredSecretRequest();
    request->setManager(manager);
    request->setIdentifier(sid);
    request->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    return request;
}

Sailfish::Secrets::StoreSecretRequest* SailfishSecretStore::getWriteRequest(const Sailfish::Secrets::Secret &secret)
{
    auto *request = new Sailfish::Secrets::StoreSecretRequest();
    request->setManager(manager);
    request->setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
    request->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    request->setSecret(secret);
    return request;
}
Sailfish::Secrets::DeleteSecretRequest* SailfishSecretStore::getDeleteRequest(const Sailfish::Secrets::Secret::Identifier &sid)
{
    auto *request = new Sailfish::Secrets::DeleteSecretRequest();
    request->setManager(manager);
    request->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    return request;
}
