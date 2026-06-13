#include "sailfishsecretsstore_p.h"

#include <QDebug>

Q_LOGGING_CATEGORY(lcQKeychainBackendSailfish,"qkeychain.sailfish.backend.secrets")

SailfishSecretStore::SailfishSecretStore()
{
    manager = new Sailfish::Secrets::SecretManager();
    /* setting these to makes storage go to SQLCipher-ed databases, under
     * ~/.../Secrets/org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher
     *
     * setting them both to the same one is not a bug, if the same one is
     * DefaultEncryptedStoragePluginName a.k.a. "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher"
     */
    m_storagePlugin    = manager->DefaultEncryptedStoragePluginName;
    m_encryptionPlugin = manager->DefaultEncryptedStoragePluginName;

    m_authPlugin    = manager->DefaultAuthenticationPluginName;
    //m_authPlugin    = QStringLiteral("org.sailfishos.secrets.plugin.authentication.inapp");
    //m_authPlugin    = QStringLiteral("org.sailfishos.secrets.plugin.authentication.passwordagent");
    //printPlugins();
    lockTimer = new QTimer(this);
    lockTimer->setInterval(lockTimeout);
    lockTimer->connect(lockTimer, SIGNAL(timeout()), this, SLOT(requestLock()));
}

// SQLCipher plugin only accepts alphanumeric collection names.
// SQLCipher plugin only supports collection names shorter than 32 characters
QString SailfishSecretStore::formatCollectionName(const QString &toClean) {
    const QRegExp re(QStringLiteral("[-`~!@#$%^&*()_—+=|:;<>«»,.?/{}\'\"\\[\\]\\\\]"));
    QString clean = QString("%1QKeychain").arg(toClean);
    clean.replace(re, "0").truncate(32);
    return clean;
}

/* Look for existing, if not found create new, collection */
bool SailfishSecretStore::getCollection(const QString& name)
{
    QStringList collections;
    if (!listCollections(&collections)) {
        qCWarning(lcQKeychainBackendSailfish) << "Failed to open secret collection!";
        return false;
    }
    if (collections.contains(name))
        return true;
    if (createCollection(name))
        return true;

    qCWarning(lcQKeychainBackendSailfish) << "Failed to create secret collection!";
    return false;
}

bool SailfishSecretStore::createCollection(const QString& name)
{
    Sailfish::Secrets::CreateCollectionRequest request;
    bool result = false;

    request.setManager(manager);
    request.setCollectionName(name);

    // can not change app call with this:
    //request.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    // not implemented!
    //request.setAccessControlMode(Sailfish::Secrets::SecretManager::SystemAccessControlMode);
    // this will still prompt:
    request.setAccessControlMode(manager->NoAccessControlMode);

    request.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    //request.setDeviceLockUnlockSemantic(manager->DeviceLockKeepUnlocked);
    request.setDeviceLockUnlockSemantic(manager->DeviceLockRelock);
    //request.setDeviceLockUnlockSemantic(manager->DeviceLockVerifyLock);

    /*
    request.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::CustomLock);
    request.setCustomLockUnlockSemantic(manager->CustomLockAccessRelock);
    request.setAuthenticationPluginName(m_authPlugin);
    */

    request.setAuthenticationPluginName(m_authPlugin);
    request.setStoragePluginName(m_storagePlugin);
    request.setEncryptionPluginName(m_encryptionPlugin);

    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
        qCInfo(lcQKeychainBackendSailfish) << "Created new collection named" << name;
        result = true;
    } else if (request.result().code() == Sailfish::Secrets::Result::Pending) {
        qCritical(lcQKeychainBackendSailfish) << "Error:" << Q_FUNC_INFO << "Request wass still Pending, this should not happen";
    } else {
        auto code = request.result().errorCode();
        if (code == Sailfish::Secrets::Result::ErrorCode::CollectionAlreadyExistsError) {
            qCDebug(lcQKeychainBackendSailfish) << "Error (ignored):" << code;
            result = true;
        } else {
            setError(request.result());
        }
    }
    return result;
}

bool SailfishSecretStore::deleteCollection(const QString& name)
{
    Sailfish::Secrets::DeleteCollectionRequest request;

    request.setManager(manager);
    request.setUserInteractionMode(manager->SystemInteraction);
    request.setStoragePluginName(m_storagePlugin);
    request.setCollectionName(name);

    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        setError(request.result());
        return false;
    }
    qCInfo(lcQKeychainBackendSailfish) << "Deleted collection named" << name;
    return true;
}

// FIXME: This can fail to open the collection for various reasons.
//        e.g. requires device unlock but that's not possible.
bool SailfishSecretStore::listCollections(QStringList* names)
{
    Sailfish::Secrets::CollectionNamesRequest request;
    request.setManager(manager);
    request.setStoragePluginName(m_storagePlugin);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        setError(request.result());
        return false;
    }
    *names = request.collectionNames();
    return true;
}

Sailfish::Secrets::Secret* SailfishSecretStore::createSecret(const QString &collection, const QString &name) const
{
    return new Sailfish::Secrets::Secret(
        name,
        collection,
        m_storagePlugin);
}

Sailfish::Secrets::Secret::Identifier SailfishSecretStore::createIdentifier(const QString &collection, const QString &name) const
{
    return Sailfish::Secrets::Secret::Identifier(
        name,
        collection,
        m_storagePlugin);
}

bool SailfishSecretStore::listSecrets(const QString &service, const QString &collection,
                    QVector<Sailfish::Secrets::Secret::Identifier> *ids)
{
    bool success = false;
    Sailfish::Secrets::FindSecretsRequest request;
    request.setManager(manager);
    request.setUserInteractionMode(manager->SystemInteraction);
    request.setStoragePluginName(this->m_storagePlugin);

    request.setCollectionName(collection);

    auto filter = createFilterData(service);
    request.setFilter(filter);

    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed) {
        setError(request.result());
        success = false;
    } else {
        *ids = request.identifiers();
        success = true;
    }
    return success;
}


Sailfish::Secrets::StoredSecretRequest* SailfishSecretStore::getReadRequest(const Sailfish::Secrets::Secret::Identifier &sid) const
{
    auto *request = new Sailfish::Secrets::StoredSecretRequest();
    request->setManager(manager);
    request->setIdentifier(sid);
    request->setUserInteractionMode(manager->SystemInteraction);
    return request;
}

Sailfish::Secrets::StoreSecretRequest* SailfishSecretStore::getWriteRequest(const QString& service, Sailfish::Secrets::Secret* secret) const
{
    auto *request = new Sailfish::Secrets::StoreSecretRequest();
    request->setManager(manager);
    request->setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
    request->setUserInteractionMode(manager->SystemInteraction);
    request->setAuthenticationPluginName(m_authPlugin);

    /*
    Sailfish::Secrets::InteractionParameters params = request->interactionParameters();
    QString prompt = QStringLiteral("%1 asks on behalf of %1 to store the Password for %3").arg("QtKeychain").arg(QCoreApplication::applicationName());
    params.setApplicationId(QCoreApplication::applicationName());
    params.setPromptText(prompt);
    request->setInteractionParameters(params);
    */

    auto filter = createFilterData(service);
    secret->setFilterData(filter);

    request->setSecret(*secret);
    return request;
}

Sailfish::Secrets::DeleteSecretRequest* SailfishSecretStore::getDeleteRequest(const Sailfish::Secrets::Secret::Identifier &sid) const
{
    auto *request = new Sailfish::Secrets::DeleteSecretRequest();
    request->setManager(manager);
    request->setUserInteractionMode(manager->SystemInteraction);
    request->setIdentifier(sid);
    return request;
}

//void SailfishSecretStore::requestLock(const QString &collection) const
void SailfishSecretStore::requestLock() const
{
    qCDebug(lcQKeychainBackendSailfish) << "Locking requested!";
    Sailfish::Secrets::LockCodeRequest request;
    request.setManager(manager);
    request.setUserInteractionMode(manager->PreventInteraction);
//    request.setLockCodeRequestType(Sailfish::Secrets::LockCodeRequest::ForgetLockCode);
//    request.setLockCodeTargetType(Sailfish::Secrets::LockCodeRequest::MetadataDatabase);
//    request.setLockCodeTarget(collection);
    request.setLockCodeTargetType(Sailfish::Secrets::LockCodeRequest::ExtensionPlugin);
    request.setLockCodeTarget(m_storagePlugin);
}

Sailfish::Secrets::Secret::FilterData SailfishSecretStore::createFilterData(const QString &service) const
{
    Sailfish::Secrets::Secret::FilterData filter;

    filter.insert(QStringLiteral("writer"), QStringLiteral("QtKeychain"));
    filter.insert(QStringLiteral("service"), service);
    if (!QCoreApplication::organizationName().isEmpty())
        filter.insert(QStringLiteral("org"), QCoreApplication::organizationName());
    if (!QCoreApplication::applicationName().isEmpty())
        filter.insert(QStringLiteral("app"), QCoreApplication::applicationName());
    return filter;
}
