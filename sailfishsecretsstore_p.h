#ifndef QTKEYCHAIN_SFOSSSTORE_P_H
#define QTKEYCHAIN_SFOSSSTORE_P_H

#include "keychain_p.h"

#include <Secrets/secretmanager.h>
#include <Secrets/collectionnamesrequest.h>
#include <Secrets/createcollectionrequest.h>
#include <Secrets/deletecollectionrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/storesecretrequest.h>
#include <Secrets/deletesecretrequest.h>
#include <Secrets/findsecretsrequest.h>
#include <Secrets/lockcoderequest.h>

#include <QTimer>

//namespace QKeychain {

class SailfishSecretStore : public QObject {
    Q_OBJECT
    //Q_DECLARE_TR_FUNCTIONS(QKeychain::SailfishSecretStore)
public:
    explicit SailfishSecretStore();

    static QString formatCollectionName(const QString &toClean);

    bool createCollection(const QString& name);
    bool deleteCollection(const QString& name);
    bool getCollectionNames(QStringList* names);
    Sailfish::Secrets::Secret::Identifier createIdentifier(const QString& collection, const QString& name);
    bool listSecrets(const QString &service, const QString &collection,
                    QVector<Sailfish::Secrets::Secret::Identifier> *ids);


    bool isInitialized() const { return manager->isInitialized(); };

    Sailfish::Secrets::StoredSecretRequest* getReadRequest(const Sailfish::Secrets::Secret::Identifier &sid) const;
    Sailfish::Secrets::StoreSecretRequest*  getWriteRequest(const Sailfish::Secrets::Secret &s) const;
    Sailfish::Secrets::DeleteSecretRequest* getDeleteRequest(const Sailfish::Secrets::Secret::Identifier &sid) const;

    Sailfish::Secrets::LockCodeRequest* getUnlockRequest(const Sailfish::Secrets::Secret::Identifier &sid) const;


    Sailfish::Secrets::Result lastError() const { return m_lastError; };

protected Q_SLOTS:
    void maybeFinished(const Sailfish::Secrets::Request::Status &status,
                       const Sailfish::Secrets::Result &result) const;
    //void requestLock(const QString &collection) const;
    void requestLock() const;

protected:
    void setError(Sailfish::Secrets::Result r) { m_lastError = r; };

private:
    Sailfish::Secrets::SecretManager *manager;
    Sailfish::Secrets::Result m_lastError;

    static const uint lockTimeout = 1000 * 60 * 5;
    QTimer* lockTimer;

    QString m_storagePlugin;
    QString m_encryptionPlugin;
    QString m_authPlugin;

};

//} // namespace QKeychain

#endif // QTKEYCHAIN_SFOSSSTORE_P_H

