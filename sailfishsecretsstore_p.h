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

//namespace QKeychain {

class SailfishSecretStore {
    Q_DECLARE_TR_FUNCTIONS(QKeychain::SailfishSecretStore)

public:
    explicit SailfishSecretStore();

    static QString cleanString(const QString &toClean);

    bool createCollection(const QString& name);
    bool deleteCollection(const QString& name);
    bool getCollectionNames(QStringList* names);
    Sailfish::Secrets::Secret::Identifier createIdentifier(const QString& collection, const QString& name);
    bool findSecret(const QString &service, const QString &collection, const QString &key, 
                           QVector<Sailfish::Secrets::Secret::Identifier> *identifiers);

    bool isInitialized() { return manager->isInitialized(); };

    Sailfish::Secrets::StoredSecretRequest* getReadRequest(const Sailfish::Secrets::Secret::Identifier &sid);
    Sailfish::Secrets::StoreSecretRequest*  getWriteRequest(const Sailfish::Secrets::Secret &s);
    Sailfish::Secrets::DeleteSecretRequest* getDeleteRequest(const Sailfish::Secrets::Secret::Identifier &sid);

    Sailfish::Secrets::Result getLastError() { return lastError; };
private:
    Sailfish::Secrets::SecretManager *manager;
    Sailfish::Secrets::Result lastError;

};

//} // namespace QKeychain

#endif // QTKEYCHAIN_SFOSSSTORE_P_H

