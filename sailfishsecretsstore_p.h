#ifndef QTKEYCHAIN_SFOSSSTORE_P_H
#define QTKEYCHAIN_SFOSSSTORE_P_H

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic warning "-Wall"
#pragma GCC diagnostic warning "-Wextra"
#endif

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
#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcQKeychainBackendSailfish)

class SailfishSecretStore : public QObject {
    Q_OBJECT
    Q_PROPERTY(Sailfish::Secrets::Result lastError READ lastError NOTIFY errorChanged)
    /*
    Q_PROPERTY(QString storagePlugin         MEMBER m_storagePlugin)
    Q_PROPERTY(QString encryptionPlugin      MEMBER m_encryptionPlugin)
    Q_PROPERTY(QString authPlugin            MEMBER m_authPlugin)
    */

public:
    explicit SailfishSecretStore();

    bool isInitialized() const { return manager->isInitialized(); };

    static QString formatCollectionName(const QString &toClean);

    bool deleteCollection(const QString& name);
    bool getCollection(const QString& name);
    Sailfish::Secrets::Secret::Identifier createIdentifier(const QString& collection, const QString& name) const;
    Sailfish::Secrets::Secret* createSecret(const QString& collection, const QString& name) const;
    bool listSecrets(const QString &service, const QString &collection,
                    QVector<Sailfish::Secrets::Secret::Identifier> *ids);

    Sailfish::Secrets::StoredSecretRequest* getReadRequest(const Sailfish::Secrets::Secret::Identifier &sid) const;
    Sailfish::Secrets::StoreSecretRequest*  getWriteRequest(const QString& service, Sailfish::Secrets::Secret* s) const;
    Sailfish::Secrets::DeleteSecretRequest* getDeleteRequest(const Sailfish::Secrets::Secret::Identifier &sid) const;

    Sailfish::Secrets::Result lastError() const { return m_lastError; };

Q_SIGNALS:
    void errorChanged() const;

protected Q_SLOTS:
    //void requestLock(const QString &collection) const;
    void requestLock() const;

protected:
    void setError(Sailfish::Secrets::Result r) {
        if ( r != m_lastError) {
            m_lastError = r;
            emit errorChanged();
        }
    };

private:
    Sailfish::Secrets::SecretManager *manager;
    Sailfish::Secrets::Result m_lastError;

    static const uint lockTimeout = 1000 * 60 * 5;
    QTimer* lockTimer;

    QString m_storagePlugin;
    QString m_encryptionPlugin;
    QString m_authPlugin;

    bool createCollection(const QString& name);
    bool listCollections(QStringList* names);
    //  QMap<QString,QString>
    Sailfish::Secrets::Secret::FilterData createFilterData(const QString &service) const;

};

#endif // QTKEYCHAIN_SFOSSSTORE_P_H
