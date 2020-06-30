#include "Certificate.h"

#pragma comment(lib, "Crypt32.lib")

PCCERT_CONTEXT My::Certificate::get(const char* name)
{
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, "My");
    if (!store) {
        return nullptr;
    }
    //NOTE: 
    //1) Wildcard subject and Subject Alternative Name are not supported!
    //2) There may be multiple certificates matching the subject name. We don't try to get the best one. 
    //   For example, some may be expired while some not.
    PCCERT_CONTEXT cert = CertFindCertificateInStore(store, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, 
        CERT_FIND_SUBJECT_STR, name, nullptr);
    CertCloseStore(store, 0);
    return cert;
}
