#pragma once

#include "common.h"
#include <Wincrypt.h>

namespace My {
    class Certificate
    {
    public:
        static PCCERT_CONTEXT get(const char* name);

        static inline void free(PCCERT_CONTEXT cert) {
            CertFreeCertificateContext(cert);
        }
    };
}
