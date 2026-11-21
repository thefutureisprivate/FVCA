#ifndef FVCA_ATTESTATION_KEY_H
#define FVCA_ATTESTATION_KEY_H

#include <tss2/tss2_esys.h>

TSS2_RC fvca_attestation_key(ESYS_CONTEXT *esys, ESYS_TR *key, TPM2B_NAME *qualified_name);

#endif
