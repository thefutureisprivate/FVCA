/* The TPM bridge collects quotes. Identity, freshness and PCR appraisal live in Rust. */
#include <stdint.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#define ATTESTATION_KEY UINT32_C(0x81004656)
#define KEY_ATTRIBUTES (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | \
                        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY | \
                        TPMA_OBJECT_NODA | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT)

static int expected_key(const TPMT_PUBLIC *key) {
    /* SHA256(zero_policy_digest || TPM_CC_PolicyCommandCode || TPM_CC_Quote). */
    static const uint8_t policy[] = {
        0xa0, 0x39, 0xca, 0xd5, 0xfe, 0x68, 0x87, 0x06, 0x88, 0xf8, 0x23, 0x3c, 0x3e, 0x3e, 0xe3, 0xcf, 0x27,
        0xaa, 0xc9, 0xe2, 0xef, 0xe3, 0x48, 0x6a, 0xeb, 0x4e, 0x30, 0x4c, 0x0e, 0x90, 0xcd, 0x27,
    };
    const TPMS_ECC_PARMS *ecc = &key->parameters.eccDetail;
    return key->type == TPM2_ALG_ECC && key->nameAlg == TPM2_ALG_SHA256 &&
           key->objectAttributes == KEY_ATTRIBUTES && key->authPolicy.size == sizeof(policy) &&
           memcmp(key->authPolicy.buffer, policy, sizeof(policy)) == 0 && ecc->curveID == TPM2_ECC_NIST_P256 &&
           ecc->symmetric.algorithm == TPM2_ALG_NULL && ecc->kdf.scheme == TPM2_ALG_NULL &&
           ecc->scheme.scheme == TPM2_ALG_ECDSA && ecc->scheme.details.ecdsa.hashAlg == TPM2_ALG_SHA256;
}

uint32_t fvca_boot_quote(const char *transport, const uint8_t nonce[32], const uint8_t pcrs[3],
                         uint8_t *attest, size_t capacity, size_t *size, uint8_t signature[64]) {
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR key = ESYS_TR_NONE, session = ESYS_TR_NONE;
    TPM2B_PUBLIC *public = NULL;
    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signed_quote = NULL;
    TPM2B_DATA qualifying = {.size = 32};
    memcpy(qualifying.buffer, nonce, 32);
    const TPML_PCR_SELECTION selection = {
        .count = 1, .pcrSelections = {{
            .hash = TPM2_ALG_SHA256, .sizeofSelect = 3, .pcrSelect = {pcrs[0], pcrs[1], pcrs[2]},
        }},
    };
    const TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
    const TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_NULL};
    TSS2_RC rc = Tss2_TctiLdr_Initialize(transport, &tcti);
    if (rc == 0)
        rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc == 0)
        rc = Esys_SetTimeout(esys, 3000);
    if (rc == 0)
        rc = Esys_TR_FromTPMPublic(esys, ATTESTATION_KEY, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &key);
    if (rc == 0)
        rc = Esys_ReadPublic(esys, key, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &public, NULL, NULL);
    if (rc == 0 && !expected_key(&public->publicArea))
        rc = TSS2_ESYS_RC_BAD_VALUE;
    if (rc == 0)
        rc = Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                   ESYS_TR_NONE, NULL, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &session);
    if (rc == 0)
        rc = Esys_PolicyCommandCode(esys, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CC_Quote);
    if (rc == 0)
        rc = Esys_Quote(esys, key, session, ESYS_TR_NONE, ESYS_TR_NONE, &qualifying, &scheme,
                        &selection, &quoted, &signed_quote);
    if (rc == 0) {
        const TPMS_SIGNATURE_ECDSA *ecdsa = &signed_quote->signature.ecdsa;
        const TPM2B_ECC_PARAMETER *r = &ecdsa->signatureR, *s = &ecdsa->signatureS;
        if (quoted->size == 0 || quoted->size > capacity || signed_quote->sigAlg != TPM2_ALG_ECDSA ||
            ecdsa->hash != TPM2_ALG_SHA256 || r->size == 0 || r->size > 32 || s->size == 0 || s->size > 32) {
            rc = TSS2_ESYS_RC_BAD_VALUE;
        } else {
            memcpy(attest, quoted->attestationData, quoted->size);
            *size = quoted->size;
            memset(signature, 0, 64);
            memcpy(signature + 32 - r->size, r->buffer, r->size);
            memcpy(signature + 64 - s->size, s->buffer, s->size);
        }
    }
    Esys_Free(public);
    Esys_Free(quoted);
    Esys_Free(signed_quote);
    if (session != ESYS_TR_NONE)
        Esys_FlushContext(esys, session);
    if (esys != NULL)
        Esys_Finalize(&esys);
    if (tcti != NULL)
        Tss2_TctiLdr_Finalize(&tcti);
    return rc;
}
