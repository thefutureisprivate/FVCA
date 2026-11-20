/* Narrow connection to the Fedora TPM stack. Release policy and disk leases live in Rust. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#define FLOOR_INDEX UINT32_C(0x01504656)
/* AUTHREAD | POLICYWRITE | COUNTER | NO_DA | WRITTEN */
#define FLOOR_ATTRIBUTES UINT32_C(0x22040018)

struct floor_tpm {
    TSS2_TCTI_CONTEXT *transport;
    ESYS_CONTEXT *esys;
    ESYS_TR index;
    ESYS_TR key;
    ESYS_TR session;
    TPM2B_DIGEST policy;
    TPM2B_DIGEST command;
    TPM2B_NONCE reference;
    TPM2B_NONCE nonce;
};

void fvca_floor_close(struct floor_tpm *tpm) {
    if (tpm == NULL)
        return;
    if (tpm->esys != NULL) {
        if (tpm->session != ESYS_TR_NONE)
            Esys_FlushContext(tpm->esys, tpm->session);
        if (tpm->key != ESYS_TR_NONE)
            Esys_FlushContext(tpm->esys, tpm->key);
        Esys_Finalize(&tpm->esys);
    }
    if (tpm->transport != NULL)
        Tss2_TctiLdr_Finalize(&tpm->transport);
    free(tpm);
}

uint32_t fvca_floor_open(const char *transport, const uint8_t policy[32], struct floor_tpm **out,
                         uint8_t name[34]) {
    struct floor_tpm *tpm = calloc(1, sizeof(*tpm));
    if (tpm == NULL)
        return TSS2_ESYS_RC_MEMORY;
    tpm->key = tpm->session = ESYS_TR_NONE;
    TPM2B_NV_PUBLIC *public = NULL;
    TPM2B_NAME *index_name = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize(transport, &tpm->transport);
    if (rc == 0)
        rc = Esys_Initialize(&tpm->esys, tpm->transport, NULL);
    if (rc == 0)
        rc = Esys_SetTimeout(tpm->esys, 20000);
    if (rc == 0)
        rc = Esys_TR_FromTPMPublic(tpm->esys, FLOOR_INDEX, ESYS_TR_NONE, ESYS_TR_NONE,
                                   ESYS_TR_NONE, &tpm->index);
    if (rc == 0)
        rc = Esys_NV_ReadPublic(tpm->esys, tpm->index, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                &public, &index_name);
    if (rc == 0 && (public->nvPublic.nvIndex != FLOOR_INDEX ||
                    public->nvPublic.nameAlg != TPM2_ALG_SHA256 ||
                    public->nvPublic.attributes != FLOOR_ATTRIBUTES ||
                    public->nvPublic.dataSize != 8 || public->nvPublic.authPolicy.size != 32 ||
                    memcmp(public->nvPublic.authPolicy.buffer, policy, 32) != 0 ||
                    index_name->size != 34))
        rc = TSS2_ESYS_RC_BAD_VALUE;
    if (rc == 0) {
        tpm->policy = public->nvPublic.authPolicy;
        memcpy(name, index_name->name, 34);
        *out = tpm;
    } else {
        fvca_floor_close(tpm);
    }
    Esys_Free(public);
    Esys_Free(index_name);
    return rc;
}

uint32_t fvca_floor_read(struct floor_tpm *tpm, uint64_t *out) {
    TPM2B_MAX_NV_BUFFER *data = NULL;
    TSS2_RC rc = Esys_NV_Read(tpm->esys, tpm->index, tpm->index, ESYS_TR_PASSWORD,
                             ESYS_TR_NONE, ESYS_TR_NONE, 8, 0, &data);
    if (rc == 0) {
        if (data->size != 8) {
            rc = TSS2_ESYS_RC_BAD_VALUE;
        } else {
            uint64_t value = 0;
            for (size_t i = 0; i < 8; ++i)
                value = (value << 8) | data->buffer[i];
            *out = value;
        }
    }
    Esys_Free(data);
    return rc;
}

static TSS2_RC session(struct floor_tpm *tpm, TPM2_SE type, ESYS_TR *handle) {
    const TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
    return Esys_StartAuthSession(tpm->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 ESYS_TR_NONE, ESYS_TR_NONE, NULL, type, &symmetric,
                                 TPM2_ALG_SHA256, handle);
}

static TSS2_RC authorize(struct floor_tpm *tpm, ESYS_TR handle, const TPM2B_NONCE *nonce,
                         const TPM2B_DIGEST *command, int32_t expires,
                         const TPMT_SIGNATURE *signature) {
    TPM2B_TIMEOUT *timeout = NULL;
    TPMT_TK_AUTH *ticket = NULL;
    TSS2_RC rc = Esys_PolicySigned(tpm->esys, tpm->key, handle, ESYS_TR_NONE, ESYS_TR_NONE,
                                  ESYS_TR_NONE, nonce, command, &tpm->reference, expires,
                                  signature, &timeout, &ticket);
    Esys_Free(timeout);
    Esys_Free(ticket);
    if (rc == 0)
        rc = Esys_PolicyCommandCode(tpm->esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    TPM2_CC_NV_Increment);
    return rc;
}

static TSS2_RC check_authority(struct floor_tpm *tpm) {
    ESYS_TR trial = ESYS_TR_NONE;
    TPM2B_DIGEST *derived = NULL;
    const TPM2B_NONCE nonce = {0};
    const TPM2B_DIGEST command = {0};
    const TPMT_SIGNATURE signature = {
        .sigAlg = TPM2_ALG_ECDSA, .signature.ecdsa.hash = TPM2_ALG_SHA256,
    };
    TSS2_RC rc = session(tpm, TPM2_SE_TRIAL, &trial);
    if (rc == 0)
        rc = authorize(tpm, trial, &nonce, &command, 0, &signature);
    if (rc == 0)
        rc = Esys_PolicyGetDigest(tpm->esys, trial, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &derived);
    if (rc == 0 && (derived->size != 32 || memcmp(derived->buffer, tpm->policy.buffer, 32) != 0))
        rc = TSS2_ESYS_RC_BAD_VALUE;
    Esys_Free(derived);
    if (trial != ESYS_TR_NONE) {
        const TSS2_RC flush = Esys_FlushContext(tpm->esys, trial);
        if (rc == 0)
            rc = flush;
    }
    return rc;
}

uint32_t fvca_floor_begin(struct floor_tpm *tpm, const uint8_t *key, size_t key_bytes,
                         const uint8_t reference[40], const uint8_t command[32], uint8_t nonce[32]) {
    TPM2B_PUBLIC public = {0};
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(key, key_bytes, &offset, &public);
    if (rc != 0)
        return rc;
    if (offset != key_bytes || public.publicArea.type != TPM2_ALG_ECC ||
        public.publicArea.nameAlg != TPM2_ALG_SHA256 ||
        public.publicArea.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256 ||
        tpm->key != ESYS_TR_NONE)
        return TSS2_ESYS_RC_BAD_VALUE;
    tpm->reference.size = 40;
    memcpy(tpm->reference.buffer, reference, 40);
    tpm->command.size = 32;
    memcpy(tpm->command.buffer, command, 32);
    rc = Esys_LoadExternal(tpm->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &public,
                           ESYS_TR_RH_OWNER, &tpm->key);
    if (rc == 0)
        rc = check_authority(tpm);
    if (rc == 0)
        rc = session(tpm, TPM2_SE_POLICY, &tpm->session);
    TPM2B_NONCE *live_nonce = NULL;
    if (rc == 0)
        rc = Esys_TRSess_GetNonceTPM(tpm->esys, tpm->session, &live_nonce);
    if (rc == 0 && live_nonce->size != 32)
        rc = TSS2_ESYS_RC_BAD_VALUE;
    if (rc == 0) {
        tpm->nonce = *live_nonce;
        memcpy(nonce, live_nonce->buffer, 32);
    }
    Esys_Free(live_nonce);
    return rc;
}

uint32_t fvca_floor_authorize(struct floor_tpm *tpm, uint32_t seconds, const uint8_t raw[64]) {
    if (tpm->session == ESYS_TR_NONE || seconds == 0 || seconds > 300)
        return TSS2_ESYS_RC_BAD_VALUE;
    TPMT_SIGNATURE signature = {
        .sigAlg = TPM2_ALG_ECDSA, .signature.ecdsa.hash = TPM2_ALG_SHA256,
        .signature.ecdsa.signatureR.size = 32, .signature.ecdsa.signatureS.size = 32,
    };
    memcpy(signature.signature.ecdsa.signatureR.buffer, raw, 32);
    memcpy(signature.signature.ecdsa.signatureS.buffer, raw + 32, 32);
    return authorize(tpm, tpm->session, &tpm->nonce, &tpm->command, (int32_t)seconds, &signature);
}

uint32_t fvca_floor_increment(struct floor_tpm *tpm) {
    if (tpm->session == ESYS_TR_NONE)
        return TSS2_ESYS_RC_BAD_VALUE;
    TSS2_RC rc = Esys_TRSess_SetAttributes(tpm->esys, tpm->session, 0, TPMA_SESSION_CONTINUESESSION);
    if (rc == 0)
        rc = Esys_NV_Increment(tpm->esys, tpm->index, tpm->index, tpm->session, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc == 0)
        tpm->session = ESYS_TR_NONE;
    return rc;
}
