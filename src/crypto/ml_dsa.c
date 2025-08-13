/*
 * ML-DSA (FIPS 204) Implementation
 * Post-quantum digital signature algorithm
 */

#include "ml_dsa.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

// Generate ML-DSA keypair
int ml_dsa_keygen(ml_dsa_keypair_t *keypair, int variant) {
    if (!keypair) return -1;
    
    const char *alg_name;
    switch (variant) {
        case ML_DSA_44:
            alg_name = OQS_SIG_alg_ml_dsa_44;
            break;
        case ML_DSA_65:
            alg_name = OQS_SIG_alg_ml_dsa_65;
            break;
        case ML_DSA_87:
            alg_name = OQS_SIG_alg_ml_dsa_87;
            break;
        default:
            return -1;
    }
    
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) return -1;
    
    size_t public_key_len = sig->length_public_key;
    size_t private_key_len = sig->length_secret_key;
    
    // Verify buffer sizes match
    if (public_key_len > sizeof(keypair->public_key) || 
        private_key_len > sizeof(keypair->private_key)) {
        OQS_SIG_free(sig);
        return -1;
    }
    
    int result = OQS_SIG_keypair(sig, keypair->public_key, keypair->private_key);
    
    OQS_SIG_free(sig);
    return (result == OQS_SUCCESS) ? 0 : -1;
}

// Sign message with ML-DSA
int ml_dsa_sign(uint8_t *signature, size_t *sig_len, 
                const uint8_t *message, size_t msg_len,
                const ml_dsa_keypair_t *keypair) {
    if (!signature || !sig_len || !message || !keypair) return -1;
    
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return -1;
    
    int result = OQS_SIG_sign(sig, signature, sig_len, message, msg_len, keypair->private_key);
    
    OQS_SIG_free(sig);
    return (result == OQS_SUCCESS) ? 0 : -1;
}

// Verify ML-DSA signature
int ml_dsa_verify(const uint8_t *signature, size_t sig_len,
                  const uint8_t *message, size_t msg_len,
                  const uint8_t *public_key) {
    if (!signature || !message || !public_key) return -1;
    
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return -1;
    
    int result = OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key);
    
    OQS_SIG_free(sig);
    return (result == OQS_SUCCESS) ? 0 : -1;
}

// Free ML-DSA keypair
void ml_dsa_keypair_free(ml_dsa_keypair_t *keypair) {
    if (!keypair) return;
    
    // Secure cleanup
    memset(keypair->private_key, 0, sizeof(keypair->private_key));
    memset(keypair->public_key, 0, sizeof(keypair->public_key));
}
