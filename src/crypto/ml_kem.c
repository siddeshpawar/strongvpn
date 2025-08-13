/*
 * ML-KEM (FIPS 203) Implementation
 * Post-quantum key encapsulation mechanism
 */

#include "ml_kem.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

// Generate ML-KEM keypair
int ml_kem_keygen(ml_kem_keypair_t *keypair, int variant) {
    if (!keypair) return -1;
    
    const char *alg_name;
    switch (variant) {
        case ML_KEM_512:
            alg_name = OQS_KEM_alg_ml_kem_512;
            break;
        case ML_KEM_768:
            alg_name = OQS_KEM_alg_ml_kem_768;
            break;
        case ML_KEM_1024:
            alg_name = OQS_KEM_alg_ml_kem_1024;
            break;
        default:
            return -1;
    }
    
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) return -1;
    
    size_t public_key_len = kem->length_public_key;
    size_t private_key_len = kem->length_secret_key;
    
    // Verify buffer sizes match
    if (public_key_len > sizeof(keypair->public_key) || 
        private_key_len > sizeof(keypair->private_key)) {
        OQS_KEM_free(kem);
        return -1;
    }
    
    int result = OQS_KEM_keypair(kem, keypair->public_key, keypair->private_key);
    
    OQS_KEM_free(kem);
    return (result == OQS_SUCCESS) ? 0 : -1;
}

// Encapsulate shared secret with ML-KEM
int ml_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret,
                       const uint8_t *public_key) {
    if (!ciphertext || !shared_secret || !public_key) return -1;
    
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    
    size_t ciphertext_len = kem->length_ciphertext;
    size_t shared_secret_len = kem->length_shared_secret;
    
    int result = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    
    OQS_KEM_free(kem);
    return (result == OQS_SUCCESS) ? 0 : -1;
}

// Decapsulate shared secret with ML-KEM
int ml_kem_decapsulate(uint8_t *shared_secret,
                       const uint8_t *ciphertext,
                       const ml_kem_keypair_t *keypair) {
    if (!shared_secret || !ciphertext || !keypair) return -1;
    
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    
    int result = OQS_KEM_decaps(kem, shared_secret, ciphertext, keypair->private_key);
    
    OQS_KEM_free(kem);
    return (result == OQS_SUCCESS) ? 0 : -1;
}

// Free ML-KEM keypair
void ml_kem_keypair_free(ml_kem_keypair_t *keypair) {
    if (!keypair) return;
    
    // Secure cleanup
    memset(keypair->private_key, 0, sizeof(keypair->private_key));
    memset(keypair->public_key, 0, sizeof(keypair->public_key));
}
