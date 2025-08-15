/*
 * StrongVPN Post-Quantum Cryptography - liboqs Integration
 * Real NIST-standardized ML-KEM and ML-DSA implementations
 */

#include "pq_liboqs.h"
#include "ml_kem.h"
#include "ml_dsa.h"
#include "../common/logger.h"
#include <string.h>
#include <stdlib.h>

// Global crypto operations structure
static pq_crypto_ops_t g_crypto_ops;
static int g_crypto_initialized = 0;

// ============================================================================
// Real liboqs ML-KEM Implementation
// ============================================================================

#ifdef USE_LIBOQS

int ml_kem_keygen_real(ml_kem_keypair_t *keypair, int variant) {
    if (!keypair) return -1;
    
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        LOG_ERROR("Failed to initialize ML-KEM-768");
        return -1;
    }
    
    OQS_STATUS status = OQS_KEM_keypair(kem, keypair->public_key, keypair->private_key);
    OQS_KEM_free(kem);
    
    if (status != OQS_SUCCESS) {
        LOG_ERROR("ML-KEM key generation failed");
        return -1;
    }
    
    LOG_INFO("Generated real ML-KEM-768 keypair using liboqs");
    return 0;
}

int ml_kem_encapsulate_real(uint8_t *ciphertext, uint8_t *shared_secret,
                           const uint8_t *public_key) {
    if (!ciphertext || !shared_secret || !public_key) return -1;
    
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        LOG_ERROR("Failed to initialize ML-KEM-768 for encapsulation");
        return -1;
    }
    
    OQS_STATUS status = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_free(kem);
    
    if (status != OQS_SUCCESS) {
        LOG_ERROR("ML-KEM encapsulation failed");
        return -1;
    }
    
    LOG_DEBUG("ML-KEM encapsulation successful (real crypto)");
    return 0;
}

int ml_kem_decapsulate_real(uint8_t *shared_secret,
                           const uint8_t *ciphertext,
                           const ml_kem_keypair_t *keypair) {
    if (!shared_secret || !ciphertext || !keypair) return -1;
    
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        LOG_ERROR("Failed to initialize ML-KEM-768 for decapsulation");
        return -1;
    }
    
    OQS_STATUS status = OQS_KEM_decaps(kem, shared_secret, ciphertext, keypair->private_key);
    OQS_KEM_free(kem);
    
    if (status != OQS_SUCCESS) {
        LOG_ERROR("ML-KEM decapsulation failed");
        return -1;
    }
    
    LOG_DEBUG("ML-KEM decapsulation successful (real crypto)");
    return 0;
}

// ============================================================================
// Real liboqs ML-DSA Implementation
// ============================================================================

int ml_dsa_keygen_real(ml_dsa_keypair_t *keypair, int variant) {
    if (!keypair) return -1;
    
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (!sig) {
        LOG_ERROR("Failed to initialize ML-DSA-65");
        return -1;
    }
    
    OQS_STATUS status = OQS_SIG_keypair(sig, keypair->public_key, keypair->private_key);
    OQS_SIG_free(sig);
    
    if (status != OQS_SUCCESS) {
        LOG_ERROR("ML-DSA key generation failed");
        return -1;
    }
    
    LOG_INFO("Generated real ML-DSA-65 keypair using liboqs");
    return 0;
}

int ml_dsa_sign_real(uint8_t *signature, size_t *sig_len,
                    const uint8_t *message, size_t msg_len,
                    const ml_dsa_keypair_t *keypair) {
    if (!signature || !sig_len || !message || !keypair) return -1;
    
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (!sig) {
        LOG_ERROR("Failed to initialize ML-DSA-65 for signing");
        return -1;
    }
    
    OQS_STATUS status = OQS_SIG_sign(sig, signature, sig_len, message, msg_len, keypair->private_key);
    OQS_SIG_free(sig);
    
    if (status != OQS_SUCCESS) {
        LOG_ERROR("ML-DSA signing failed");
        return -1;
    }
    
    LOG_DEBUG("ML-DSA signature generated (real crypto)");
    return 0;
}

int ml_dsa_verify_real(const uint8_t *signature, size_t sig_len,
                      const uint8_t *message, size_t msg_len,
                      const uint8_t *public_key) {
    if (!signature || !message || !public_key) return -1;
    
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (!sig) {
        LOG_ERROR("Failed to initialize ML-DSA-65 for verification");
        return -1;
    }
    
    OQS_STATUS status = OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key);
    OQS_SIG_free(sig);
    
    if (status != OQS_SUCCESS) {
        LOG_DEBUG("ML-DSA signature verification failed (real crypto)");
        return -1;
    }
    
    LOG_DEBUG("ML-DSA signature verified successfully (real crypto)");
    return 0;
}

#endif // USE_LIBOQS

// ============================================================================
// Crypto Implementation Selection
// ============================================================================

int pq_crypto_init(pq_crypto_ops_t *ops, int use_real_crypto) {
    if (!ops) return -1;
    
    memset(ops, 0, sizeof(pq_crypto_ops_t));
    
#ifdef USE_LIBOQS
    if (use_real_crypto) {
        // Use real liboqs implementations
        ops->kem_keygen = ml_kem_keygen_real;
        ops->kem_encapsulate = ml_kem_encapsulate_real;
        ops->kem_decapsulate = ml_kem_decapsulate_real;
        
        ops->dsa_keygen = ml_dsa_keygen_real;
        ops->dsa_sign = ml_dsa_sign_real;
        ops->dsa_verify = ml_dsa_verify_real;
        
        ops->implementation_name = "liboqs (Real NIST Crypto)";
        
        LOG_INFO("Initialized REAL post-quantum cryptography using liboqs");
        LOG_INFO("Security Level: 128-bit quantum resistance");
        LOG_INFO("Algorithms: ML-KEM-768 + ML-DSA-65 (NIST FIPS 203/204)");
    } else {
#endif
        // Use stub implementations
        ops->kem_keygen = ml_kem_keygen;
        ops->kem_encapsulate = ml_kem_encapsulate;
        ops->kem_decapsulate = ml_kem_decapsulate;
        
        ops->dsa_keygen = ml_dsa_keygen;
        ops->dsa_sign = ml_dsa_sign;
        ops->dsa_verify = ml_dsa_verify;
        
        ops->implementation_name = "Stubs (Testing Only - NOT SECURE)";
        
        LOG_WARN("Using STUB post-quantum cryptography - NOT SECURE!");
        LOG_WARN("For production use, compile with -DUSE_LIBOQS");
#ifdef USE_LIBOQS
    }
#endif
    
    // Copy to global structure
    memcpy(&g_crypto_ops, ops, sizeof(pq_crypto_ops_t));
    g_crypto_initialized = 1;
    
    return 0;
}

void pq_crypto_cleanup(void) {
    if (g_crypto_initialized) {
        memset(&g_crypto_ops, 0, sizeof(pq_crypto_ops_t));
        g_crypto_initialized = 0;
        LOG_INFO("Post-quantum crypto cleanup completed");
    }
}

const char* pq_get_crypto_implementation(void) {
    if (!g_crypto_initialized) {
        return "Not initialized";
    }
    return g_crypto_ops.implementation_name;
}

int pq_is_real_crypto_available(void) {
#ifdef USE_LIBOQS
    return 1;
#else
    return 0;
#endif
}

// ============================================================================
// Global Crypto Operations Access
// ============================================================================

pq_crypto_ops_t* pq_get_crypto_ops(void) {
    if (!g_crypto_initialized) {
        LOG_ERROR("Crypto operations not initialized");
        return NULL;
    }
    return &g_crypto_ops;
}
