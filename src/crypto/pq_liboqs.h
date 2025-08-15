/*
 * StrongVPN Post-Quantum Cryptography - liboqs Integration
 * Real NIST-standardized ML-KEM and ML-DSA implementations
 */

#ifndef PQ_LIBOQS_H
#define PQ_LIBOQS_H

#include <stdint.h>
#include <stddef.h>
#include "pq_core.h"
#include "ml_kem.h"    // For ml_kem_keypair_t definition
#include "ml_dsa.h"    // For ml_dsa_keypair_t definition

// Compile-time switch between stub and real crypto
#ifdef USE_LIBOQS
    #include <oqs/oqs.h>
    #define CRYPTO_IMPLEMENTATION "liboqs (Real NIST Crypto)"
#else
    #define CRYPTO_IMPLEMENTATION "Stubs (Testing Only)"
#endif

// ============================================================================
// ML-KEM Real Implementation Functions
// ============================================================================

#ifdef USE_LIBOQS
// Real liboqs ML-KEM implementation
int ml_kem_keygen_real(ml_kem_keypair_t *keypair, int variant);
int ml_kem_encapsulate_real(uint8_t *ciphertext, uint8_t *shared_secret,
                           const uint8_t *public_key);
int ml_kem_decapsulate_real(uint8_t *shared_secret,
                            const uint8_t *ciphertext,
                            const ml_kem_keypair_t *keypair);
#endif

// ============================================================================
// ML-DSA Real Implementation Functions  
// ============================================================================

#ifdef USE_LIBOQS
// Real liboqs ML-DSA implementation
int ml_dsa_keygen_real(ml_dsa_keypair_t *keypair, int variant);
int ml_dsa_sign_real(uint8_t *signature, size_t *sig_len,
                     const uint8_t *message, size_t msg_len,
                     const ml_dsa_keypair_t *keypair);
int ml_dsa_verify_real(const uint8_t *signature, size_t sig_len,
                      const uint8_t *message, size_t msg_len,
                      const uint8_t *public_key);
#endif

// ============================================================================
// Crypto Implementation Selection
// ============================================================================

// Function pointers for runtime selection
typedef struct {
    int (*kem_keygen)(ml_kem_keypair_t *keypair, int variant);
    int (*kem_encapsulate)(uint8_t *ciphertext, uint8_t *shared_secret,
                          const uint8_t *public_key);
    int (*kem_decapsulate)(uint8_t *shared_secret,
                          const uint8_t *ciphertext,
                          const ml_kem_keypair_t *keypair);
    
    int (*dsa_keygen)(ml_dsa_keypair_t *keypair, int variant);
    int (*dsa_sign)(uint8_t *signature, size_t *sig_len,
                   const uint8_t *message, size_t msg_len,
                   const ml_dsa_keypair_t *keypair);
    int (*dsa_verify)(const uint8_t *signature, size_t sig_len,
                     const uint8_t *message, size_t msg_len,
                     const uint8_t *public_key);
    
    const char *implementation_name;
} pq_crypto_ops_t;

// Initialize crypto operations (stub or real)
int pq_crypto_init(pq_crypto_ops_t *ops, int use_real_crypto);
void pq_crypto_cleanup(void);

// Get current crypto implementation info
const char* pq_get_crypto_implementation(void);
int pq_is_real_crypto_available(void);

#endif // PQ_LIBOQS_H
