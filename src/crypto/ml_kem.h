/*
 * ML-KEM (FIPS 203) Interface Header
 * Post-quantum key encapsulation mechanism
 */

#ifndef ML_KEM_H
#define ML_KEM_H

#include <stdint.h>
#include <stddef.h>

// ML-KEM algorithm variants (security levels)
#define ML_KEM_512  512   // Category I security
#define ML_KEM_768  768   // Category III security
#define ML_KEM_1024 1024  // Category V security

// ML-KEM-768 parameters (Category III security)
#define ML_KEM_768_PUBKEY_BYTES     1184
#define ML_KEM_768_PRIVKEY_BYTES    2400
#define ML_KEM_768_CIPHERTEXT_BYTES 1088
#define ML_KEM_768_SHARED_SECRET_BYTES 32

// Key pair structure
typedef struct {
    uint8_t public_key[ML_KEM_768_PUBKEY_BYTES];
    uint8_t private_key[ML_KEM_768_PRIVKEY_BYTES];
} ml_kem_keypair_t;

// Function declarations
int ml_kem_keygen(ml_kem_keypair_t *keypair, int variant);
int ml_kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret,
                       const uint8_t *public_key);
int ml_kem_decapsulate(uint8_t *shared_secret,
                       const uint8_t *ciphertext,
                       const ml_kem_keypair_t *keypair);
void ml_kem_keypair_free(ml_kem_keypair_t *keypair);

#endif // ML_KEM_H
