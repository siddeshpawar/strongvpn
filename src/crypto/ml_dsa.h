/*
 * ML-DSA (FIPS 204) Interface Header
 * Post-quantum digital signature algorithms
 */

#ifndef ML_DSA_H
#define ML_DSA_H

#include <stdint.h>
#include <stddef.h>

// ML-DSA-65 parameters (Category III security)
#define ML_DSA_65 65
#define ML_DSA_65_PUBKEY_BYTES  1952
#define ML_DSA_65_PRIVKEY_BYTES 4032
#define ML_DSA_65_SIGNATURE_BYTES 3309

// Key pair structure
typedef struct {
    uint8_t public_key[ML_DSA_65_PUBKEY_BYTES];
    uint8_t private_key[ML_DSA_65_PRIVKEY_BYTES];
} ml_dsa_keypair_t;

// Function declarations
int ml_dsa_keygen(ml_dsa_keypair_t *keypair, int variant);
int ml_dsa_sign(uint8_t *signature, size_t *sig_len, 
                const uint8_t *message, size_t msg_len,
                const ml_dsa_keypair_t *keypair);
int ml_dsa_verify(const uint8_t *signature, size_t sig_len,
                  const uint8_t *message, size_t msg_len,
                  const uint8_t *public_key);
void ml_dsa_keypair_free(ml_dsa_keypair_t *keypair);

#endif // ML_DSA_H
