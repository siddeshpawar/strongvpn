/*
 * Post-Quantum Cryptographic Core Header
 * Mathematical foundations for ML-DSA and ML-KEM algorithms
 */

#ifndef PQ_CORE_H
#define PQ_CORE_H

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// ML-DSA-65 Constants and Parameters
// ============================================================================

#define ML_DSA_Q        8380417    // Prime modulus
#define ML_DSA_D        13         // Dropped bits from t
#define ML_DSA_TAU      39         // Number of ±1's in c
#define ML_DSA_BETA     78         // Bound for ||s1|| and ||s2||
#define ML_DSA_GAMMA1   (1 << 17)  // Coefficient range for y
#define ML_DSA_GAMMA2   ((ML_DSA_Q-1)/88)  // Low-order rounding range

// ML-DSA-65 specific parameters
#define ML_DSA_K        6          // Rows in A
#define ML_DSA_L        5          // Columns in A
#define ML_DSA_ETA      4          // Bound for coefficients of s1, s2

// ============================================================================
// ML-KEM-768 Constants and Parameters
// ============================================================================

#define ML_KEM_Q        3329       // Prime modulus
#define ML_KEM_N        256        // Polynomial degree
#define ML_KEM_K        3          // Module rank for ML-KEM-768
#define ML_KEM_ETA1     2          // Noise parameter η₁
#define ML_KEM_ETA2     2          // Noise parameter η₂
#define ML_KEM_DU       10         // Compression parameter for u
#define ML_KEM_DV       4          // Compression parameter for v

// ============================================================================
// Core Mathematical Functions
// ============================================================================

// Random number generation
int pq_randombytes(uint8_t *out, size_t outlen);

// Modular arithmetic
int32_t pq_barrett_reduce(int64_t a);
int32_t pq_montgomery_reduce(int64_t a);
int32_t pq_reduce32(int32_t a);

// NTT operations
void pq_ntt(int32_t a[ML_DSA_N]);
void pq_invntt_tomont(int32_t a[ML_DSA_N]);

// Polynomial operations
void pq_poly_add(int32_t *c, const int32_t *a, const int32_t *b);
void pq_poly_sub(int32_t *c, const int32_t *a, const int32_t *b);
void pq_poly_pointwise_montgomery(int32_t *c, const int32_t *a, const int32_t *b);

// Sampling functions
void pq_poly_uniform(int32_t *a, const uint8_t seed[32], uint16_t nonce);
void pq_poly_uniform_eta(int32_t *a, const uint8_t seed[64], uint16_t nonce);
void pq_poly_uniform_gamma1(int32_t *a, const uint8_t seed[64], uint16_t nonce);

// Packing/unpacking
void pq_pack_pk(uint8_t pk[ML_DSA_65_PUBKEY_BYTES], const int32_t rho[32], const int32_t t1[ML_DSA_K][ML_DSA_N]);
void pq_unpack_pk(int32_t rho[32], int32_t t1[ML_DSA_K][ML_DSA_N], const uint8_t pk[ML_DSA_65_PUBKEY_BYTES]);

// Signature operations
void pq_challenge(int32_t *c, const uint8_t seed[32]);
int pq_poly_chknorm(const int32_t *a, int32_t B);

// Utility functions
void pq_poly_power2round(int32_t *a1, int32_t *a0, const int32_t *a);
void pq_poly_decompose(int32_t *a1, int32_t *a0, const int32_t *a);
int32_t pq_make_hint(int32_t a0, int32_t a1);
int32_t pq_use_hint(int32_t a, uint32_t hint);

// Memory management
void pq_secure_zero(void *ptr, size_t len);
int pq_constant_time_compare(const void *a, const void *b, size_t len);

// Hash functions (using OpenSSL)
int pq_hash_sha3_256(uint8_t *out, const uint8_t *in, size_t inlen);
int pq_hash_sha3_512(uint8_t *out, const uint8_t *in, size_t inlen);
int pq_hash_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#endif // PQ_CORE_H
