/*
 * Post-Quantum Authentication Header
 * Direct public key authentication without certificates
 */

#ifndef PQ_AUTH_H
#define PQ_AUTH_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/ml_dsa.h"

// Forward declarations
struct tunnel_ctx;
struct pq_handshake_ctx;
typedef struct tunnel_ctx tunnel_ctx_t;
typedef struct pq_handshake_ctx pq_handshake_ctx_t;

// Authentication result codes
#define PQ_AUTH_SUCCESS     0
#define PQ_AUTH_ERROR      -1
#define PQ_AUTH_INVALID    -2
#define PQ_AUTH_REJECTED   -3

// Peer authentication structure
typedef struct {
    uint8_t public_key[ML_DSA_65_PUBKEY_BYTES];
    uint8_t peer_id[32];        // SHA256 of public key
    int is_authenticated;
    uint64_t timestamp;
} pq_peer_auth_t;

// Function declarations
int pq_auth_init(void);
void pq_auth_cleanup(void);

int pq_auth_generate_signature(uint8_t *signature, size_t *sig_len,
                              const uint8_t *message, size_t msg_len,
                              const ml_dsa_keypair_t *keypair);

int pq_auth_verify_signature(const uint8_t *signature, size_t sig_len,
                            const uint8_t *message, size_t msg_len,
                            const uint8_t *public_key);

int pq_auth_store_peer_key(const uint8_t *public_key, const uint8_t *peer_id);
int pq_auth_get_peer_key(uint8_t *public_key, const uint8_t *peer_id);
int pq_auth_is_peer_trusted(const uint8_t *peer_id);

int pq_auth_handshake_authenticate(struct tunnel_ctx *tunnel, 
                                  struct pq_handshake_ctx *pq_ctx);

// Complete handshake functions (called by main applications)
int pq_complete_handshake_client(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx);
int pq_complete_handshake_server(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx);

#endif // PQ_AUTH_H
