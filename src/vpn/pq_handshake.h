/*
 * StrongVPN Post-Quantum Handshake Protocol Header
 * Direct public key authentication model (no certificates)
 */

#ifndef PQ_HANDSHAKE_H
#define PQ_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "../crypto/ml_dsa.h"
#include "../crypto/ml_kem.h"

// Forward declaration - include the actual header
#include "../network/tunnel.h"

// ============================================================================
// Handshake State Machine
// ============================================================================

typedef enum {
    PQ_STATE_INIT = 0,
    PQ_STATE_CLIENT_HELLO_SENT,
    PQ_STATE_SERVER_HELLO_RECEIVED,
    PQ_STATE_KEY_EXCHANGE_COMPLETE,
    PQ_STATE_AUTHENTICATED,
    PQ_STATE_ESTABLISHED,
    PQ_STATE_ERROR
} pq_handshake_state_t;

// ============================================================================
// Handshake Context Structure
// ============================================================================

typedef struct {
    // State machine
    pq_handshake_state_t state;
    int is_server;
    
    // Local cryptographic keys (generated fresh each handshake)
    ml_dsa_keypair_t local_dsa_keypair;
    ml_kem_keypair_t local_kem_keypair;
    
    // Peer public keys (received directly in handshake - no certificates)
    uint8_t peer_dsa_pubkey[ML_DSA_65_PUBKEY_BYTES];   // 1952 bytes
    uint8_t peer_kem_pubkey[ML_KEM_768_PUBKEY_BYTES];  // 1184 bytes
    
    // Handshake nonces
    uint8_t client_nonce[32];
    uint8_t server_nonce[32];
    
    // Shared secret from ML-KEM
    uint8_t shared_secret[ML_KEM_768_SHARED_SECRET_BYTES]; // 32 bytes
    
    // Session keys derived from shared secret
    uint8_t session_key[32];
    uint8_t mac_key[32];
    
    // Transcript hash context
    EVP_MD_CTX *hash_ctx;
    uint8_t handshake_hash[32];
} pq_handshake_ctx_t;

// ============================================================================
// Function Declarations
// ============================================================================

// Handshake initialization and cleanup
int pq_handshake_init(pq_handshake_ctx_t *ctx, int is_server);
void pq_handshake_cleanup(pq_handshake_ctx_t *ctx);

// Message sending functions
int pq_send_client_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx);
int pq_send_server_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx);
int pq_send_key_exchange(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx);

// Message processing functions
int pq_process_client_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx,
                           const uint8_t *buffer, size_t len);
int pq_process_server_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx,
                           const uint8_t *buffer, size_t len);
int pq_process_key_exchange(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx,
                           const uint8_t *buffer, size_t len);

// Complete handshake functions (called by main applications)
int pq_complete_handshake_client(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx);
int pq_complete_handshake_server(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx);

// Session key derivation and management
int derive_session_keys(pq_handshake_ctx_t *pq_ctx);
int pq_get_session_key(const pq_handshake_ctx_t *ctx, uint8_t *key, size_t key_len);
int pq_clear_session_key(pq_handshake_ctx_t *ctx);

#endif // PQ_HANDSHAKE_H
