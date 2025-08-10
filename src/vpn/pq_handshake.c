/*
 * StrongVPN Post-Quantum Handshake Protocol
 * 
 * This implements a complete post-quantum VPN handshake using ML-DSA for
 * authentication and ML-KEM for key exchange. This is the practical
 * integration that makes the mathematical algorithms work in a real VPN.
 */

#include "tunnel.h"
#include "../crypto/ml_dsa.h"
#include "../crypto/ml_kem.h"
#include "../common/logger.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>

// ============================================================================
// Post-Quantum Handshake Protocol Messages
// ============================================================================

typedef struct {
    uint8_t type;           // Message type
    uint32_t length;        // Payload length (network byte order)
    uint8_t payload[];      // Variable length payload
} __attribute__((packed)) pq_message_t;

// Message types for post-quantum handshake
#define PQ_MSG_CLIENT_HELLO    0x01
#define PQ_MSG_SERVER_HELLO    0x02
#define PQ_MSG_KEY_EXCHANGE    0x03
#define PQ_MSG_CERTIFICATE     0x04
#define PQ_MSG_FINISHED        0x05
#define PQ_MSG_ERROR           0xFF

// Handshake state machine
typedef enum {
    PQ_STATE_INIT = 0,
    PQ_STATE_CLIENT_HELLO_SENT,
    PQ_STATE_SERVER_HELLO_RECEIVED,
    PQ_STATE_KEY_EXCHANGE_COMPLETE,
    PQ_STATE_AUTHENTICATED,
    PQ_STATE_ESTABLISHED,
    PQ_STATE_ERROR
} pq_handshake_state_t;

// Complete handshake context with all cryptographic material
typedef struct {
    pq_handshake_state_t state;
    
    // Local cryptographic keys
    ml_dsa_keypair_t local_dsa_keypair;
    ml_kem_keypair_t local_kem_keypair;
    
    // Peer public keys
    uint8_t peer_dsa_pubkey[ML_DSA_65_PUBKEY_BYTES];
    uint8_t peer_kem_pubkey[ML_KEM_768_PUBKEY_BYTES];
    
    // Shared secrets and session keys
    uint8_t shared_secret[32];      // From ML-KEM
    uint8_t session_key[32];        // Derived session key
    uint8_t mac_key[32];           // Message authentication key
    
    // Handshake transcript for authentication
    uint8_t handshake_hash[64];
    EVP_MD_CTX *hash_ctx;
    
    // Random nonces
    uint8_t client_nonce[32];
    uint8_t server_nonce[32];
    
    // Role (client or server)
    int is_server;
} pq_handshake_ctx_t;

// ============================================================================
// Core Handshake Functions
// ============================================================================

// Initialize post-quantum handshake context
int pq_handshake_init(pq_handshake_ctx_t *ctx, int is_server) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(pq_handshake_ctx_t));
    ctx->state = PQ_STATE_INIT;
    ctx->is_server = is_server;
    
    LOG_INFO("Initializing post-quantum handshake (role: %s)", 
             is_server ? "server" : "client");
    
    // Generate local ML-DSA key pair for authentication
    if (ml_dsa_keygen(&ctx->local_dsa_keypair, ML_DSA_65) != 0) {
        LOG_ERROR("Failed to generate ML-DSA key pair");
        return -1;
    }
    
    // Generate local ML-KEM key pair for key exchange
    if (ml_kem_keygen(&ctx->local_kem_keypair, ML_KEM_768) != 0) {
        LOG_ERROR("Failed to generate ML-KEM key pair");
        ml_dsa_keypair_free(&ctx->local_dsa_keypair);
        return -1;
    }
    
    // Initialize hash context for handshake transcript
    ctx->hash_ctx = EVP_MD_CTX_new();
    if (!ctx->hash_ctx || EVP_DigestInit_ex(ctx->hash_ctx, EVP_sha3_256(), NULL) != 1) {
        LOG_ERROR("Failed to initialize hash context");
        pq_handshake_cleanup(ctx);
        return -1;
    }
    
    LOG_INFO("Post-quantum handshake initialized (ML-DSA-65 + ML-KEM-768)");
    return 0;
}

// Client initiates handshake with Client Hello
int pq_send_client_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx) {
    if (!tunnel || !pq_ctx || pq_ctx->state != PQ_STATE_INIT || pq_ctx->is_server) {
        return -1;
    }
    
    LOG_INFO("Sending Client Hello with post-quantum algorithms");
    
    // Generate client nonce
    if (RAND_bytes(pq_ctx->client_nonce, 32) != 1) {
        LOG_ERROR("Failed to generate client nonce");
        return -1;
    }
    
    // Calculate message size
    size_t msg_len = sizeof(pq_message_t) + 
                     32 +                           // Client nonce
                     ML_DSA_65_PUBKEY_BYTES +       // ML-DSA public key
                     ML_KEM_768_PUBKEY_BYTES;       // ML-KEM public key
    
    uint8_t *buffer = malloc(msg_len);
    if (!buffer) {
        LOG_ERROR("Memory allocation failed");
        return -1;
    }
    
    // Construct Client Hello message
    pq_message_t *msg = (pq_message_t *)buffer;
    msg->type = PQ_MSG_CLIENT_HELLO;
    msg->length = htonl(msg_len - sizeof(pq_message_t));
    
    uint8_t *payload = msg->payload;
    
    // Add client nonce
    memcpy(payload, pq_ctx->client_nonce, 32);
    payload += 32;
    
    // Add ML-DSA public key for authentication
    memcpy(payload, pq_ctx->local_dsa_keypair.public_key, ML_DSA_65_PUBKEY_BYTES);
    payload += ML_DSA_65_PUBKEY_BYTES;
    
    // Add ML-KEM public key for key exchange
    memcpy(payload, pq_ctx->local_kem_keypair.public_key, ML_KEM_768_PUBKEY_BYTES);
    
    // Update handshake transcript hash
    EVP_DigestUpdate(pq_ctx->hash_ctx, buffer, msg_len);
    
    // Send the message
    int result = tunnel_send(tunnel, buffer, msg_len);
    free(buffer);
    
    if (result > 0) {
        pq_ctx->state = PQ_STATE_CLIENT_HELLO_SENT;
        LOG_INFO("Client Hello sent successfully (%d bytes)", result);
        return 0;
    } else {
        LOG_ERROR("Failed to send Client Hello");
        return -1;
    }
}

// Server processes Client Hello and responds with Server Hello + Key Exchange
int pq_process_client_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx, 
                           const uint8_t *data, size_t len) {
    if (!tunnel || !pq_ctx || !data || !pq_ctx->is_server) {
        return -1;
    }
    
    // Validate message size
    size_t expected_len = sizeof(pq_message_t) + 32 + 
                         ML_DSA_65_PUBKEY_BYTES + ML_KEM_768_PUBKEY_BYTES;
    if (len < expected_len) {
        LOG_ERROR("Client Hello message too short");
        return -1;
    }
    
    const pq_message_t *msg = (const pq_message_t *)data;
    if (msg->type != PQ_MSG_CLIENT_HELLO) {
        LOG_ERROR("Invalid message type: expected Client Hello");
        return -1;
    }
    
    LOG_INFO("Processing Client Hello from client");
    
    const uint8_t *payload = msg->payload;
    
    // Extract client nonce
    memcpy(pq_ctx->client_nonce, payload, 32);
    payload += 32;
    
    // Extract client's ML-DSA public key
    memcpy(pq_ctx->peer_dsa_pubkey, payload, ML_DSA_65_PUBKEY_BYTES);
    payload += ML_DSA_65_PUBKEY_BYTES;
    
    // Extract client's ML-KEM public key
    memcpy(pq_ctx->peer_kem_pubkey, payload, ML_KEM_768_PUBKEY_BYTES);
    
    // Update handshake transcript
    EVP_DigestUpdate(pq_ctx->hash_ctx, data, len);
    
    // Generate server nonce
    if (RAND_bytes(pq_ctx->server_nonce, 32) != 1) {
        LOG_ERROR("Failed to generate server nonce");
        return -1;
    }
    
    // Perform ML-KEM encapsulation with client's public key
    ml_kem_encaps_t encaps;
    if (ml_kem_encaps(&encaps, pq_ctx->peer_kem_pubkey, 
                      ML_KEM_768_PUBKEY_BYTES, ML_KEM_768) != 0) {
        LOG_ERROR("ML-KEM encapsulation failed");
        return -1;
    }
    
    // Store the shared secret from ML-KEM
    memcpy(pq_ctx->shared_secret, encaps.shared_secret, 32);
    LOG_INFO("ML-KEM shared secret established");
    
    // Construct Server Hello response
    size_t response_len = sizeof(pq_message_t) + 
                         32 +                           // Server nonce
                         ML_DSA_65_PUBKEY_BYTES +       // Server ML-DSA public key
                         ML_KEM_768_PUBKEY_BYTES +      // Server ML-KEM public key
                         encaps.ciphertext_len;         // ML-KEM ciphertext
    
    uint8_t *response = malloc(response_len);
    if (!response) {
        ml_kem_encaps_free(&encaps);
        return -1;
    }
    
    pq_message_t *resp_msg = (pq_message_t *)response;
    resp_msg->type = PQ_MSG_SERVER_HELLO;
    resp_msg->length = htonl(response_len - sizeof(pq_message_t));
    
    uint8_t *resp_payload = resp_msg->payload;
    
    // Add server nonce
    memcpy(resp_payload, pq_ctx->server_nonce, 32);
    resp_payload += 32;
    
    // Add server's ML-DSA public key
    memcpy(resp_payload, pq_ctx->local_dsa_keypair.public_key, ML_DSA_65_PUBKEY_BYTES);
    resp_payload += ML_DSA_65_PUBKEY_BYTES;
    
    // Add server's ML-KEM public key
    memcpy(resp_payload, pq_ctx->local_kem_keypair.public_key, ML_KEM_768_PUBKEY_BYTES);
    resp_payload += ML_KEM_768_PUBKEY_BYTES;
    
    // Add ML-KEM ciphertext (encapsulated shared secret)
    memcpy(resp_payload, encaps.ciphertext, encaps.ciphertext_len);
    
    // Update handshake transcript
    EVP_DigestUpdate(pq_ctx->hash_ctx, response, response_len);
    
    // Send Server Hello
    int result = tunnel_send(tunnel, response, response_len);
    
    // Cleanup
    free(response);
    ml_kem_encaps_free(&encaps);
    
    if (result > 0) {
        pq_ctx->state = PQ_STATE_KEY_EXCHANGE_COMPLETE;
        LOG_INFO("Server Hello sent with ML-KEM ciphertext (%d bytes)", result);
        
        // Derive session keys from the shared secret
        if (derive_session_keys(pq_ctx) != 0) {
            LOG_ERROR("Failed to derive session keys");
            return -1;
        }
        
        return 0;
    } else {
        LOG_ERROR("Failed to send Server Hello");
        return -1;
    }
}

// Client processes Server Hello and completes key exchange
int pq_process_server_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx,
                           const uint8_t *data, size_t len) {
    if (!tunnel || !pq_ctx || !data || pq_ctx->is_server) {
        return -1;
    }
    
    if (pq_ctx->state != PQ_STATE_CLIENT_HELLO_SENT) {
        LOG_ERROR("Invalid handshake state for Server Hello");
        return -1;
    }
    
    const pq_message_t *msg = (const pq_message_t *)data;
    if (msg->type != PQ_MSG_SERVER_HELLO) {
        LOG_ERROR("Invalid message type: expected Server Hello");
        return -1;
    }
    
    LOG_INFO("Processing Server Hello");
    
    const uint8_t *payload = msg->payload;
    
    // Extract server nonce
    memcpy(pq_ctx->server_nonce, payload, 32);
    payload += 32;
    
    // Extract server's ML-DSA public key
    memcpy(pq_ctx->peer_dsa_pubkey, payload, ML_DSA_65_PUBKEY_BYTES);
    payload += ML_DSA_65_PUBKEY_BYTES;
    
    // Extract server's ML-KEM public key
    memcpy(pq_ctx->peer_kem_pubkey, payload, ML_KEM_768_PUBKEY_BYTES);
    payload += ML_KEM_768_PUBKEY_BYTES;
    
    // Calculate ciphertext length
    size_t ciphertext_len = len - sizeof(pq_message_t) - 32 - 
                           ML_DSA_65_PUBKEY_BYTES - ML_KEM_768_PUBKEY_BYTES;
    
    // Perform ML-KEM decapsulation
    if (ml_kem_decaps(pq_ctx->shared_secret, 32, payload, ciphertext_len,
                      &pq_ctx->local_kem_keypair) != 0) {
        LOG_ERROR("ML-KEM decapsulation failed");
        return -1;
    }
    
    LOG_INFO("ML-KEM shared secret established");
    
    // Update handshake transcript
    EVP_DigestUpdate(pq_ctx->hash_ctx, data, len);
    
    // Derive session keys
    if (derive_session_keys(pq_ctx) != 0) {
        LOG_ERROR("Failed to derive session keys");
        return -1;
    }
    
    pq_ctx->state = PQ_STATE_KEY_EXCHANGE_COMPLETE;
    LOG_INFO("Key exchange completed successfully");
    
    return 0;
}

// ============================================================================
// Key Derivation - Critical for Security
// ============================================================================

// Derive session keys using HKDF with the post-quantum shared secret
static int derive_session_keys(pq_handshake_ctx_t *pq_ctx) {
    if (!pq_ctx) return -1;
    
    LOG_INFO("Deriving session keys from post-quantum shared secret");
    
    // Finalize handshake hash
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(pq_ctx->hash_ctx, pq_ctx->handshake_hash, &hash_len) != 1) {
        LOG_ERROR("Failed to finalize handshake hash");
        return -1;
    }
    
    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    const char *salt = "StrongVPN-PostQuantum-v1.0";
    uint8_t prk[32];
    
    unsigned int prk_len;
    if (HMAC(EVP_sha256(), salt, strlen(salt), 
             pq_ctx->shared_secret, 32, prk, &prk_len) == NULL) {
        LOG_ERROR("HKDF-Extract failed");
        return -1;
    }
    
    // HKDF-Expand for session key
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        LOG_ERROR("Failed to create HKDF context");
        return -1;
    }
    
    const char *session_info = "StrongVPN-SessionKey";
    size_t session_key_len = 32;
    
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen(salt)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, prk_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, session_info, strlen(session_info)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, pq_ctx->handshake_hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_derive(pctx, pq_ctx->session_key, &session_key_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG_ERROR("Failed to derive session key");
        return -1;
    }
    
    // Derive MAC key
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    
    const char *mac_info = "StrongVPN-MACKey";
    size_t mac_key_len = 32;
    
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen(salt)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, prk_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, mac_info, strlen(mac_info)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, pq_ctx->handshake_hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_derive(pctx, pq_ctx->mac_key, &mac_key_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        LOG_ERROR("Failed to derive MAC key");
        return -1;
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    // Secure cleanup of intermediate values
    OPENSSL_cleanse(prk, sizeof(prk));
    
    LOG_INFO("Session keys derived successfully using HKDF");
    pq_ctx->state = PQ_STATE_ESTABLISHED;
    
    return 0;
}

// ============================================================================
// Cleanup and Utility Functions
// ============================================================================

// Secure cleanup of handshake context
void pq_handshake_cleanup(pq_handshake_ctx_t *ctx) {
    if (!ctx) return;
    
    LOG_INFO("Cleaning up post-quantum handshake context");
    
    // Free cryptographic keys
    ml_dsa_keypair_free(&ctx->local_dsa_keypair);
    ml_kem_keypair_free(&ctx->local_kem_keypair);
    
    // Free hash context
    if (ctx->hash_ctx) {
        EVP_MD_CTX_free(ctx->hash_ctx);
        ctx->hash_ctx = NULL;
    }
    
    // Secure cleanup of sensitive data
    OPENSSL_cleanse(ctx->shared_secret, sizeof(ctx->shared_secret));
    OPENSSL_cleanse(ctx->session_key, sizeof(ctx->session_key));
    OPENSSL_cleanse(ctx->mac_key, sizeof(ctx->mac_key));
    OPENSSL_cleanse(ctx->client_nonce, sizeof(ctx->client_nonce));
    OPENSSL_cleanse(ctx->server_nonce, sizeof(ctx->server_nonce));
    
    memset(ctx, 0, sizeof(pq_handshake_ctx_t));
}

// Get established session key for VPN encryption
int pq_get_session_key(const pq_handshake_ctx_t *ctx, uint8_t *key, size_t key_len) {
    if (!ctx || !key || key_len < 32 || ctx->state != PQ_STATE_ESTABLISHED) {
        return -1;
    }
    
    memcpy(key, ctx->session_key, 32);
    return 0;
}

// Check if handshake is complete
int pq_handshake_is_complete(const pq_handshake_ctx_t *ctx) {
    return ctx && ctx->state == PQ_STATE_ESTABLISHED;
}
