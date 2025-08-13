/*
 * StrongVPN Post-Quantum Handshake Protocol Implementation
 * 
 * This implements a complete post-quantum VPN handshake using ML-DSA for
 * authentication and ML-KEM for key exchange. This is the practical
 * integration that makes the mathematical algorithms work in a real VPN.
 */

#include "pq_handshake.h"
#include "../crypto/ml_dsa.h"
#include "../crypto/ml_kem.h"
#include "../crypto/pq_core.h"
#include "../common/logger.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

// ============================================================================
// Handshake Implementation - NO DUPLICATE DEFINITIONS
// ============================================================================

// Initialize post-quantum handshake context
int pq_handshake_init(pq_handshake_ctx_t *ctx, int is_server) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(pq_handshake_ctx_t));
    ctx->state = PQ_STATE_INIT;
    ctx->is_server = is_server;
    
    // Generate local ML-DSA keypair for authentication
    if (ml_dsa_keygen(&ctx->local_dsa_keypair, ML_DSA_65) != 0) {
        LOG_ERROR("Failed to generate ML-DSA keypair");
        return -1;
    }
    
    // Generate local ML-KEM keypair for key exchange
    if (ml_kem_keygen(&ctx->local_kem_keypair, ML_KEM_768) != 0) {
        LOG_ERROR("Failed to generate ML-KEM keypair");
        ml_dsa_keypair_free(&ctx->local_dsa_keypair);
        return -1;
    }
    
    // Initialize transcript hash context
    ctx->hash_ctx = EVP_MD_CTX_new();
    if (!ctx->hash_ctx || EVP_DigestInit_ex(ctx->hash_ctx, EVP_sha3_256(), NULL) != 1) {
        LOG_ERROR("Failed to initialize transcript hash");
        pq_handshake_cleanup(ctx);
        return -1;
    }
    
    LOG_INFO("Post-quantum handshake context initialized (server=%d)", is_server);
    return 0;
}

// Send Client Hello message
int pq_send_client_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx) {
    if (!tunnel || !pq_ctx || pq_ctx->state != PQ_STATE_INIT || pq_ctx->is_server) {
        return -1;
    }
    
    // Generate client nonce
    if (RAND_bytes(pq_ctx->client_nonce, 32) != 1) {
        LOG_ERROR("Failed to generate client nonce");
        return -1;
    }
    
    // Calculate message size: type(1) + length(4) + nonce(32) + dsa_pubkey + kem_pubkey
    size_t msg_len = sizeof(pq_message_t) + 32 + ML_DSA_65_PUBKEY_BYTES + ML_KEM_768_PUBKEY_BYTES;
    uint8_t *buffer = malloc(msg_len);
    if (!buffer) {
        LOG_ERROR("Memory allocation failed for Client Hello");
        return -1;
    }
    
    pq_message_t *msg = (pq_message_t *)buffer;
    msg->type = PQ_MSG_CLIENT_HELLO;
    msg->length = htonl(msg_len - sizeof(pq_message_t));
    
    uint8_t *payload = msg->payload;
    
    // Pack: nonce + ML-DSA public key + ML-KEM public key
    memcpy(payload, pq_ctx->client_nonce, 32);
    payload += 32;
    memcpy(payload, pq_ctx->local_dsa_keypair.public_key, ML_DSA_65_PUBKEY_BYTES);
    payload += ML_DSA_65_PUBKEY_BYTES;
    memcpy(payload, pq_ctx->local_kem_keypair.public_key, ML_KEM_768_PUBKEY_BYTES);
    
    // Update transcript hash
    EVP_DigestUpdate(pq_ctx->hash_ctx, buffer, msg_len);
    
    // Send message
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

// Process Client Hello message (server side)
int pq_process_client_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx,
                           const uint8_t *buffer, size_t len) {
    if (!tunnel || !pq_ctx || !buffer || !pq_ctx->is_server) {
        return -1;
    }
    
    const pq_message_t *msg = (const pq_message_t *)buffer;
    if (msg->type != PQ_MSG_CLIENT_HELLO) {
        LOG_ERROR("Expected Client Hello, got message type %d", msg->type);
        return -1;
    }
    
    const uint8_t *payload = msg->payload;
    
    // Verify minimum payload size
    if (len < sizeof(pq_message_t) + 32 + ML_DSA_65_PUBKEY_BYTES + ML_KEM_768_PUBKEY_BYTES) {
        LOG_ERROR("Client Hello payload too small");
        return -1;
    }
    
    // Extract client nonce
    memcpy(pq_ctx->client_nonce, payload, 32);
    payload += 32;
    
    // Extract peer ML-DSA public key
    memcpy(pq_ctx->peer_dsa_pubkey, payload, ML_DSA_65_PUBKEY_BYTES);
    payload += ML_DSA_65_PUBKEY_BYTES;
    
    // Extract peer ML-KEM public key
    memcpy(pq_ctx->peer_kem_pubkey, payload, ML_KEM_768_PUBKEY_BYTES);
    
    // Update transcript hash
    EVP_DigestUpdate(pq_ctx->hash_ctx, buffer, len);
    
    // Generate server nonce
    if (RAND_bytes(pq_ctx->server_nonce, 32) != 1) {
        LOG_ERROR("Failed to generate server nonce");
        return -1;
    }
    
    // Perform ML-KEM encapsulation
    uint8_t ciphertext[ML_KEM_768_CIPHERTEXT_BYTES];
    uint8_t shared_secret[32];
    
    if (ml_kem_encapsulate(ciphertext, shared_secret, pq_ctx->peer_kem_pubkey) != 0) {
        LOG_ERROR("ML-KEM encapsulation failed");
        return -1;
    }
    
    // Store shared secret
    memcpy(pq_ctx->shared_secret, shared_secret, 32);
    
    // Create Server Hello response
    size_t resp_len = sizeof(pq_message_t) + 32 + ML_DSA_65_PUBKEY_BYTES + 
                     ML_KEM_768_CIPHERTEXT_BYTES + ML_DSA_65_SIGNATURE_BYTES;
    uint8_t *resp_buffer = malloc(resp_len);
    if (!resp_buffer) {
        LOG_ERROR("Memory allocation failed for Server Hello");
        return -1;
    }
    
    pq_message_t *resp_msg = (pq_message_t *)resp_buffer;
    resp_msg->type = PQ_MSG_SERVER_HELLO;
    resp_msg->length = htonl(resp_len - sizeof(pq_message_t));
    
    uint8_t *resp_payload = resp_msg->payload;
    
    // Pack: server_nonce + server_dsa_pubkey + kem_ciphertext + signature
    memcpy(resp_payload, pq_ctx->server_nonce, 32);
    resp_payload += 32;
    memcpy(resp_payload, pq_ctx->local_dsa_keypair.public_key, ML_DSA_65_PUBKEY_BYTES);
    resp_payload += ML_DSA_65_PUBKEY_BYTES;
    memcpy(resp_payload, ciphertext, ML_KEM_768_CIPHERTEXT_BYTES);
    resp_payload += ML_KEM_768_CIPHERTEXT_BYTES;
    
    // Create signature over the handshake data
    uint8_t to_sign[64]; // client_nonce + server_nonce
    memcpy(to_sign, pq_ctx->client_nonce, 32);
    memcpy(to_sign + 32, pq_ctx->server_nonce, 32);
    
    size_t sig_len = ML_DSA_65_SIGNATURE_BYTES;
    if (ml_dsa_sign(resp_payload, &sig_len, to_sign, 64, &pq_ctx->local_dsa_keypair) != 0) {
        LOG_ERROR("ML-DSA signature generation failed");
        free(resp_buffer);
        return -1;
    }
    
    // Update transcript hash
    EVP_DigestUpdate(pq_ctx->hash_ctx, resp_buffer, resp_len);
    
    // Send Server Hello
    int result = tunnel_send(tunnel, resp_buffer, resp_len);
    free(resp_buffer);
    
    if (result > 0) {
        // Derive session keys after successful key exchange
        if (derive_session_keys(pq_ctx) != 0) {
            LOG_ERROR("Failed to derive session keys");
            return -1;
        }
        
        pq_ctx->state = PQ_STATE_ESTABLISHED;
        LOG_INFO("Server Hello sent successfully, handshake complete");
        return 0;
    } else {
        LOG_ERROR("Failed to send Server Hello");
        return -1;
    }
}

// Process Server Hello message (client side)
int pq_process_server_hello(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx,
                           const uint8_t *buffer, size_t len) {
    if (!tunnel || !pq_ctx || !buffer || pq_ctx->is_server) {
        return -1;
    }
    
    const pq_message_t *msg = (const pq_message_t *)buffer;
    if (msg->type != PQ_MSG_SERVER_HELLO) {
        LOG_ERROR("Expected Server Hello, got message type %d", msg->type);
        return -1;
    }
    
    const uint8_t *payload = msg->payload;
    
    // Extract server nonce
    memcpy(pq_ctx->server_nonce, payload, 32);
    payload += 32;
    
    // Extract server ML-DSA public key
    memcpy(pq_ctx->peer_dsa_pubkey, payload, ML_DSA_65_PUBKEY_BYTES);
    payload += ML_DSA_65_PUBKEY_BYTES;
    
    // Extract ML-KEM ciphertext
    const uint8_t *ciphertext = payload;
    size_t ciphertext_len = ML_KEM_768_CIPHERTEXT_BYTES;
    payload += ciphertext_len;
    
    // Extract signature
    const uint8_t *signature = payload;
    size_t sig_len = ML_DSA_65_SIGNATURE_BYTES;
    
    // Perform ML-KEM decapsulation
    if (ml_kem_decapsulate(pq_ctx->shared_secret, ciphertext, &pq_ctx->local_kem_keypair) != 0) {
        LOG_ERROR("ML-KEM decapsulation failed");
        return -1;
    }
    
    // Verify server signature
    uint8_t to_verify[64]; // client_nonce + server_nonce
    memcpy(to_verify, pq_ctx->client_nonce, 32);
    memcpy(to_verify + 32, pq_ctx->server_nonce, 32);
    
    if (ml_dsa_verify(signature, sig_len, to_verify, 64, pq_ctx->peer_dsa_pubkey) != 0) {
        LOG_ERROR("Server signature verification failed");
        return -1;
    }
    
    // Update transcript hash
    EVP_DigestUpdate(pq_ctx->hash_ctx, buffer, len);
    
    // Derive session keys
    if (derive_session_keys(pq_ctx) != 0) {
        LOG_ERROR("Failed to derive session keys");
        return -1;
    }
    
    pq_ctx->state = PQ_STATE_ESTABLISHED;
    LOG_INFO("Server Hello processed successfully, handshake complete");
    return 0;
}

// Derive session keys from handshake transcript
int derive_session_keys(pq_handshake_ctx_t *pq_ctx) {
    if (!pq_ctx || !pq_ctx->hash_ctx) {
        return -1;
    }
    
    // Finalize transcript hash
    uint8_t transcript_hash[32];
    unsigned int hash_len = 32;
    
    // Create a copy of the hash context to preserve original
    EVP_MD_CTX *hash_copy = EVP_MD_CTX_new();
    if (!hash_copy || EVP_MD_CTX_copy_ex(hash_copy, pq_ctx->hash_ctx) != 1) {
        EVP_MD_CTX_free(hash_copy);
        return -1;
    }
    
    if (EVP_DigestFinal_ex(hash_copy, transcript_hash, &hash_len) != 1) {
        EVP_MD_CTX_free(hash_copy);
        return -1;
    }
    EVP_MD_CTX_free(hash_copy);
    
    // Derive session key using HKDF
    EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!hkdf_ctx) {
        return -1;
    }
    
    if (EVP_PKEY_derive_init(hkdf_ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, pq_ctx->shared_secret, 32) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, (uint8_t*)"StrongVPN-PQ-Session", 20) <= 0) {
        EVP_PKEY_CTX_free(hkdf_ctx);
        return -1;
    }
    
    size_t session_key_len = 32;
    if (EVP_PKEY_derive(hkdf_ctx, pq_ctx->session_key, &session_key_len) <= 0) {
        EVP_PKEY_CTX_free(hkdf_ctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(hkdf_ctx);
    
    LOG_INFO("Session keys derived successfully");
    return 0;
}

// Cleanup handshake context
void pq_handshake_cleanup(pq_handshake_ctx_t *ctx) {
    if (!ctx) return;
    
    // Free cryptographic contexts
    if (ctx->hash_ctx) {
        EVP_MD_CTX_free(ctx->hash_ctx);
    }
    
    // Free keypairs
    ml_dsa_keypair_free(&ctx->local_dsa_keypair);
    ml_kem_keypair_free(&ctx->local_kem_keypair);
    
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

// Clear session key securely
int pq_clear_session_key(pq_handshake_ctx_t *ctx) {
    if (!ctx) return -1;
    
    OPENSSL_cleanse(ctx->session_key, sizeof(ctx->session_key));
    OPENSSL_cleanse(ctx->mac_key, sizeof(ctx->mac_key));
    return 0;
}

// Check if handshake is complete
int pq_handshake_is_complete(const pq_handshake_ctx_t *ctx) {
    return ctx && ctx->state == PQ_STATE_ESTABLISHED;
}
