/*
 * StrongVPN Post-Quantum Authentication Implementation
 * Direct public key authentication using ML-DSA (no certificates)
 */

#include "pq_handshake.h"
#include "../network/tunnel.h"
#include "../crypto/ml_dsa.h"
#include "../common/logger.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// Authentication Message Processing (Direct Public Key Model)
// ============================================================================

int pq_send_authentication(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx) {
    if (!tunnel || !pq_ctx || pq_ctx->state != PQ_STATE_KEY_EXCHANGE_COMPLETE) {
        LOG_ERROR("Invalid parameters for authentication");
        return -1;
    }
    
    LOG_INFO("Generating authentication signature (direct public key model)");
    
    // Finalize transcript hash for authentication
    uint8_t transcript_hash[32];
    unsigned int hash_len;
    EVP_MD_CTX *temp_ctx = EVP_MD_CTX_new();
    if (!temp_ctx) {
        LOG_ERROR("Failed to create hash context");
        return -1;
    }
    
    // Copy current hash state and finalize
    if (EVP_MD_CTX_copy_ex(temp_ctx, pq_ctx->hash_ctx) != 1 ||
        EVP_DigestFinal_ex(temp_ctx, transcript_hash, &hash_len) != 1) {
        LOG_ERROR("Failed to finalize transcript hash");
        EVP_MD_CTX_free(temp_ctx);
        return -1;
    }
    EVP_MD_CTX_free(temp_ctx);
    
    // Generate ML-DSA signature over transcript hash (no certificate involved)
    uint8_t signature[ML_DSA_65_SIGNATURE_BYTES]; // 3309 bytes
    size_t sig_len;
    
    if (ml_dsa_sign(signature, &sig_len, transcript_hash, hash_len,
                    &pq_ctx->local_dsa_keypair) != 0) {
        LOG_ERROR("ML-DSA signature generation failed");
        return -1;
    }
    
    LOG_DEBUG("Generated ML-DSA signature: %zu bytes", sig_len);
    
    // Construct FINISHED message with direct signature
    size_t msg_len = sizeof(pq_message_t) + sig_len;
    uint8_t *buffer = malloc(msg_len);
    if (!buffer) {
        LOG_ERROR("Failed to allocate message buffer");
        return -1;
    }
    
    pq_message_t *msg = (pq_message_t *)buffer;
    msg->type = PQ_MSG_FINISHED;
    msg->length = htonl(sig_len);
    memcpy(msg->payload, signature, sig_len);
    
    // Update transcript hash with authentication message
    EVP_DigestUpdate(pq_ctx->hash_ctx, buffer, msg_len);
    
    // Send authentication message
    int result = tunnel_send(tunnel, buffer, msg_len);
    free(buffer);
    
    // Secure cleanup of signature
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(transcript_hash, sizeof(transcript_hash));
    
    if (result > 0) {
        pq_ctx->state = PQ_STATE_AUTHENTICATED;
        LOG_INFO("Authentication message sent successfully");
        return 0;
    }
    
    LOG_ERROR("Failed to send authentication message");
    return -1;
}

int pq_process_authentication(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx,
                             const uint8_t *data, size_t len) {
    if (!pq_ctx || !data || pq_ctx->state != PQ_STATE_KEY_EXCHANGE_COMPLETE) {
        LOG_ERROR("Invalid parameters for authentication processing");
        return -1;
    }
    
    const pq_message_t *msg = (const pq_message_t *)data;
    uint32_t payload_len = ntohl(msg->length);
    
    if (payload_len != ML_DSA_65_SIGNATURE_BYTES) {
        LOG_ERROR("Invalid signature length: %u (expected %d)", 
                 payload_len, ML_DSA_65_SIGNATURE_BYTES);
        return -1;
    }
    
    LOG_INFO("Verifying peer authentication (direct public key model)");
    
    // Compute transcript hash for verification
    uint8_t transcript_hash[32];
    unsigned int hash_len;
    EVP_MD_CTX *temp_ctx = EVP_MD_CTX_new();
    if (!temp_ctx) {
        LOG_ERROR("Failed to create hash context");
        return -1;
    }
    
    // Copy current hash state and finalize (before this message)
    if (EVP_MD_CTX_copy_ex(temp_ctx, pq_ctx->hash_ctx) != 1 ||
        EVP_DigestFinal_ex(temp_ctx, transcript_hash, &hash_len) != 1) {
        LOG_ERROR("Failed to compute transcript hash");
        EVP_MD_CTX_free(temp_ctx);
        return -1;
    }
    EVP_MD_CTX_free(temp_ctx);
    
    // Verify ML-DSA signature using directly exchanged public key
    if (ml_dsa_verify(msg->payload, payload_len, transcript_hash, hash_len,
                      pq_ctx->peer_dsa_pubkey) != 0) {
        LOG_ERROR("ML-DSA signature verification failed");
        return -1;
    }
    
    LOG_INFO("Peer authentication successful (direct public key verification)");
    
    // Update transcript hash with received authentication message
    EVP_DigestUpdate(pq_ctx->hash_ctx, data, len);
    
    pq_ctx->state = PQ_STATE_AUTHENTICATED;
    
    // If we're the server and just verified client auth, send our auth
    if (pq_ctx->is_server) {
        LOG_INFO("Sending server authentication response");
        if (pq_send_authentication(tunnel, pq_ctx) != 0) {
            LOG_ERROR("Failed to send server authentication");
            return -1;
        }
    }
    
    // Derive session keys after successful mutual authentication
    if (derive_session_keys(pq_ctx) != 0) {
        LOG_ERROR("Failed to derive session keys");
        return -1;
    }
    
    LOG_INFO("Mutual authentication completed - session keys derived");
    return 0;
}

// ============================================================================
// Complete Handshake Orchestration
// ============================================================================

int pq_complete_handshake_client(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx) {
    if (!tunnel || !pq_ctx) return -1;
    
    LOG_INFO("Starting client-side post-quantum handshake");
    
    // Step 1: Send Client Hello
    if (pq_send_client_hello(tunnel, pq_ctx) != 0) {
        LOG_ERROR("Failed to send Client Hello");
        return -1;
    }
    
    // Step 2: Process Server Hello + Key Exchange
    uint8_t buffer[8192]; // Large buffer for post-quantum messages
    int received = tunnel_recv(tunnel, buffer, sizeof(buffer));
    if (received <= 0) {
        LOG_ERROR("Failed to receive Server Hello");
        return -1;
    }
    
    if (pq_process_server_hello(tunnel, pq_ctx, buffer, received) != 0) {
        LOG_ERROR("Failed to process Server Hello");
        return -1;
    }
    
    // Step 3: Send Client Authentication
    if (pq_send_authentication(tunnel, pq_ctx) != 0) {
        LOG_ERROR("Failed to send client authentication");
        return -1;
    }
    
    // Step 4: Process Server Authentication
    received = tunnel_recv(tunnel, buffer, sizeof(buffer));
    if (received <= 0) {
        LOG_ERROR("Failed to receive server authentication");
        return -1;
    }
    
    if (pq_process_authentication(tunnel, pq_ctx, buffer, received) != 0) {
        LOG_ERROR("Failed to process server authentication");
        return -1;
    }
    
    LOG_INFO("Client handshake completed successfully");
    return 0;
}

int pq_complete_handshake_server(tunnel_ctx_t *tunnel, pq_handshake_ctx_t *pq_ctx) {
    if (!tunnel || !pq_ctx) return -1;
    
    LOG_INFO("Starting server-side post-quantum handshake");
    
    uint8_t buffer[8192]; // Large buffer for post-quantum messages
    
    // Step 1: Process Client Hello
    int received = tunnel_recv(tunnel, buffer, sizeof(buffer));
    if (received <= 0) {
        LOG_ERROR("Failed to receive Client Hello");
        return -1;
    }
    
    if (pq_process_client_hello(tunnel, pq_ctx, buffer, received) != 0) {
        LOG_ERROR("Failed to process Client Hello");
        return -1;
    }
    
    // Step 2: Process Client Authentication
    received = tunnel_recv(tunnel, buffer, sizeof(buffer));
    if (received <= 0) {
        LOG_ERROR("Failed to receive client authentication");
        return -1;
    }
    
    if (pq_process_authentication(tunnel, pq_ctx, buffer, received) != 0) {
        LOG_ERROR("Failed to process client authentication");
        return -1;
    }
    
    LOG_INFO("Server handshake completed successfully");
    return 0;
}

// ============================================================================
// Trust Management (Direct Public Key Model)
// ============================================================================

int pq_validate_peer_pubkey(const uint8_t *pubkey, size_t pubkey_len, int algorithm) {
    if (!pubkey) return -1;
    
    // Validate ML-DSA public key format
    if (algorithm == ML_DSA_65) {
        if (pubkey_len != ML_DSA_65_PUBKEY_BYTES) {
            LOG_ERROR("Invalid ML-DSA public key length: %zu", pubkey_len);
            return -1;
        }
        
        // Additional FIPS 204 validation could be added here
        // For now, basic length validation suffices
        LOG_DEBUG("ML-DSA public key validation passed");
        return 0;
    }
    
    // Validate ML-KEM public key format
    if (algorithm == ML_KEM_768) {
        if (pubkey_len != ML_KEM_768_PUBKEY_BYTES) {
            LOG_ERROR("Invalid ML-KEM public key length: %zu", pubkey_len);
            return -1;
        }
        
        // Additional FIPS 203 validation could be added here
        LOG_DEBUG("ML-KEM public key validation passed");
        return 0;
    }
    
    LOG_ERROR("Unknown algorithm for public key validation");
    return -1;
}

// Store peer public key (Trust-On-First-Use model)
int pq_store_peer_pubkey(pq_handshake_ctx_t *pq_ctx, 
                        const uint8_t *dsa_pubkey, 
                        const uint8_t *kem_pubkey) {
    if (!pq_ctx || !dsa_pubkey || !kem_pubkey) return -1;
    
    // Validate public key formats
    if (pq_validate_peer_pubkey(dsa_pubkey, ML_DSA_65_PUBKEY_BYTES, ML_DSA_65) != 0 ||
        pq_validate_peer_pubkey(kem_pubkey, ML_KEM_768_PUBKEY_BYTES, ML_KEM_768) != 0) {
        return -1;
    }
    
    // Store peer public keys for direct authentication
    memcpy(pq_ctx->peer_dsa_pubkey, dsa_pubkey, ML_DSA_65_PUBKEY_BYTES);
    memcpy(pq_ctx->peer_kem_pubkey, kem_pubkey, ML_KEM_768_PUBKEY_BYTES);
    
    LOG_INFO("Peer public keys stored (direct trust model)");
    return 0;
}
