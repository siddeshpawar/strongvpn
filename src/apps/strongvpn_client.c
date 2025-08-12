/*
 * StrongVPN Post-Quantum Client Application
 * Complete client implementation for EVE-NG testing
 */

#include "../vpn/pq_handshake.h"
#include "../vpn/pq_auth.h"
#include "../network/tunnel.h"
#include "../common/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    const char *server_ip = "10.1.1.20"; // Default EVE-NG server IP
    uint16_t port = 8443; // Default StrongVPN port
    
    // Parse command line arguments
    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        port = (uint16_t)atoi(argv[2]);
        if (port == 0) {
            fprintf(stderr, "Usage: %s [server_ip] [port]\n", argv[0]);
            return -1;
        }
    }
    
    // Initialize logging system
    log_init(LOG_LEVEL_INFO);
    LOG_INFO("StrongVPN Post-Quantum Client v1.0");
    LOG_INFO("Pure post-quantum VPN using ML-DSA-65 + ML-KEM-768");
    LOG_INFO("Target server: %s:%u", server_ip, port);
    
    // Initialize tunnel context and connect to server
    tunnel_ctx_t tunnel;
    if (tunnel_client_init(&tunnel, server_ip, port) != 0) {
        LOG_ERROR("Failed to connect to server %s:%u", server_ip, port);
        return -1;
    }
    
    LOG_INFO("TCP connection established to server");
    
    // Initialize post-quantum handshake context
    pq_handshake_ctx_t pq_ctx;
    if (pq_handshake_init(&pq_ctx, 0) != 0) { // is_server = 0
        LOG_ERROR("Failed to initialize PQ handshake context");
        tunnel_cleanup(&tunnel);
        return -1;
    }
    
    LOG_INFO("Generated ephemeral ML-DSA-65 key pair (1952 byte public key)");
    LOG_INFO("Generated ephemeral ML-KEM-768 key pair (1184 byte public key)");
    LOG_INFO("Starting pure post-quantum handshake...");
    
    // Complete client-side handshake
    if (pq_complete_handshake_client(&tunnel, &pq_ctx) == 0) {
        LOG_INFO("=== POST-QUANTUM HANDSHAKE SUCCESSFUL ===");
        LOG_INFO("Pure post-quantum VPN tunnel established");
        LOG_INFO("Authentication: Direct ML-DSA public key verification");
        LOG_INFO("Key Exchange: ML-KEM-768 encapsulation completed");
        LOG_INFO("Session Keys: HKDF-derived from ML-KEM shared secret");
        
        // Display session key for verification (first 16 bytes)
        uint8_t session_key[32];
        if (pq_get_session_key(&pq_ctx, session_key, 32) == 0) {
            LOG_INFO("Session key established (first 16 bytes): %02x%02x%02x%02x...",
                    session_key[0], session_key[1], session_key[2], session_key[3]);
        }
        
        LOG_INFO("VPN tunnel ready for data transmission");
        LOG_INFO("Handshake completed using pure post-quantum cryptography");
        
    } else {
        LOG_ERROR("Post-quantum handshake failed");
        pq_handshake_cleanup(&pq_ctx);
        tunnel_cleanup(&tunnel);
        return -1;
    }
    
    // Cleanup
    pq_handshake_cleanup(&pq_ctx);
    tunnel_cleanup(&tunnel);
    
    LOG_INFO("StrongVPN client session completed");
    return 0;
}
