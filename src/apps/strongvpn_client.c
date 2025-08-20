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
#include <signal.h>

// Graceful shutdown flag and handler
static volatile int g_running = 1;
static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

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
    
    // Setup signals for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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

        // Continuous send/receive loop: send initial 5000B, then a few varied sizes
        uint8_t echo_buf[9000];

        for (int iter = 0; iter < 4 && g_running; ++iter) {
            size_t send_len;
            if (iter == 0) {
                send_len = 5000; // large payload to exercise fragmentation
            } else if (iter == 1) {
                send_len = 100; // small
            } else if (iter == 2) {
                send_len = 2800; // multi-fragment but smaller
            } else {
                send_len = 1400; // exactly one fragment size
            }

            uint8_t *test_buf = (uint8_t*)malloc(send_len);
            if (!test_buf) {
                LOG_ERROR("Allocation failed for test buffer");
                break;
            }
            for (size_t i = 0; i < send_len; ++i) test_buf[i] = (uint8_t)((i + iter) & 0xFF);

            if (!g_running) { free(test_buf); break; }
            if (tunnel_send_data(&tunnel, test_buf, send_len) < 0) {
                LOG_ERROR("Failed to send test data (len=%zu)", send_len);
                free(test_buf);
                break;
            }
            LOG_INFO("Sent %zu bytes test payload (iter %d); waiting for echo", send_len, iter);

            if (!g_running) { free(test_buf); break; }
            int got = tunnel_recv_data(&tunnel, echo_buf, sizeof(echo_buf), 10000);
            if (got == (int)send_len && memcmp(test_buf, echo_buf, send_len) == 0) {
                LOG_INFO("Echo verification successful: %d bytes match (iter %d)", got, iter);
            } else if (got > 0) {
                LOG_WARN("Echo received %d bytes but content/size mismatch (expected %zu) (iter %d)", got, send_len, iter);
            } else {
                if (!g_running) {
                    LOG_INFO("Shutdown requested - exiting client loop");
                } else {
                    LOG_WARN("No echo received within timeout or error (iter %d)", iter);
                }
                free(test_buf);
                break;
            }
            free(test_buf);
        }
        
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
