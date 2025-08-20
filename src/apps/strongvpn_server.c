/*
 * StrongVPN Post-Quantum Server Application
 * Complete server implementation for EVE-NG testing
 */

#include "../vpn/pq_handshake.h"
#include "../vpn/pq_auth.h"
#include "../network/tunnel.h"
#include "../common/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// Global variables for signal handling
static tunnel_ctx_t g_tunnel;
static pq_handshake_ctx_t g_pq_ctx;
static volatile int g_running = 1;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    LOG_INFO("Received signal %d, shutting down...", sig);
    g_running = 0;
}

int main(int argc, char *argv[]) {
    uint16_t port = 8443; // Default StrongVPN port
    
    // Parse command line arguments
    if (argc == 2) {
        // Single argument: port number
        port = (uint16_t)atoi(argv[1]);
        if (port == 0) {
            fprintf(stderr, "Usage: %s [port] or %s [ip] [port]\n", argv[0], argv[0]);
            return -1;
        }
    } else if (argc == 3) {
        // Two arguments: IP address and port
        // For now, ignore IP (server binds to INADDR_ANY anyway)
        port = (uint16_t)atoi(argv[2]);
        if (port == 0) {
            fprintf(stderr, "Usage: %s [port] or %s [ip] [port]\n", argv[0], argv[0]);
            return -1;
        }
    } else if (argc > 3) {
        fprintf(stderr, "Usage: %s [port] or %s [ip] [port]\n", argv[0], argv[0]);
        return -1;
    }
    
    // Initialize logging system
    log_init(LOG_LEVEL_INFO);
    LOG_INFO("StrongVPN Post-Quantum Server v1.0");
    LOG_INFO("Pure post-quantum VPN using ML-DSA-65 + ML-KEM-768");
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize server tunnel
    if (tunnel_server_init(&g_tunnel, port) != 0) {
        LOG_ERROR("Failed to initialize server tunnel on port %u", port);
        return -1;
    }
    
    LOG_INFO("Server listening on port %u (EVE-NG: 10.1.1.20:%u)", port, port);
    LOG_INFO("Waiting for post-quantum VPN clients...");
    
    while (g_running) {
        // Accept client connection
        if (tunnel_server_accept(&g_tunnel) != 0) {
            if (g_running) {
                LOG_ERROR("Failed to accept client connection - retrying in 2 seconds");
                sleep(2); // Prevent log flooding
            }
            continue;
        }
        
        LOG_INFO("Client connected - starting post-quantum handshake");
        
        // Initialize post-quantum handshake context
        if (pq_handshake_init(&g_pq_ctx, 1) != 0) { // is_server = 1
            LOG_ERROR("Failed to initialize PQ handshake context");
            continue;
        }
        
        LOG_INFO("Generated ephemeral ML-DSA-65 key pair (1952 byte public key)");
        LOG_INFO("Generated ephemeral ML-KEM-768 key pair (1184 byte public key)");
        
        // Complete server-side handshake
        if (pq_complete_handshake_server(&g_tunnel, &g_pq_ctx) == 0) {
            LOG_INFO("=== POST-QUANTUM HANDSHAKE SUCCESSFUL ===");
            LOG_INFO("Pure post-quantum VPN tunnel established");
            LOG_INFO("Authentication: Direct ML-DSA public key model");
            LOG_INFO("Key Exchange: ML-KEM-768 encapsulation");
            LOG_INFO("Session Keys: HKDF-derived from ML-KEM shared secret");
            
            // Display session key for verification (first 16 bytes)
            uint8_t session_key[32];
            if (pq_get_session_key(&g_pq_ctx, session_key, 32) == 0) {
                LOG_INFO("Session key established (first 16 bytes): %02x%02x%02x%02x...",
                        session_key[0], session_key[1], session_key[2], session_key[3]);
            }
            
            // Keep connection alive for testing
            LOG_INFO("VPN tunnel ready for data transmission");

            // Continuous receive/echo loop to support multiple messages per connection
            uint8_t app_buf[8192];
            while (g_running) {
                int got = tunnel_recv_data(&g_tunnel, app_buf, sizeof(app_buf), 10000);
                if (got > 0) {
                    LOG_INFO("Received application data: %d bytes - echoing back", got);
                    if (tunnel_send_data(&g_tunnel, app_buf, (size_t)got) < 0) {
                        LOG_ERROR("Failed to echo data back to client");
                        break;
                    }
                } else {
                    LOG_INFO("Client done or recv timeout/error - closing connection");
                    break;
                }
            }
            
        } else {
            LOG_ERROR("Post-quantum handshake failed");
        }
        
        // Cleanup handshake context
        pq_handshake_cleanup(&g_pq_ctx);
        LOG_INFO("Client disconnected - ready for next connection");
    }
    
    // Cleanup
    tunnel_cleanup(&g_tunnel);
    LOG_INFO("StrongVPN server shutdown complete");
    
    return 0;
}
