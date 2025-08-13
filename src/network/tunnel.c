/*
 * StrongVPN Network Transport Layer Implementation
 * TCP socket implementation for post-quantum handshake messages
 */

#include "tunnel.h"
#include "../common/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

// ============================================================================
// Network Transport Implementation
// ============================================================================

int tunnel_send(tunnel_ctx_t *tunnel, const uint8_t *data, size_t len) {
    if (!tunnel || !data || tunnel->socket_fd < 0) {
        LOG_ERROR("Invalid tunnel parameters for send");
        return -1;
    }
    
    LOG_DEBUG("Sending %zu bytes over tunnel", len);
    
    // Handle large post-quantum messages (up to 3309 bytes for ML-DSA signatures)
    ssize_t total_sent = 0;
    while ((size_t)total_sent < len) {
        ssize_t sent = send(tunnel->socket_fd, data + total_sent, 
                           len - total_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue; // Retry for non-blocking sockets
            }
            LOG_ERROR("Network send failed: %s", strerror(errno));
            return -1;
        }
        total_sent += sent;
    }
    
    LOG_DEBUG("Successfully sent %zu bytes", total_sent);
    return total_sent;
}

int tunnel_recv(tunnel_ctx_t *tunnel, uint8_t *buffer, size_t max_len) {
    if (!tunnel || !buffer || tunnel->socket_fd < 0) {
        LOG_ERROR("Invalid tunnel parameters for recv");
        return -1;
    }
    
    // First, receive message header to determine payload size
    pq_message_t header;
    ssize_t received = recv(tunnel->socket_fd, &header, sizeof(header), MSG_WAITALL);
    if (received != sizeof(header)) {
        if (received == 0) {
            LOG_INFO("Connection closed by peer");
        } else {
            LOG_ERROR("Failed to receive message header: %s", strerror(errno));
        }
        return -1;
    }
    
    // Convert network byte order to host byte order
    uint32_t payload_len = ntohl(header.length);
    size_t total_len = sizeof(header) + payload_len;
    
    if (total_len > max_len) {
        LOG_ERROR("Message too large: %zu bytes (max %zu)", total_len, max_len);
        return -1;
    }
    
    // Copy header to buffer
    memcpy(buffer, &header, sizeof(header));
    
    // Receive payload if present
    if (payload_len > 0) {
        received = recv(tunnel->socket_fd, buffer + sizeof(header), 
                       payload_len, MSG_WAITALL);
        if (received != payload_len) {
            LOG_ERROR("Failed to receive complete payload: expected %u, got %zd", 
                     payload_len, received);
            return -1;
        }
    }
    
    LOG_DEBUG("Received %zu bytes from tunnel", total_len);
    return total_len;
}

// ============================================================================
// Server Socket Operations
// ============================================================================

int tunnel_server_init(tunnel_ctx_t *tunnel, uint16_t port) {
    if (!tunnel) return -1;
    
    memset(tunnel, 0, sizeof(tunnel_ctx_t));
    
    // Create TCP socket
    tunnel->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel->socket_fd < 0) {
        LOG_ERROR("Failed to create server socket: %s", strerror(errno));
        return -1;
    }
    
    // Enable address reuse
    int opt = 1;
    if (setsockopt(tunnel->socket_fd, SOL_SOCKET, SO_REUSEADDR, 
                   &opt, sizeof(opt)) < 0) {
        LOG_WARN("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    // Configure server address (for EVE-NG: 10.1.1.20)
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(port);
    
    // Bind socket
    if (bind(tunnel->socket_fd, (struct sockaddr*)&server_addr, 
             sizeof(server_addr)) < 0) {
        LOG_ERROR("Failed to bind server socket: %s", strerror(errno));
        close(tunnel->socket_fd);
        return -1;
    }
    
    // Listen for connections
    if (listen(tunnel->socket_fd, 1) < 0) {
        LOG_ERROR("Failed to listen on server socket: %s", strerror(errno));
        close(tunnel->socket_fd);
        return -1;
    }
    
    tunnel->is_server = 1;
    LOG_INFO("Server listening on port %u", port);
    return 0;
}

int tunnel_server_accept(tunnel_ctx_t *tunnel) {
    if (!tunnel || !tunnel->is_server) return -1;
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    LOG_INFO("Waiting for client connection...");
    int client_fd = accept(tunnel->socket_fd, (struct sockaddr*)&client_addr, &client_len);
    
    if (client_fd < 0) {
        LOG_ERROR("Failed to accept client connection: %s", strerror(errno));
        return -1;
    }
    
    // Store client information and connection
    tunnel->peer_addr = client_addr;
    // Keep listening socket for future connections, use client socket for communication
    tunnel->socket_fd = client_fd; // Use client connection for handshake
    
    LOG_INFO("Client connected from %s:%u", 
             inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    return 0;
}

// ============================================================================
// Client Socket Operations  
// ============================================================================

int tunnel_client_init(tunnel_ctx_t *tunnel, const char *server_ip, uint16_t port) {
    if (!tunnel || !server_ip) return -1;
    
    memset(tunnel, 0, sizeof(tunnel_ctx_t));
    
    // Create TCP socket
    tunnel->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel->socket_fd < 0) {
        LOG_ERROR("Failed to create client socket: %s", strerror(errno));
        return -1;
    }
    
    // Configure server address (for EVE-NG: 10.1.1.20:8443)
    tunnel->peer_addr.sin_family = AF_INET;
    tunnel->peer_addr.sin_port = htons(port);
    
    if (inet_aton(server_ip, &tunnel->peer_addr.sin_addr) == 0) {
        LOG_ERROR("Invalid server IP address: %s", server_ip);
        close(tunnel->socket_fd);
        return -1;
    }
    
    // Connect to server
    LOG_INFO("Connecting to server %s:%u", server_ip, port);
    if (connect(tunnel->socket_fd, (struct sockaddr*)&tunnel->peer_addr,
                sizeof(tunnel->peer_addr)) < 0) {
        LOG_ERROR("Failed to connect to server: %s", strerror(errno));
        close(tunnel->socket_fd);
        return -1;
    }
    
    tunnel->is_server = 0;
    LOG_INFO("Connected to server successfully");
    return 0;
}

// ============================================================================
// Cleanup Operations
// ============================================================================

void tunnel_cleanup(tunnel_ctx_t *tunnel) {
    if (!tunnel) return;
    
    if (tunnel->socket_fd >= 0) {
        close(tunnel->socket_fd);
        tunnel->socket_fd = -1;
    }
    
    memset(tunnel, 0, sizeof(tunnel_ctx_t));
    LOG_DEBUG("Tunnel cleanup completed");
}
