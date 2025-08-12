/*
 * StrongVPN Network Transport Layer Header
 * TCP socket interface for post-quantum handshake messages
 */

#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

// ============================================================================
// Message Format Definitions
// ============================================================================

typedef struct {
    uint8_t type;           // Message type identifier
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

// ============================================================================
// Network Context Structure
// ============================================================================

typedef struct {
    int socket_fd;                    // TCP socket file descriptor
    struct sockaddr_in peer_addr;     // Peer address information
    int is_server;                    // Server (1) or client (0) role
} tunnel_ctx_t;

// ============================================================================
// Function Declarations
// ============================================================================

// Core transport functions
int tunnel_send(tunnel_ctx_t *tunnel, const uint8_t *data, size_t len);
int tunnel_recv(tunnel_ctx_t *tunnel, uint8_t *buffer, size_t max_len);

// Server operations
int tunnel_server_init(tunnel_ctx_t *tunnel, uint16_t port);
int tunnel_server_accept(tunnel_ctx_t *tunnel);

// Client operations
int tunnel_client_init(tunnel_ctx_t *tunnel, const char *server_ip, uint16_t port);

// Cleanup
void tunnel_cleanup(tunnel_ctx_t *tunnel);

#endif // TUNNEL_H
