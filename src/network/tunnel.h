/*
 * StrongVPN Network Transport Layer Header
 * TCP socket interface for post-quantum handshake messages
 */

#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
 #include <time.h>

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

// Data transfer (post-handshake)
#define PQ_MSG_DATA            0x10

// Fragmentation parameters
#define TUNNEL_FRAGMENT_SIZE   1400u   // network-friendly MTU-sized fragments

// Data fragment payload layout carried inside pq_message_t when type == PQ_MSG_DATA
typedef struct {
    uint32_t total_len;   // total application data length (network byte order)
    uint32_t offset;      // fragment offset from start (network byte order)
    uint32_t chunk_len;   // length of this fragment (network byte order)
    uint8_t  data[];      // fragment bytes
} __attribute__((packed)) pq_data_fragment_t;

// ============================================================================
// Network Context Structure
// ============================================================================

typedef struct {
    int socket_fd;                    // TCP socket file descriptor
    struct sockaddr_in peer_addr;     // Peer address information
    int is_server;                    // Server (1) or client (0) role
    // Reassembly context (per-connection)
    uint8_t *reassembly_buf;          // buffer for assembling a full message
    size_t   reassembly_size;         // expected total size
    size_t   reassembly_received;     // bytes received so far
    struct timespec reassembly_ts;    // last update time
    // Fragment tracking for duplicate/out-of-order handling
    uint8_t *frag_bitmap;             // one bit per fragment
    size_t   frag_count;              // total number of fragments expected
    size_t   frags_received;          // number of distinct fragments received
} tunnel_ctx_t;

// ============================================================================
// Function Declarations
// ============================================================================

// Core transport functions
int tunnel_send(tunnel_ctx_t *tunnel, const uint8_t *data, size_t len);
int tunnel_recv(tunnel_ctx_t *tunnel, uint8_t *buffer, size_t max_len);

// Fragmentation-aware data transfer (post-handshake data channel)
int tunnel_send_data(tunnel_ctx_t *tunnel, const uint8_t *data, size_t len);
// Receives and reassembles into 'buffer' up to max_len. Timeout in milliseconds for full message.
int tunnel_recv_data(tunnel_ctx_t *tunnel, uint8_t *buffer, size_t max_len, int timeout_ms);

// Server operations
int tunnel_server_init(tunnel_ctx_t *tunnel, uint16_t port);
int tunnel_server_accept(tunnel_ctx_t *tunnel);

// Client operations
int tunnel_client_init(tunnel_ctx_t *tunnel, const char *server_ip, uint16_t port);

// Cleanup
void tunnel_cleanup(tunnel_ctx_t *tunnel);

#endif // TUNNEL_H
