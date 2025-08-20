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
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>

#ifndef MSG_WAITALL
#define MSG_WAITALL 0x100
#endif

// set a socket to non-blocking mode
static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

// read exactly len bytes with retry/backoff and optional timeout (ms). If timeout_ms < 0, wait indefinitely.
static ssize_t read_exact_retry(int fd, uint8_t *buf, size_t len, int timeout_ms) {
    size_t off = 0;
    struct timespec start, now;
    if (timeout_ms >= 0) clock_gettime(CLOCK_MONOTONIC, &start);
    int backoff_ms = 1;
    const int backoff_max = 50;
    while (off < len) {
        ssize_t r = recv(fd, buf + off, len - off, 0);
        if (r > 0) {
            off += (size_t)r;
            backoff_ms = 1; // reset after progress
            continue;
        } else if (r == 0) {
            // peer closed
            return 0;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (timeout_ms >= 0) {
                clock_gettime(CLOCK_MONOTONIC, &now);
                long elapsed = (now.tv_sec - start.tv_sec) * 1000L + (now.tv_nsec - start.tv_nsec) / 1000000L;
                if (elapsed >= timeout_ms) return -1;
            }
            struct timespec ts = { .tv_sec = 0, .tv_nsec = backoff_ms * 1000000L };
            nanosleep(&ts, NULL);
            if (backoff_ms < backoff_max) backoff_ms *= 2;
            continue;
        }
        return -1; // other error
    }
    return (ssize_t)off;
}

// ============================================================================
// Network Transport Implementation
// ============================================================================

static void reassembly_reset(tunnel_ctx_t *t) {
    if (t->reassembly_buf) {
        free(t->reassembly_buf);
        t->reassembly_buf = NULL;
    }
    if (t->frag_bitmap) {
        free(t->frag_bitmap);
        t->frag_bitmap = NULL;
    }
    t->reassembly_size = 0;
    t->reassembly_received = 0;
    t->reassembly_ts = (struct timespec){0};
    t->frag_count = 0;
    t->frags_received = 0;
}

// internal variant with timeout for use by data-plane
static int tunnel_recv_with_timeout(tunnel_ctx_t *tunnel, uint8_t *buffer, size_t max_len, int timeout_ms) {
    if (!tunnel || !buffer || tunnel->socket_fd < 0) {
        LOG_ERROR("Invalid tunnel parameters for recv");
        return -1;
    }
    
    // First, receive message header to determine payload size
    pq_message_t header;
    ssize_t received = read_exact_retry(tunnel->socket_fd, (uint8_t*)&header, sizeof(header), timeout_ms);
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
        received = read_exact_retry(tunnel->socket_fd, buffer + sizeof(header), payload_len, timeout_ms);
        if (received != (ssize_t)payload_len) {
            LOG_ERROR("Failed to receive complete payload: expected %u, got %zd", 
                     payload_len, received);
            return -1;
        }
    }
    
    LOG_DEBUG("Received %zu bytes from tunnel", total_len);
    return total_len;
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
        received = recv(tunnel->socket_fd, buffer + sizeof(header), payload_len, MSG_WAITALL);
        if (received != (ssize_t)payload_len) {
            LOG_ERROR("Failed to receive complete payload: expected %u, got %zd", 
                     payload_len, received);
            return -1;
        }
    }
    
    LOG_DEBUG("Received %zu bytes from tunnel", total_len);
    return total_len;
}

// Receive and reassemble a full PQ_MSG_DATA message
int tunnel_recv_data(tunnel_ctx_t *tunnel, uint8_t *buffer, size_t max_len, int timeout_ms) {
    if (!tunnel || !buffer) {
        LOG_ERROR("Invalid parameters to tunnel_recv_data");
        return -1;
    }

    const int timeout_total_ms = (timeout_ms > 0) ? timeout_ms : 5000;
    struct timespec start_ts; clock_gettime(CLOCK_MONOTONIC, &start_ts);

    // temp buffer for incoming frames
    size_t temp_max = sizeof(pq_message_t) + sizeof(pq_data_fragment_t) + TUNNEL_FRAGMENT_SIZE;
    uint8_t *temp = (uint8_t*)malloc(temp_max);
    if (!temp) return -1;

    for (;;) {
        // consume next frame with remaining timeout budget per iteration
        int n = tunnel_recv_with_timeout(tunnel, temp, temp_max, timeout_total_ms);
        if (n < 0) { free(temp); return -1; }

        if ((size_t)n < sizeof(pq_message_t)) { free(temp); return -1; }
        pq_message_t *hdr = (pq_message_t*)temp;
        if (hdr->type != PQ_MSG_DATA) {
            LOG_WARN("Unexpected message type 0x%02x in data channel", hdr->type);
            free(temp);
            return -1;
        }

        uint32_t payload_len = ntohl(hdr->length);
        if (sizeof(pq_message_t) + payload_len != (size_t)n) {
            LOG_ERROR("Malformed data frame length");
            free(temp);
            return -1;
        }

        pq_data_fragment_t *frag = (pq_data_fragment_t*)hdr->payload;
        size_t total_len = (size_t)ntohl(frag->total_len);
        size_t offset = (size_t)ntohl(frag->offset);
        size_t chunk_len = (size_t)ntohl(frag->chunk_len);

        if (sizeof(pq_data_fragment_t) + chunk_len != payload_len) {
            LOG_ERROR("Inconsistent fragment sizes");
            free(temp);
            return -1;
        }

        // Initialize or validate reassembly state
        if (!tunnel->reassembly_buf) {
            if (total_len > max_len) {
                LOG_ERROR("Incoming message too large: %zu > %zu", total_len, max_len);
                free(temp);
                return -1;
            }
            tunnel->reassembly_buf = (uint8_t*)malloc(total_len);
            if (!tunnel->reassembly_buf) { free(temp); return -1; }
            tunnel->reassembly_size = total_len;
            tunnel->reassembly_received = 0;
            // compute fragment count and allocate bitmap
            tunnel->frag_count = (total_len + TUNNEL_FRAGMENT_SIZE - 1) / TUNNEL_FRAGMENT_SIZE;
            size_t bitmap_bytes = (tunnel->frag_count + 7) / 8;
            tunnel->frag_bitmap = (uint8_t*)calloc(1, bitmap_bytes);
            tunnel->frags_received = 0;
        } else if (tunnel->reassembly_size != total_len) {
            LOG_WARN("Total length changed mid-reassembly; resetting");
            reassembly_reset(tunnel);
            continue;
        }

        if (offset + chunk_len > tunnel->reassembly_size) {
            LOG_ERROR("Fragment exceeds bounds");
            reassembly_reset(tunnel);
            free(temp);
            return -1;
        }

        // determine fragment index and check duplicates
        size_t frag_idx = offset / TUNNEL_FRAGMENT_SIZE;
        int bit = (tunnel->frag_bitmap[frag_idx / 8] >> (frag_idx % 8)) & 1;
        if (!bit) {
            memcpy(tunnel->reassembly_buf + offset, frag->data, chunk_len);
            tunnel->reassembly_received += chunk_len;
            tunnel->frag_bitmap[frag_idx / 8] |= (uint8_t)(1u << (frag_idx % 8));
            tunnel->frags_received++;
        } else {
            // duplicate fragment: ignore
        }
        clock_gettime(CLOCK_MONOTONIC, &tunnel->reassembly_ts);

        if (tunnel->frags_received >= tunnel->frag_count) {
            // complete
            memcpy(buffer, tunnel->reassembly_buf, tunnel->reassembly_size);
            int out = (int)tunnel->reassembly_size;
            reassembly_reset(tunnel);
            free(temp);
            return out;
        }

        // check timeout
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - start_ts.tv_sec) * 1000L + (now.tv_nsec - start_ts.tv_nsec) / 1000000L;
        if (elapsed_ms > timeout_total_ms) {
            LOG_ERROR("Reassembly timed out after %ld ms", elapsed_ms);
            reassembly_reset(tunnel);
            free(temp);
            return -1;
        }
    }
}

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

// Fragmentation-aware data sender: splits payload into PQ_MSG_DATA fragments
int tunnel_send_data(tunnel_ctx_t *tunnel, const uint8_t *data, size_t len) {
    if (!tunnel || !data) {
        LOG_ERROR("Invalid parameters to tunnel_send_data");
        return -1;
    }

    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > TUNNEL_FRAGMENT_SIZE) chunk = TUNNEL_FRAGMENT_SIZE;

        // Build message: pq_message_t header + pq_data_fragment_t + data
        size_t frag_header_len = sizeof(pq_data_fragment_t);
        size_t payload_len = frag_header_len + chunk;
        size_t msg_len = sizeof(pq_message_t) + payload_len;

        uint8_t *msg = (uint8_t*)malloc(msg_len);
        if (!msg) {
            LOG_ERROR("Allocation failed in tunnel_send_data");
            return -1;
        }

        pq_message_t *hdr = (pq_message_t*)msg;
        hdr->type = PQ_MSG_DATA;
        hdr->length = htonl((uint32_t)payload_len);

        pq_data_fragment_t *frag = (pq_data_fragment_t*)hdr->payload;
        frag->total_len = htonl((uint32_t)len);
        frag->offset = htonl((uint32_t)offset);
        frag->chunk_len = htonl((uint32_t)chunk);
        memcpy(frag->data, data + offset, chunk);

        int rc = tunnel_send(tunnel, msg, msg_len);
        free(msg);
        if (rc < 0) return -1;

        offset += chunk;
    }
    return (int)len;
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
    set_nonblocking(tunnel->socket_fd);
    
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
    set_nonblocking(tunnel->socket_fd);
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
    // free reassembly buffer if any
    if (tunnel->reassembly_buf) {
        free(tunnel->reassembly_buf);
        tunnel->reassembly_buf = NULL;
    }
    if (tunnel->frag_bitmap) {
        free(tunnel->frag_bitmap);
        tunnel->frag_bitmap = NULL;
    }
    
    memset(tunnel, 0, sizeof(tunnel_ctx_t));
    LOG_DEBUG("Tunnel cleanup completed");
}
