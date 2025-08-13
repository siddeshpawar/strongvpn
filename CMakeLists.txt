cmake_minimum_required(VERSION 3.16)
project(StrongVPN VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

# Find liboqs
pkg_check_modules(LIBOQS REQUIRED liboqs)

# Include directories
include_directories(${LIBOQS_INCLUDE_DIRS})
include_directories(src)

# Compiler flags for optimization and security
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -march=native")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Source files
set(STRONGVPN_SOURCES
    src/crypto/pq_core.c
    src/vpn/pq_handshake.c
    src/vpn/pq_auth.c
    src/network/tunnel.c
    src/common/logger.c
)

# Server executable
add_executable(strongvpn_server
    src/apps/strongvpn_server.c
    ${STRONGVPN_SOURCES}
)

# Client executable
add_executable(strongvpn_client
    src/apps/strongvpn_client.c
    ${STRONGVPN_SOURCES}
)

# Link libraries
target_link_libraries(strongvpn_server 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${LIBOQS_LIBRARIES}
    m  # Math library
)

target_link_libraries(strongvpn_client 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${LIBOQS_LIBRARIES}
    m  # Math library
)

# Compiler flags for liboqs
target_compile_options(strongvpn_server PRIVATE ${LIBOQS_CFLAGS_OTHER})
target_compile_options(strongvpn_client PRIVATE ${LIBOQS_CFLAGS_OTHER})

# Set output directory
set_target_properties(strongvpn_server strongvpn_client
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install targets
install(TARGETS strongvpn_server strongvpn_client
    RUNTIME DESTINATION bin
)
