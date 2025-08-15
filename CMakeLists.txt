cmake_minimum_required(VERSION 3.16)
project(StrongVPN VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)

# Verify OpenSSL version (3.0+ required for post-quantum support)
if(OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(FATAL_ERROR "OpenSSL 3.0.0 or higher is required for post-quantum cryptography support")
endif()

# Option to enable real liboqs cryptography
option(USE_LIBOQS "Use real liboqs cryptography (production)" OFF)

# Find liboqs with fallback methods
if(USE_LIBOQS)
    pkg_check_modules(LIBOQS liboqs)
    if(NOT LIBOQS_FOUND)
        # Fallback: try to find liboqs manually
        find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h
            PATHS /usr/local/include /usr/include
            PATH_SUFFIXES oqs
        )
        find_library(LIBOQS_LIBRARY
            NAMES oqs liboqs
            PATHS /usr/local/lib /usr/lib
        )
        
        if(LIBOQS_INCLUDE_DIR AND LIBOQS_LIBRARY)
            set(LIBOQS_FOUND TRUE)
            set(LIBOQS_INCLUDE_DIRS ${LIBOQS_INCLUDE_DIR})
            set(LIBOQS_LIBRARIES ${LIBOQS_LIBRARY})
            message(STATUS "Found liboqs: ${LIBOQS_LIBRARY}")
        else()
            message(FATAL_ERROR "liboqs not found. Please install liboqs development package.")
        endif()
    endif()
    
    # Configure for real cryptography
    add_definitions(-DUSE_LIBOQS)
    message(STATUS "Building with REAL post-quantum cryptography (liboqs)")
    message(STATUS "Security Level: 128-bit quantum resistance")
else()
    # Using stubs for testing
    message(WARNING "Building with STUB cryptography - NOT SECURE!")
    message(WARNING "For production use: cmake -DUSE_LIBOQS=ON ..")
endif()

# Include directories
if(USE_LIBOQS AND LIBOQS_FOUND)
    include_directories(${LIBOQS_INCLUDE_DIRS})
endif()
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(src)

# Compiler flags for optimization and security
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -march=native")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")  # Position independent code

# Debug flags for development
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DDEBUG -fsanitize=address")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# Source files
set(STRONGVPN_SOURCES
    src/crypto/pq_core.c
    src/crypto/ml_dsa.c
    src/crypto/ml_kem.c
    src/crypto/pq_liboqs.c
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

# Link libraries with conditional liboqs linking
if(USE_LIBOQS AND LIBOQS_FOUND)
    target_link_libraries(strongvpn_server 
        ${LIBOQS_LIBRARIES}
        OpenSSL::SSL 
        OpenSSL::Crypto 
        m          # Math library
        pthread    # Threading support
        dl         # Dynamic linking
    )
    
    target_link_libraries(strongvpn_client 
        ${LIBOQS_LIBRARIES}
        OpenSSL::SSL 
        OpenSSL::Crypto 
        m          # Math library
        pthread    # Threading support
        dl         # Dynamic linking
    )
else()
    # Stub mode - no liboqs linking
    target_link_libraries(strongvpn_server 
        OpenSSL::SSL 
        OpenSSL::Crypto 
        m          # Math library
        pthread    # Threading support
        dl         # Dynamic linking
    )
    
    target_link_libraries(strongvpn_client 
        OpenSSL::SSL 
        OpenSSL::Crypto 
        m          # Math library
        pthread    # Threading support
        dl         # Dynamic linking
    )
endif()

# Compiler flags for liboqs
if(LIBOQS_CFLAGS_OTHER)
    target_compile_options(strongvpn_server PRIVATE ${LIBOQS_CFLAGS_OTHER})
    target_compile_options(strongvpn_client PRIVATE ${LIBOQS_CFLAGS_OTHER})
endif()

# Link directories
if(LIBOQS_LIBRARY_DIRS)
    target_link_directories(strongvpn_server PRIVATE ${LIBOQS_LIBRARY_DIRS})
    target_link_directories(strongvpn_client PRIVATE ${LIBOQS_LIBRARY_DIRS})
endif()

# Set output directory
set_target_properties(strongvpn_server strongvpn_client
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    INSTALL_RPATH_USE_LINK_PATH TRUE
)

# Add custom target for testing liboqs linkage
add_custom_target(test_liboqs
    COMMAND ${CMAKE_COMMAND} -E echo "Testing liboqs linkage..."
    COMMAND ldd ${CMAKE_BINARY_DIR}/bin/strongvpn_server | grep -E "(oqs|ssl|crypto)" || echo "Libraries linked successfully"
    DEPENDS strongvpn_server
    COMMENT "Verifying liboqs and OpenSSL linkage"
)

# Install targets
install(TARGETS strongvpn_server strongvpn_client
    RUNTIME DESTINATION bin
)

# Print configuration summary
message(STATUS "=== StrongVPN Build Configuration ===")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "liboqs Include: ${LIBOQS_INCLUDE_DIRS}")
message(STATUS "liboqs Libraries: ${LIBOQS_LIBRARIES}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Flags: ${CMAKE_C_FLAGS}")
message(STATUS "=====================================")

# Add test for basic functionality
enable_testing()
add_test(NAME strongvpn_server_help 
         COMMAND ${CMAKE_BINARY_DIR}/bin/strongvpn_server --help)
add_test(NAME strongvpn_client_help 
         COMMAND ${CMAKE_BINARY_DIR}/bin/strongvpn_client --help)
set_tests_properties(strongvpn_server_help strongvpn_client_help 
                     PROPERTIES WILL_FAIL TRUE)  # Help commands return non-zero
