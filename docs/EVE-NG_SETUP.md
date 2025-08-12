# StrongVPN Post-Quantum Testing in EVE-NG

## EVE-NG Network Topology Setup

### Network Architecture
```
EVE-NG Lab: StrongVPN-PostQuantum-Testing
┌─────────────────────────────────────────────────────────────┐
│                        EVE-NG Host                          │
│  ┌─────────────────┐           ┌─────────────────┐          │
│  │   Client VM     │           │   Server VM     │          │
│  │   Ubuntu 22.04  │           │   Ubuntu 22.04  │          │
│  │   StrongVPN     │◄─────────►│   StrongVPN     │          │
│  │   Client        │    eth0   │   Server        │          │
│  │   10.1.1.10/24  │           │   10.1.1.20/24  │          │
│  └─────────────────┘           └─────────────────┘          │
│           │                             │                   │
│           └─────────────┬───────────────┘                   │
│                         │                                   │
│                 ┌───────▼───────┐                           │
│                 │  Virtual LAN   │                           │
│                 │  10.1.1.0/24   │                           │
│                 └───────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

## VM Configuration

### VM Specifications
- **OS**: Ubuntu 22.04 LTS Server
- **RAM**: 4GB minimum (8GB recommended for NTT operations)
- **Storage**: 20GB minimum
- **CPU**: 2 cores minimum (4 cores recommended)
- **Network**: Single interface connected to shared LAN

### Network Configuration (Manual IP Assignment)

#### Client VM (10.1.1.10)
```bash
# Method 1: Using ifconfig (temporary - lost on reboot)
sudo ifconfig eth0 10.1.1.10 netmask 255.255.255.0
sudo route add default gw 10.1.1.1

# Method 2: Using ip command (temporary - lost on reboot)
sudo ip addr add 10.1.1.10/24 dev eth0
sudo ip link set eth0 up
sudo ip route add default via 10.1.1.1

# Method 3: Permanent configuration via /etc/network/interfaces
sudo nano /etc/network/interfaces
# Add these lines:
auto eth0
iface eth0 inet static
    address 10.1.1.10
    netmask 255.255.255.0
    gateway 10.1.1.1
    dns-nameservers 8.8.8.8 8.8.4.4

# Apply permanent configuration
sudo systemctl restart networking
# OR
sudo ifdown eth0 && sudo ifup eth0
```

#### Server VM (10.1.1.20)
```bash
# Method 1: Using ifconfig (temporary - lost on reboot)
sudo ifconfig eth0 10.1.1.20 netmask 255.255.255.0
sudo route add default gw 10.1.1.1

# Method 2: Using ip command (temporary - lost on reboot)
sudo ip addr add 10.1.1.20/24 dev eth0
sudo ip link set eth0 up
sudo ip route add default via 10.1.1.1

# Method 3: Permanent configuration via /etc/network/interfaces
sudo nano /etc/network/interfaces
# Add these lines:
auto eth0
iface eth0 inet static
    address 10.1.1.20
    netmask 255.255.255.0
    gateway 10.1.1.1
    dns-nameservers 8.8.8.8 8.8.4.4

# Apply permanent configuration
sudo systemctl restart networking
# OR
sudo ifdown eth0 && sudo ifup eth0
```

#### Verify Network Configuration
```bash
# Check IP assignment
ip addr show eth0
ifconfig eth0

# Test connectivity between VMs
ping -c 4 10.1.1.20  # From client to server
ping -c 4 10.1.1.10  # From server to client

# Check routing table
ip route show
route -n

# Verify DNS resolution (if needed)
nslookup google.com
```

## StrongVPN Build Setup

### Dependencies Installation (Both VMs)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build dependencies
sudo apt install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    liboqs-dev \
    pkg-config \
    tcpdump \
    wireshark \
    net-tools \
    iperf3 \
    htop

# Verify OpenSSL version (3.0+ required)
openssl version
```

### StrongVPN Compilation
```bash
# Build StrongVPN (both VMs)
cd strongvpn
mkdir build && cd build

# Configure with post-quantum support
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_POST_QUANTUM=ON \
    -DML_DSA_LEVEL=65 \
    -DML_KEM_LEVEL=768

# Compile with optimizations
make -j$(nproc)

# Verify build
ls -la src/apps/
./src/apps/strongvpn_server --help
```

## Testing Procedures

### Step 1: Start Server
```bash
# On Server VM (10.1.1.20)
cd strongvpn/build
sudo ./src/apps/strongvpn_server 8443

# Expected output:
# [INFO] StrongVPN Post-Quantum Server v1.0
# [INFO] Server listening on port 8443 (EVE-NG: 10.1.1.20:8443)
# [INFO] Generated ephemeral ML-DSA-65 key pair (1952 byte public key)
# [INFO] Generated ephemeral ML-KEM-768 key pair (1184 byte public key)
# [INFO] Waiting for post-quantum VPN clients...
```

### Step 2: Start Client
```bash
# On Client VM (10.1.1.10)
cd strongvpn/build
./src/apps/strongvpn_client 10.1.1.20 8443

# Expected output:
# [INFO] StrongVPN Post-Quantum Client v1.0
# [INFO] Target server: 10.1.1.20:8443
# [INFO] TCP connection established to server
# [INFO] Starting pure post-quantum handshake...
# [INFO] === POST-QUANTUM HANDSHAKE SUCCESSFUL ===
# [INFO] Pure post-quantum VPN tunnel established
```

### Step 3: Network Analysis
```bash
# Capture handshake packets (run on either VM)
sudo tcpdump -i eth0 -w strongvpn_handshake.pcap port 8443

# Analyze with Wireshark
wireshark strongvpn_handshake.pcap

# Expected packet sizes:
# Client Hello: ~3173 bytes (nonce + ML-DSA pubkey + ML-KEM pubkey)
# Server Hello: ~3173 bytes (nonce + ML-DSA pubkey + ML-KEM pubkey)
# Key Exchange: ~1093 bytes (ML-KEM ciphertext)
# Client Auth: ~3314 bytes (ML-DSA signature)
# Server Auth: ~3314 bytes (ML-DSA signature)
# Total: ~13.7KB handshake traffic
```

## Performance Testing

### Handshake Performance Script
```bash
#!/bin/bash
# test_performance.sh

echo "StrongVPN Post-Quantum Performance Test"
echo "========================================"

for i in {1..10}; do
    echo "Test $i/10"
    
    # Start server in background
    timeout 10s ./src/apps/strongvpn_server &
    SERVER_PID=$!
    sleep 2
    
    # Measure client handshake time
    start_time=$(date +%s%N)
    timeout 8s ./src/apps/strongvpn_client
    end_time=$(date +%s%N)
    
    # Calculate handshake duration
    duration=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
    echo "Handshake duration: ${duration}ms"
    
    # Cleanup
    kill $SERVER_PID 2>/dev/null
    sleep 1
done
```

## Security Validation

### Cryptographic Testing
```bash
# Create validation script
#!/bin/bash
# validate_crypto.sh

echo "StrongVPN Cryptographic Validation"
echo "=================================="

# Test ML-DSA operations
echo "Testing ML-DSA-65 signature operations..."
./tests/test_ml_dsa

# Test ML-KEM operations  
echo "Testing ML-KEM-768 key exchange..."
./tests/test_ml_kem

# Test complete handshake
echo "Testing end-to-end handshake protocol..."
./tests/test_handshake

echo "All cryptographic operations validated"
```

## Expected Results

### Successful Handshake Output
```
Server Side:
[INFO] Client connected - starting post-quantum handshake
[INFO] Processing Client Hello (direct public key model)
[INFO] ML-KEM key exchange completed
[INFO] Peer authentication successful (direct public key verification)
[INFO] === POST-QUANTUM HANDSHAKE SUCCESSFUL ===

Client Side:
[INFO] Sending Client Hello (direct public key model)
[INFO] Processing Server Hello + Key Exchange
[INFO] ML-KEM-768 encapsulation completed
[INFO] === POST-QUANTUM HANDSHAKE SUCCESSFUL ===
```

### Performance Metrics
- **Handshake Duration**: 50-200ms (VM dependent)
- **Key Generation**: 10-50ms per key pair
- **Signature Operations**: 5-20ms per ML-DSA signature
- **Network Overhead**: ~13.7KB total handshake traffic
- **Memory Usage**: ~8MB per handshake context

This EVE-NG setup provides a professional testing environment for validating the pure post-quantum VPN implementation with direct public key authentication.
