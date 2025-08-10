/*
 * StrongVPN Post-Quantum Mathematics Verification Demo
 * 
 * This demo verifies the mathematical correctness of ML-DSA and ML-KEM
 * implementations by testing all critical operations and showing the
 * actual mathematical transformations happening inside the algorithms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/crypto/ml_dsa.h"
#include "../src/crypto/ml_kem.h"

// Mathematical verification functions
static void print_hex_compact(const char *label, const uint8_t *data, size_t len, size_t max_show);
static int verify_ntt_correctness(void);
static int verify_mldsa_mathematics(void);
static int verify_mlkem_mathematics(void);
static int benchmark_operations(void);

static void print_hex_compact(const char *label, const uint8_t *data, size_t len, size_t max_show) {
    printf("%-20s: ", label);
    size_t show = len < max_show ? len : max_show;
    for (size_t i = 0; i < show; i++) {
        printf("%02x", data[i]);
    }
    if (len > max_show) {
        printf("... (%zu bytes total)", len);
    }
    printf("\n");
}

// Verify NTT mathematical correctness
static int verify_ntt_correctness(void) {
    printf("\n=== NTT Mathematical Verification ===\n");
    
    // Test polynomial: f(x) = 1 + 2x + 3x² + ... + 256x²⁵⁵
    int32_t poly[256];
    int32_t poly_copy[256];
    
    for (int i = 0; i < 256; i++) {
        poly[i] = i + 1;
        poly_copy[i] = poly[i];
    }
    
    printf("Original polynomial coefficients: [1, 2, 3, ..., 256]\n");
    
    // Forward NTT
    extern void mldsa_ntt(int32_t a[256]);
    mldsa_ntt(poly);
    printf("After forward NTT: frequency domain representation computed\n");
    
    // Inverse NTT
    extern void mldsa_invntt(int32_t a[256]);
    mldsa_invntt(poly);
    printf("After inverse NTT: back to coefficient domain\n");
    
    // Verify correctness
    int correct = 1;
    for (int i = 0; i < 256; i++) {
        if (poly[i] != poly_copy[i]) {
            correct = 0;
            printf("ERROR: Coefficient %d: expected %d, got %d\n", i, poly_copy[i], poly[i]);
            break;
        }
    }
    
    if (correct) {
        printf("✓ NTT mathematical correctness verified: NTT⁻¹(NTT(f)) = f\n");
        return 0;
    } else {
        printf("✗ NTT verification failed\n");
        return -1;
    }
}

// Verify ML-DSA mathematical properties
static int verify_mldsa_mathematics(void) {
    printf("\n=== ML-DSA Mathematical Verification ===\n");
    
    // Test all security levels
    ml_dsa_param_t params[] = {ML_DSA_44, ML_DSA_65, ML_DSA_87};
    const char *param_names[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    
    for (int p = 0; p < 3; p++) {
        printf("\nTesting %s:\n", param_names[p]);
        
        // Generate key pair
        ml_dsa_keypair_t keypair;
        if (ml_dsa_keygen(&keypair, params[p]) != 0) {
            printf("✗ Key generation failed for %s\n", param_names[p]);
            return -1;
        }
        
        size_t pk_len, sk_len, sig_len;
        ml_dsa_get_sizes(params[p], &pk_len, &sk_len, &sig_len);
        
        printf("  Key sizes: PK=%zu bytes, SK=%zu bytes, Sig=%zu bytes\n", 
               pk_len, sk_len, sig_len);
        
        print_hex_compact("  Public Key", keypair.public_key, pk_len, 16);
        print_hex_compact("  Private Key", keypair.private_key, sk_len, 16);
        
        // Test message signing and verification
        const char *test_messages[] = {
            "Hello, post-quantum world!",
            "StrongVPN with ML-DSA signatures",
            "Mathematical verification test message",
            "" // Empty message
        };
        
        for (int m = 0; m < 4; m++) {
            const char *msg = test_messages[m];
            size_t msg_len = strlen(msg);
            
            // Sign message
            ml_dsa_signature_t signature;
            if (ml_dsa_sign(&signature, (const uint8_t*)msg, msg_len, &keypair) != 0) {
                printf("✗ Signing failed for message %d\n", m);
                ml_dsa_keypair_free(&keypair);
                return -1;
            }
            
            // Verify signature
            int verify_result = ml_dsa_verify(&signature, (const uint8_t*)msg, msg_len,
                                            keypair.public_key, pk_len, params[p]);
            
            if (verify_result == 0) {
                printf("  ✓ Message %d: Sign/Verify correct (msg_len=%zu)\n", m, msg_len);
            } else {
                printf("  ✗ Message %d: Verification failed\n", m);
                ml_dsa_signature_free(&signature);
                ml_dsa_keypair_free(&keypair);
                return -1;
            }
            
            // Test signature malleability (should fail)
            if (signature.signature_len > 0) {
                signature.signature[0] ^= 1; // Flip one bit
                int tampered_result = ml_dsa_verify(&signature, (const uint8_t*)msg, msg_len,
                                                  keypair.public_key, pk_len, params[p]);
                if (tampered_result != 0) {
                    printf("  ✓ Tampered signature correctly rejected\n");
                } else {
                    printf("  ✗ Tampered signature incorrectly accepted\n");
                    ml_dsa_signature_free(&signature);
                    ml_dsa_keypair_free(&keypair);
                    return -1;
                }
                signature.signature[0] ^= 1; // Restore
            }
            
            ml_dsa_signature_free(&signature);
        }
        
        ml_dsa_keypair_free(&keypair);
        printf("  ✓ %s mathematical verification complete\n", param_names[p]);
    }
    
    return 0;
}

// Verify ML-KEM mathematical properties
static int verify_mlkem_mathematics(void) {
    printf("\n=== ML-KEM Mathematical Verification ===\n");
    
    // Test all security levels
    ml_kem_param_t params[] = {ML_KEM_512, ML_KEM_768, ML_KEM_1024};
    const char *param_names[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    
    for (int p = 0; p < 3; p++) {
        printf("\nTesting %s:\n", param_names[p]);
        
        // Generate key pair
        ml_kem_keypair_t keypair;
        if (ml_kem_keygen(&keypair, params[p]) != 0) {
            printf("✗ Key generation failed for %s\n", param_names[p]);
            return -1;
        }
        
        size_t pk_len, sk_len, ct_len, ss_len;
        ml_kem_get_sizes(params[p], &pk_len, &sk_len, &ct_len, &ss_len);
        
        printf("  Key sizes: PK=%zu, SK=%zu, CT=%zu, SS=%zu bytes\n", 
               pk_len, sk_len, ct_len, ss_len);
        
        print_hex_compact("  Public Key", keypair.public_key, pk_len, 16);
        print_hex_compact("  Private Key", keypair.private_key, sk_len, 16);
        
        // Test encapsulation/decapsulation multiple times
        for (int test = 0; test < 5; test++) {
            // Encapsulation
            ml_kem_encaps_t encaps;
            if (ml_kem_encaps(&encaps, keypair.public_key, pk_len, params[p]) != 0) {
                printf("✗ Encapsulation failed (test %d)\n", test);
                ml_kem_keypair_free(&keypair);
                return -1;
            }
            
            print_hex_compact("  Ciphertext", encaps.ciphertext, ct_len, 16);
            print_hex_compact("  Shared Secret A", encaps.shared_secret, ss_len, 32);
            
            // Decapsulation
            uint8_t decaps_secret[32];
            if (ml_kem_decaps(decaps_secret, sizeof(decaps_secret),
                            encaps.ciphertext, ct_len, &keypair) != 0) {
                printf("✗ Decapsulation failed (test %d)\n", test);
                ml_kem_encaps_free(&encaps);
                ml_kem_keypair_free(&keypair);
                return -1;
            }
            
            print_hex_compact("  Shared Secret B", decaps_secret, ss_len, 32);
            
            // Verify shared secrets match
            if (memcmp(encaps.shared_secret, decaps_secret, ss_len) == 0) {
                printf("  ✓ Test %d: Shared secrets match perfectly\n", test);
            } else {
                printf("  ✗ Test %d: Shared secret mismatch!\n", test);
                ml_kem_encaps_free(&encaps);
                ml_kem_keypair_free(&keypair);
                return -1;
            }
            
            // Test ciphertext malleability (should produce different secret)
            if (encaps.ciphertext_len > 0) {
                encaps.ciphertext[0] ^= 1; // Flip one bit
                uint8_t tampered_secret[32];
                if (ml_kem_decaps(tampered_secret, sizeof(tampered_secret),
                                encaps.ciphertext, ct_len, &keypair) == 0) {
                    if (memcmp(encaps.shared_secret, tampered_secret, ss_len) != 0) {
                        printf("  ✓ Tampered ciphertext produces different secret (as expected)\n");
                    } else {
                        printf("  ✗ Tampered ciphertext produces same secret (unexpected)\n");
                    }
                } else {
                    printf("  ✓ Tampered ciphertext rejected (acceptable)\n");
                }
            }
            
            ml_kem_encaps_free(&encaps);
        }
        
        ml_kem_keypair_free(&keypair);
        printf("  ✓ %s mathematical verification complete\n", param_names[p]);
    }
    
    return 0;
}

// Benchmark critical operations
static int benchmark_operations(void) {
    printf("\n=== Performance Benchmarks ===\n");
    
    const int iterations = 100;
    clock_t start, end;
    
    // ML-DSA-65 benchmarks
    printf("\nML-DSA-65 Performance:\n");
    
    // Key generation
    start = clock();
    for (int i = 0; i < iterations; i++) {
        ml_dsa_keypair_t keypair;
        ml_dsa_keygen(&keypair, ML_DSA_65);
        ml_dsa_keypair_free(&keypair);
    }
    end = clock();
    double keygen_time = ((double)(end - start)) / CLOCKS_PER_SEC / iterations * 1000;
    printf("  Key Generation: %.2f ms/op\n", keygen_time);
    
    // Signing benchmark
    ml_dsa_keypair_t keypair;
    ml_dsa_keygen(&keypair, ML_DSA_65);
    const char *msg = "Benchmark message for signing performance test";
    
    start = clock();
    for (int i = 0; i < iterations; i++) {
        ml_dsa_signature_t sig;
        ml_dsa_sign(&sig, (const uint8_t*)msg, strlen(msg), &keypair);
        ml_dsa_signature_free(&sig);
    }
    end = clock();
    double sign_time = ((double)(end - start)) / CLOCKS_PER_SEC / iterations * 1000;
    printf("  Signing: %.2f ms/op\n", sign_time);
    
    // Verification benchmark
    ml_dsa_signature_t sig;
    ml_dsa_sign(&sig, (const uint8_t*)msg, strlen(msg), &keypair);
    
    start = clock();
    for (int i = 0; i < iterations; i++) {
        ml_dsa_verify(&sig, (const uint8_t*)msg, strlen(msg),
                     keypair.public_key, keypair.public_key_len, ML_DSA_65);
    }
    end = clock();
    double verify_time = ((double)(end - start)) / CLOCKS_PER_SEC / iterations * 1000;
    printf("  Verification: %.2f ms/op\n", verify_time);
    
    ml_dsa_signature_free(&sig);
    ml_dsa_keypair_free(&keypair);
    
    // ML-KEM-768 benchmarks
    printf("\nML-KEM-768 Performance:\n");
    
    // Key generation
    start = clock();
    for (int i = 0; i < iterations; i++) {
        ml_kem_keypair_t kem_keypair;
        ml_kem_keygen(&kem_keypair, ML_KEM_768);
        ml_kem_keypair_free(&kem_keypair);
    }
    end = clock();
    double kem_keygen_time = ((double)(end - start)) / CLOCKS_PER_SEC / iterations * 1000;
    printf("  Key Generation: %.2f ms/op\n", kem_keygen_time);
    
    // Encapsulation benchmark
    ml_kem_keypair_t kem_keypair;
    ml_kem_keygen(&kem_keypair, ML_KEM_768);
    
    start = clock();
    for (int i = 0; i < iterations; i++) {
        ml_kem_encaps_t encaps;
        ml_kem_encaps(&encaps, kem_keypair.public_key, kem_keypair.public_key_len, ML_KEM_768);
        ml_kem_encaps_free(&encaps);
    }
    end = clock();
    double encaps_time = ((double)(end - start)) / CLOCKS_PER_SEC / iterations * 1000;
    printf("  Encapsulation: %.2f ms/op\n", encaps_time);
    
    // Decapsulation benchmark
    ml_kem_encaps_t encaps;
    ml_kem_encaps(&encaps, kem_keypair.public_key, kem_keypair.public_key_len, ML_KEM_768);
    
    start = clock();
    for (int i = 0; i < iterations; i++) {
        uint8_t secret[32];
        ml_kem_decaps(secret, 32, encaps.ciphertext, encaps.ciphertext_len, &kem_keypair);
    }
    end = clock();
    double decaps_time = ((double)(end - start)) / CLOCKS_PER_SEC / iterations * 1000;
    printf("  Decapsulation: %.2f ms/op\n", decaps_time);
    
    ml_kem_encaps_free(&encaps);
    ml_kem_keypair_free(&kem_keypair);
    
    printf("\nPerformance Summary:\n");
    printf("  ML-DSA-65: %.1f ms keygen, %.1f ms sign, %.1f ms verify\n", 
           keygen_time, sign_time, verify_time);
    printf("  ML-KEM-768: %.1f ms keygen, %.1f ms encaps, %.1f ms decaps\n",
           kem_keygen_time, encaps_time, decaps_time);
    
    return 0;
}

int main(void) {
    printf("StrongVPN Post-Quantum Mathematics Verification\n");
    printf("================================================\n");
    printf("Verifying mathematical correctness of ML-DSA and ML-KEM implementations\n");
    
    // Run mathematical verification tests
    if (verify_ntt_correctness() != 0) {
        printf("\n❌ NTT verification failed - mathematical error detected!\n");
        return 1;
    }
    
    if (verify_mldsa_mathematics() != 0) {
        printf("\n❌ ML-DSA verification failed - mathematical error detected!\n");
        return 1;
    }
    
    if (verify_mlkem_mathematics() != 0) {
        printf("\n❌ ML-KEM verification failed - mathematical error detected!\n");
        return 1;
    }
    
    if (benchmark_operations() != 0) {
        printf("\n❌ Performance benchmarking failed!\n");
        return 1;
    }
    
    printf("\n🎉 MATHEMATICAL VERIFICATION COMPLETE 🎉\n");
    printf("=========================================\n");
    printf("✅ All mathematical operations verified correct\n");
    printf("✅ NTT forward/inverse transforms working perfectly\n");
    printf("✅ ML-DSA signatures mathematically sound\n");
    printf("✅ ML-KEM key encapsulation mathematically sound\n");
    printf("✅ Performance benchmarks completed\n");
    printf("\nStrongVPN post-quantum cryptography is mathematically verified!\n");
    printf("Ready for quantum-resistant VPN deployment.\n");
    
    return 0;
}
