#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// Include the donna implementation (fix the typedefs inside the .c file)
#include "curve25519-donna.c"

void generate_random_bytes(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    fread(buf, 1, len, fp);
    fclose(fp);
}

int sign_data_rsa(const uint8_t *hash, size_t hash_len, uint8_t *sig, size_t *sig_len, const char *keyfile) {
    FILE *fp = fopen(keyfile, "r");
    if (!fp) return -1;

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa) return -2;

    int result = RSA_sign(NID_sha1, hash, hash_len, sig, (unsigned int *)sig_len, rsa);
    RSA_free(rsa);
    return result ? 0 : -3;
}

int main() {
    uint8_t server_private[32], server_public[32];
    uint8_t client_random[32], server_random[32];
    uint8_t signed_hash[256];
    size_t sig_len = 0;

    const uint8_t curve25519_basepoint[32] = {9};  // Corrected basepoint

    // Generate X25519 key pair
    generate_random_bytes(server_private, 32);
    curve25519_donna(server_public, server_private, curve25519_basepoint);

    // Simulate TLS randoms
    generate_random_bytes(client_random, 32);
    generate_random_bytes(server_random, 32);

    uint8_t data_to_hash[96];  // 32 + 32 + 32
    memcpy(data_to_hash, client_random, 32);
    memcpy(data_to_hash + 32, server_random, 32);
    memcpy(data_to_hash + 64, server_public, 32);

    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA1(data_to_hash, sizeof(data_to_hash), hash);

    if (sign_data_rsa(hash, SHA_DIGEST_LENGTH, signed_hash, &sig_len, "server-key.pem") != 0) {
        fprintf(stderr, "RSA signing failed\n");
        return 1;
    }

    // Print results
    printf("Server Public Key:\n");
    for (int i = 0; i < 32; i++) printf("%02x", server_public[i]);
    printf("\nSignature (%zu bytes):\n", sig_len);
    for (size_t i = 0; i < sig_len; i++) printf("%02x", signed_hash[i]);
    printf("\n");

    return 0;
}

