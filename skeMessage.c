#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// Minimal X25519 (Curve25519) implementation
#include "curve25519-donna.c"

// Basepoint for X25519 (first byte = 9)
const uint8_t curve25519_basepoint[32] = {9};

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

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
    uint8_t server_priv[32], server_pub[32];
    uint8_t client_random[32], server_random[32];

    // Step 1: Generate X25519 ephemeral keypair
    generate_random_bytes(server_priv, 32);
    curve25519_donna(server_pub, server_priv, curve25519_basepoint);

    // Step 2: Generate TLS client_random and server_random
    generate_random_bytes(client_random, 32);
    generate_random_bytes(server_random, 32);

    // Step 3: Build ServerECDHParams = 1-byte curve_type + 2-byte named_curve + pubkey
    uint8_t server_params[3 + 1 + 32];
    server_params[0] = 0x03;         // curve_type: named_curve
    server_params[1] = 0x00;         // named_curve: X25519 = 0x001D
    server_params[2] = 0x1D;
    server_params[3] = 32;           // public key length
    memcpy(server_params + 4, server_pub, 32);

    // Step 4: Hash(client_random || server_random || server_params)
    uint8_t data_to_sign[32 + 32 + sizeof(server_params)];
    memcpy(data_to_sign, client_random, 32);
    memcpy(data_to_sign + 32, server_random, 32);
    memcpy(data_to_sign + 64, server_params, sizeof(server_params));

    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA1(data_to_sign, sizeof(data_to_sign), hash);

    // Step 5: Sign the hash with RSA
    uint8_t sig[256]; // Enough for 2048-bit key
    size_t sig_len = 0;
    if (sign_data_rsa(hash, sizeof(hash), sig, &sig_len, "server-key.pem") != 0) {
        fprintf(stderr, "RSA signature failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Step 6: Construct the full ServerKeyExchange message
    // TLS format: ServerECDHParams + signature_algorithm + sig_len + sig
    uint8_t server_key_exchange[512];
    size_t offset = 0;

    memcpy(server_key_exchange + offset, server_params, sizeof(server_params));
    offset += sizeof(server_params);

    // SignatureAlgorithm (sha1(2), rsa(1)) = 0x02 0x01
    server_key_exchange[offset++] = 0x02;
    server_key_exchange[offset++] = 0x01;

    // Signature length (2 bytes)
    server_key_exchange[offset++] = (sig_len >> 8) & 0xFF;
    server_key_exchange[offset++] = (sig_len     ) & 0xFF;

    // Signature
    memcpy(server_key_exchange + offset, sig, sig_len);
    offset += sig_len;

    // Final output
    print_hex("Client Random", client_random, 32);
    print_hex("Server Random", server_random, 32);
    print_hex("Server Public Key", server_pub, 32);
    print_hex("RSA Signature", sig, sig_len);
    print_hex("Full ServerKeyExchange", server_key_exchange, offset);

    return 0;
}
