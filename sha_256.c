#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __SHA256_HASH_0_LEN 8
uint32_t __SHA256_HASH_0[__SHA256_HASH_0_LEN] = {0X6A09E667, 0XBB67AE85, 0X3C6EF372, 0XA54FF53A,
                                                 0X510E527F, 0X9B05688C, 0X1F83D9AB, 0X5BE0CD19};
#define K_256_LEN 64
const int K_256[K_256_LEN] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void print_uint8_t(uint8_t val) {
    for (int i = 7; i >= 0; i--) {
        printf("%c", (val >> i) & 0x1 == 1 ? '1' : '0');
    }
}

void print_uint_32_t(uint32_t val) {
    for (int i = 31; i >= 0; i--) {
        printf("%c", (val >> i) & 0x1 == 1 ? '1' : '0');
    }
}

void print_uint_32_array(uint32_t msg[], uint32_t len) {

    printf("\n");
    int counter = 0;
    int rows = 0;
    for (uint32_t i = 0; i < len; i++) {

        print_uint_32_t(msg[i]);
        if (++counter == 4) {
            counter = 0;
            rows++;
            printf("\n");
            continue;
        }
        printf("\t");
    }
    printf("\nTotal Rows: %d | Total values: %d\n", rows, rows * 4);
}

void print_byte_array(uint8_t msg[], uint32_t len) {
    printf("\n");
    int counter = 0;
    int rows = 0;
    for (uint32_t i = 0; i < len; i++) {
        print_uint8_t(msg[i]);
        if (++counter == 4) {
            counter = 0;
            rows++;
            printf("\n");
            continue;
        }
        printf("\t");
    }
    printf("\nTotal Rows: %d | Total values: %d\n", rows, rows * 4);
}
#define ror(x, n) (((uint32_t)(x) >> (n)) | ((uint32_t)(x) << (32 - (n))))

typedef struct {
    uint8_t *output_message;
    uint64_t total_bytes_out;
} __sha256_preprocess_out;

__sha256_preprocess_out *__sha256_preprocess(const uint8_t *message, const uint64_t L) {

    if (!message) {
        printf("\n[ERROR]: No message to process in __sha256_preprocess_out.\n");
        return NULL;
    }

    if (L % 8 != 0) {
        printf("\nLength of message is not byte-aligned.\n");
        return NULL;
    }
    // const uint64_t K = (447 - L) % 512;
    const uint64_t mod = (L + 1) % 512;
    const uint64_t K = (mod <= 448) ? (448 - mod) : (512 + 448 - mod);

    uint64_t out_msg_iter = 0;
    const uint64_t out_msg_len = L + 1 + K + 64;
    uint8_t *output_message = calloc(out_msg_len, 1);

    if (!output_message) {
        printf("\n[ERROR]: Failed to allocate memory for output_message in __sha256_preprocess\n");
        return NULL;
    }

    while (out_msg_iter < (L / 8)) {
        output_message[out_msg_iter] = message[out_msg_iter];
        out_msg_iter++;
    }

    // message copied. out_msg_iter = length of message in bytes
    printf("\nK: %llu (%d bytes) | L: %llu (%d bytes) | out_msg_len: %llu (%d bytes) | out_msg_iter: %llu\n", K, K / 8,
           L, L / 8, out_msg_len, out_msg_len / 8, out_msg_iter);

    output_message[out_msg_iter++] = 0x80;

    for (int i = 0; i < K / 8; i++) {
        output_message[out_msg_iter++] = 0;
    }

    for (int i = 56; i >= 0; i -= 8) {
        output_message[out_msg_iter++] = (uint8_t)((L >> i) & 0xFF);
    }

    //    print_byte_array(output_message, out_msg_len / 8);
    __sha256_preprocess_out *out = malloc(sizeof(__sha256_preprocess_out));
    if (!out) {
        printf("\n[ERROR]: Failed to allocate mamory for output in __sha256_preprocess\n");
        free(output_message);
        return NULL;
    }

    out->output_message = output_message;
    out->total_bytes_out = out_msg_len / 8;
    return out;
}

void __sha256_process_chunk(const uint8_t *chunk) {
    uint32_t w[64];

    int w_iter = 0;

    while (w_iter < 16) {
        int offset = w_iter * 4;
        w[w_iter] = ((uint32_t)chunk[offset] << 24) | ((uint32_t)chunk[offset + 1] << 16) |
                    ((uint32_t)chunk[offset + 2] << 8) | ((uint32_t)chunk[offset + 3]);
        w_iter++;
    }
    // First all values of chunk copied tightly into first 16 words of w array

    while (w_iter < 64) {
        const uint32_t S0 = (ror(w[w_iter - 15], 7)) ^ (ror(w[w_iter - 15], 18)) ^ (w[w_iter - 15] >> 3);
        const uint32_t S1 = (ror(w[w_iter - 2], 17)) ^ (ror(w[w_iter - 2], 19)) ^ (w[w_iter - 2] >> 10);
        w[w_iter] = w[w_iter - 16] + S0 + w[w_iter - 7] + S1;
        w_iter++;
    }

    uint32_t a = __SHA256_HASH_0[0];
    uint32_t b = __SHA256_HASH_0[1];
    uint32_t c = __SHA256_HASH_0[2];
    uint32_t d = __SHA256_HASH_0[3];
    uint32_t e = __SHA256_HASH_0[4];
    uint32_t f = __SHA256_HASH_0[5];
    uint32_t g = __SHA256_HASH_0[6];
    uint32_t h = __SHA256_HASH_0[7];

    for (uint8_t i = 0; i < 64; i++) {
        const uint32_t S1 = (ror(e, 6)) ^ (ror(e, 11)) ^ (ror(e, 25));
        const uint32_t CH = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + S1 + CH + K_256[i] + w[i];

        const uint32_t S0 = (ror(a, 2)) ^ (ror(a, 13)) ^ (ror(a, 22));
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    __SHA256_HASH_0[0] += a;
    __SHA256_HASH_0[1] += b;
    __SHA256_HASH_0[2] += c;
    __SHA256_HASH_0[3] += d;
    __SHA256_HASH_0[4] += e;
    __SHA256_HASH_0[5] += f;
    __SHA256_HASH_0[6] += g;
    __SHA256_HASH_0[7] += h;
}

typedef struct {
    uint8_t hash[8];
} __sha256_hash;

const __sha256_hash __sha256_generate_hash(void *input) {
    const uint8_t *msg = (uint8_t *)input;
    uint64_t msg_len = strlen(msg);
    __sha256_preprocess_out *preprocess_out = __sha256_preprocess(msg, msg_len * 8);
    // process chunks one after the another (512 bit gaps)
    for (uint64_t i = 0; i < preprocess_out->total_bytes_out * 8; i += 512) {
        __sha256_process_chunk(preprocess_out->output_message);
    }
}

int main() {
    char msg[] = "";
    __sha256_preprocess_out *out = __sha256_preprocess(msg, strlen(msg) * 8);
    if (!out) {
        printf("\nExiting...\n");
        return 0;
    }

    const __sha256_hash sha_256_hash = __sha256_generate_hash(msg);
    print_byte_array(out->output_message, out->total_bytes_out);
    //__sha256_process_chunk(out->output_message);
    printf("\nAfter compression function, the produced __SHA256_HASH_0 values are:\n");
    for (int i = 0; i < 8; i++) {
        printf("%x\n", __SHA256_HASH_0[i]);
    }
    printf("\n");

    return 0;
}
