#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define HASH_0_LEN 8
const int HASH_0[HASH_0_LEN] = {0X6A09E667, 0XBB67AE85, 0X3C6EF372, 0XA54FF53A,
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

void print_bits(const int *ptr, int len) {
    for (int i = 0; i < len; i++) {
        unsigned int v = ptr[i];
        for (int b = 31; b >= 0; b--) {
            printf("%d", (v >> b) & 1); // print MSB first
        }
        printf("\n"); // newline per int
    }
}
#define __SHA_256_VAR_SIZE 32
#define __PADDED_1_BIT_VALUE 0x80000000 // 1000 0000 0000 0000 0000 0000 0000 0000 0000
typedef struct {
    int *ascii_message_out;
    int total_bits_out;
} __sha256_preprocess_out;
// int *__sha256_preprocess(char message[], const unsigned long l) {
__sha256_preprocess_out __sha256_preprocess(char message[], const unsigned long l) {
    const unsigned K = 512 - ((l + 1 + 64) % 512); // (L + 1 + K + 64) % 512 == 0
    int additional_bytes_needed = (1 + 64 + K) / sizeof(char);
    if ((1 + 64 + K) % sizeof(char) != 0) {
        additional_bytes_needed++;
    }
    // begin with the original message of length L bits
    // copy to int form (ascii value)
    // append a single '1' bit
    unsigned total_bits_L = l * __SHA_256_VAR_SIZE;
    unsigned total_bits_K = 512 - (total_bits_L + 1 + 64) % 512;
    printf("\nTotal bits K are %d\n", total_bits_K);
    unsigned total_bytes_K = total_bits_K / __SHA_256_VAR_SIZE;
    printf("Total bytes K are %d\n", total_bytes_K);
    printf("\nTotal bits L are: %d\n", total_bits_L);

    int ascii_message_len = total_bits_L + 1 + total_bits_K + 64;
    printf("\nascii_message length will be %d\n\n", ascii_message_len);
    // int *ascii_message = malloc(total_bits_L + 1 + total_bits_K + 64);
    int *ascii_message = calloc(sizeof(int), ascii_message_len / __SHA_256_VAR_SIZE);
    int ascii_iter = 0;
    while (ascii_iter < l) {
        ascii_message[ascii_iter] = message[ascii_iter];
        ascii_iter++;
        //  printf("\n\t%c", ascii_message[ascii_iter]);
    }
    // append a single 1 bit to t_mess
    ascii_message[ascii_iter++] = __PADDED_1_BIT_VALUE;
    //   print_bits(ascii_message, (total_bits_L + 1 + total_bits_K + 64) / __SHA_256_VAR_SIZE);

    // add K zeros
    for (int i = 0; i < total_bytes_K; i++) {
        ascii_message[ascii_iter++] = 0;
    }
    printf("\n\n");
    //  print_bits(ascii_message, (total_bits_L + 1 + total_bits_K + 64) / __SHA_256_VAR_SIZE);
    // add L as a 64-bit integer -> leave secondlast as is, replace last with l value

    ascii_message[ascii_iter++] = (l >> __SHA_256_VAR_SIZE);
    ascii_message[ascii_iter] = (l << __SHA_256_VAR_SIZE) >> __SHA_256_VAR_SIZE;
    //    print_bits(ascii_message, (total_bits_L + 1 + total_bits_K + 64) / __SHA_256_VAR_SIZE);
    __sha256_preprocess_out spo = {ascii_message, ascii_message_len};
    return spo;
}

int main() {

    char message[] = "lmnophhqrstuvhehel";
    unsigned message_len = strlen(message);
    unsigned message_ascii[message_len];

    printf("\n");
    __sha256_preprocess_out preprocessed_message = __sha256_preprocess(message, message_len);
    print_bits(preprocessed_message.ascii_message_out, preprocessed_message.total_bits_out / __SHA_256_VAR_SIZE);
    // printf("\n%d\n", HASH_0[0]);
    return 0;
}
