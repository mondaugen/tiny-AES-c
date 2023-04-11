#ifndef CTR_BLOCK_CIPHER_H
#define CTR_BLOCK_CIPHER_H 

#include <stddef.h>
#include <stdint.h>

typedef struct {
    // the size of a single block of data that is encrypted, e.g., for AES 128
    // it is 128 bits (16 bytes)
    size_t block_size;
    // initialization vector, length must be block_size
    uint8_t *iv;
    // function that increments the initialization vector
    void (*increment_iv)(uint8_t *iv, size_t block_size, void *aux);
    // function that encrypts a block of data
    void (*encrypt_block)(const uint8_t *in, uint8_t *out, size_t block_size, void *aux);
    // auxiliary data for the increment_iv and encrypt_block functions
    void *aux;
} ctr_block_cipher_t;

void ctr_block_cipher_default_init(ctr_block_cipher_t *coder);
void ctr_block_cipher_enc_block(ctr_block_cipher_t *coder, const uint8_t *input, uint8_t *output, size_t block_length);
void ctr_block_cipher_enc(ctr_block_cipher_t *coder, const uint8_t *input, uint8_t *output, size_t length);

#endif /* CTR_BLOCK_CIPHER_H */
