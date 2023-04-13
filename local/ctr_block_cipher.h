#ifndef CTR_BLOCK_CIPHER_H
#define CTR_BLOCK_CIPHER_H

// An implementation of the Counter Block Cipher (CTR) as described in NIST
// Special Publication 800-38A 2001 Edition "Recommendation for Block Cipher
// Modes of Operation: Methods and Techniques", pp. 15-16.
//
// The CTR is a way of encrypting data of arbitrary length with a block-wise
// encoder (e.g., the AES encoder) in a way that still
// encrypts repetitive messages. In addition to the encryption key, an
// Initialization Vector (IV) must be shared. This is basically a random number
// with precision equal to the number of bits in the block. This number is
// incremented every block. Typically the vector is incremented by 1 and allowed
// to roll over (this is compatible with widely-used encryption libraries such
// as openssl). The IV is then encrypted and the current plaintext block is
// XOR'd with the result, giving an encrpyted block. If a block is not full
// (because the length of the message is not a multiple of the block size), then
// the XOR is performed with the u most-significant bytes of the IV. The
// concatenation of these blocks is the encrypted message.
//
// Decryption is virtually the same: the IV is initialized with the same value
// as it was for encryption, it is incremented and encrypted each block, and
// the XOR is performed with encrypted block giving a plaintext block. This
// means that only the forward-cipher function is required.
//
// See the document above for more details.
//
// How to use this:
//
// The application initializes an instance of ctr_block_cipher_t with the
// relevant block_size, IV, incrementing function, forward-cipher function
// (encrypt_block) and any auxiliary data required.
// Then ctr_block_cipher_enc_block can be called on a block of data that is <=
// the length of a block, or ctr_block_cipher_enc can be called on a longer
// length of data.
//
// Note ctr_block_cipher_default_init should be called before other
// initialization of the ctr_block_cipher_t fields takes place.

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
    void (*encrypt_block)(const uint8_t *in,
                          uint8_t *out,
                          size_t block_size,
                          void *aux);
    // auxiliary data for the increment_iv and encrypt_block functions
    void *aux;
} ctr_block_cipher_t;

// Initialize coder with default fields
// This initializes all fields to 0 and sets the increment_iv function to one
// that simply increments by 1 (the standard)
void ctr_block_cipher_default_init(ctr_block_cipher_t *coder);

// Encode input and place the (identically-sized) result into output. input and
// output must have size equal to block_size and <= to coder->block_size
void ctr_block_cipher_enc_block(ctr_block_cipher_t *coder,
                                const uint8_t *input,
                                uint8_t *output,
                                size_t block_size);

// Encode input and place the (identically-sized) result into output. input and
// output can have any length in the range of size_t
void ctr_block_cipher_enc(ctr_block_cipher_t *coder,
                          const uint8_t *input,
                          uint8_t *output,
                          size_t length);

#endif /* CTR_BLOCK_CIPHER_H */
