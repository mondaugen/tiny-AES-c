#include "ctr_block_cipher.h"
#include <string.h>

#define MIN(x, y)                                                              \
    ({                                                                         \
        typeof(x) a = x;                                                       \
        typeof(y) b = y;                                                       \
        a < b ? a : b;                                                         \
    })

static void vect_xor(uint8_t *in_out, const uint8_t *in, size_t len)
{
    while (len-- > 0) {
        *in_out++ ^= *in++;
    }
}

// vector stored msb first
static void vect_inc(uint8_t *in_out, size_t len)
{
    uint8_t carry = 1;
    in_out += len;
    while (carry && (len-- > 0)) {
        in_out--;
        *in_out += carry;
        carry = *in_out == 0;
    }
}

static void default_increment_iv(uint8_t *iv, size_t block_size, void *aux)
{
    vect_inc(iv, block_size);
}

// block_size must be <= to coder->block_size
void ctr_block_cipher_enc_block(ctr_block_cipher_t *coder,
                                const uint8_t *input,
                                uint8_t *output,
                                size_t block_size)
{
    uint8_t tmp[coder->block_size];
    coder->encrypt_block(coder->iv, tmp, coder->block_size, coder->aux);
    // here the xor and memcpy are only performed on the first block_size
    // bytes so that incomplete blocks can get encoded without padding
    vect_xor(tmp, input, block_size);
    memcpy(output, tmp, block_size);
    coder->increment_iv(coder->iv, coder->block_size, coder->aux);
}

void ctr_block_cipher_enc(ctr_block_cipher_t *coder,
                          const uint8_t *input,
                          uint8_t *output,
                          size_t length)
{
    while (length > 0) {
        ctr_block_cipher_enc_block(coder, input, output,
                                   MIN(length, coder->block_size));
        length = length < coder->block_size ? 0 : length - coder->block_size;
        input += coder->block_size;
        output += coder->block_size;
    }
}

void ctr_block_cipher_default_init(ctr_block_cipher_t *coder)
{
    memset(coder, 0, sizeof(ctr_block_cipher_t));
    coder->increment_iv = default_increment_iv;
}
