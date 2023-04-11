#include <string.h>
#include "ctr_block_cipher.h"

#define MIN(x,y) ({ \
    typeof(x) a = x; \
    typeof(y) b = y; \
    a < b ? a : b; \
})

static void vect_xor(uint8_t *in_out, const uint8_t *in, size_t len)
{
    while (len-- > 0) {
        *in_out++ ^= *in++;
    }
}

// vector stored lsb first
static void vect_inc(uint8_t *in_out, size_t len)
{
    uint8_t carry = 1;
    while (carry && (len-- > 0)) {
        *in_out += carry;
        carry = *in_out == 0;
        in_out++;
    }
}

static void default_increment_iv(uint8_t *iv, size_t block_size, void *aux)
{
    vect_inc(iv,block_size);
}

// block_length must be <= to coder->block_size
void ctr_block_cipher_enc_block(ctr_block_cipher_t *coder, const uint8_t *input, uint8_t *output, size_t block_length)
{
    coder->encrypt_block(coder->iv,output,block_length,coder->aux);
    vect_xor(output,input,block_length);
    coder->increment_iv(coder->iv,coder->block_size,coder->aux);
}

void ctr_block_cipher_enc(ctr_block_cipher_t *coder, const uint8_t *input, uint8_t *output, size_t length)
{
    while (length > 0) {
        ctr_block_cipher_enc_block(coder,input,output,MIN(length,coder->block_size));
        length = length < coder->block_size ? 0 : length - coder->block_size;
        input += coder->block_size;
        output += coder->block_size;
    }
}

void ctr_block_cipher_default_init(ctr_block_cipher_t *coder)
{
    memset(coder,0,sizeof(ctr_block_cipher_t));
    coder->increment_iv = default_increment_iv;
}
