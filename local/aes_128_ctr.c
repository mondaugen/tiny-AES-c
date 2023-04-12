#include "aes.h"
#include "ctr_block_cipher.h"
#include <string.h>

static void
encrypt_block(const uint8_t *in, uint8_t *out, size_t block_size, void *aux)
{
    struct AES_ctx *ctx = aux;
    memcpy(out, in, block_size);
    AES_ECB_encrypt(ctx, out);
}

void ctr_block_cipher_aes_128_init(ctr_block_cipher_t *coder,
                                   struct AES_ctx *ctx)
{
    ctr_block_cipher_default_init(coder);
    coder->block_size = AES_BLOCKLEN;
    coder->encrypt_block = encrypt_block;
    coder->aux = ctx;
}
