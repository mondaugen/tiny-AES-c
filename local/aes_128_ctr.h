#ifndef AES_128_CTR_H
#define AES_128_CTR_H

#include "aes.h"
#include "ctr_block_cipher.h"

void ctr_block_cipher_aes_128_init(ctr_block_cipher_t *coder,
                                   struct AES_ctx *ctx);

#endif /* AES_128_CTR_H */
