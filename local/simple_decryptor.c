#include "aes.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_KEY "00112233445566778899aabbccddeeff"
#define DEFAULT_IV "ffeeddccbbaa99887766554433221100"

#include "_common.h"

int main(void)
{
    uint8_t key[AES_KEYLEN];
    uint8_t iv[AES_BLOCKLEN];
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    maybe_parse_hexstr("KEY", key, AES_KEYLEN, DEFAULT_KEY);
    maybe_parse_hexstr("IV", iv, AES_BLOCKLEN, DEFAULT_IV);
    fprintf(stderr, "key is: ");
    print_as_hex(stderr, key, AES_KEYLEN);
    fprintf(stderr, "\n");
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    uint8_t block[AES_BLOCKLEN];
    while (fread(memset(block, 0, AES_BLOCKLEN), sizeof(uint8_t), AES_BLOCKLEN,
                 stdin) > 0) {
        fprintf(stderr, "decrypting ");
        print_as_hex(stderr, block, AES_BLOCKLEN);
        fprintf(stderr, "\n");
        if (strcmp(getenv("STYLE"), "ECB") == 0) {
            AES_ECB_decrypt(&ctx, block);
        } else if (strcmp(getenv("STYLE"), "CBC") == 0) {
            AES_CBC_decrypt_buffer(&ctx, block, AES_BLOCKLEN);
        } else if (strcmp(getenv("STYLE"), "CTR") == 0) {
            AES_CTR_xcrypt_buffer(&ctx, block, AES_BLOCKLEN);
        } else {
            fprintf(stderr, "STYLE %s not known\n", getenv("STYLE"));
        }
        fwrite(block, sizeof(uint8_t), AES_BLOCKLEN, stdout);
    }
    return 0;
}
