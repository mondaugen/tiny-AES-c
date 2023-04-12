#ifndef _COMMON_H
#define _COMMON_H 

#include <string.h>
#include <stdio.h>
#include <assert.h>

static inline void my_assert(int x)
{
    if (x != 0) {
        fprintf(stderr,"got %d\n",x);
    }
    assert(x == 0);
}

static inline int parse_hexstr(uint8_t *key, const char *keystr, size_t keylen)
{
    if ((strlen(keystr) >> 1) != keylen) {
        return -1;
    }
    while (keylen-- > 0) {
        char tmp[3];
        tmp[2] = '\0';
        memcpy(tmp,keystr,2);
        uint8_t byte;
        *key++ = (uint8_t)strtol(tmp,NULL,16);
        keystr += 2;
    }
    return 0;
}

// keylen is the number of bytes in the string or one half the string length
static inline void maybe_parse_hexstr(const char *envname, uint8_t *output, size_t keylen, const char *default_hexstr)
{
    const char *hexstr = getenv(envname);
    if (!hexstr) {
        hexstr = default_hexstr;
    }
    my_assert(parse_hexstr(output,hexstr,keylen));
}

static inline void print_as_hex(FILE *fd, const uint8_t *x, size_t len)
{
    while (len-- > 0) {
        fprintf(fd,"%.2x ",*x++);
    }
}

static inline int nonnull_strcmp(const char *s1, const char *s2)
{
    if (!s1) { return -2; }
    if (!s2) { return 2; }
    return strcmp(s1,s2);
}

#endif /* _COMMON_H */
