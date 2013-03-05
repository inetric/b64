#include "b64.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
    FILE *in;
    unsigned char buff[0x2000], enc_buff[0x4000];
    size_t fr = 0, w = 0;
    b64_t b;

    if (argc < 2) return 1;

    in = fopen(argv[1], "rb");
    if (!in) return 1;

    b64_init(&b);

    while ((fr = fread(buff, 1, sizeof buff, in)) > 0) {
        w = sizeof enc_buff;
        b64_encode(&b, buff, fr, enc_buff, &w);
        fwrite(enc_buff, 1, w, stdout);
    }
    w = b64_finish(&b, enc_buff, sizeof enc_buff);
    if (w) fwrite(enc_buff, 1, w, stdout);
    fclose(in);

    return 0;
};
