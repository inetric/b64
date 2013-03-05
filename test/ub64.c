#include "b64.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
    FILE *in;
    unsigned char buff[0x2000];
    size_t fr = 0;
    b64_t b;

    if (argc < 2) return 1;

    in = fopen(argv[1], "rb");
    if (!in) return 1;

    b64_init(&b);

    while ((fr = fread(buff, 1, sizeof buff, in)) > 0) {
        size_t r = fr;
        b64_decode(&b, buff, r, buff, &r);
        fwrite(buff, 1, r, stdout);
    }
    fclose(in);

    return 0;
};
