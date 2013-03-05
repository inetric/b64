/*
Copyright (c) 2012, Michael Contreras
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
3. Neither the name of Inetric, LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "b64.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define NUME(a) (sizeof (a) / sizeof (*a))
struct test_item {
    struct {
        const char *data;
        unsigned int len;
    } t, enc, dec;
};

#define TT(t, tl, e, el, d, dl) {{t, tl},{e, el},{d, dl}}
#define T(e, el, d, dl) TT(e, el, e, el, d, dl)
static const struct test_item tests[] = {
    /* rfc4648 test vectors - http://tools.ietf.org/html/rfc4648#page-12 */
    T("FPucA9l+", 8, "\x14\xfb\x9c\x03\xd9\x7e", 6),
    T("FPucA9k=", 8, "\x14\xfb\x9c\x03\xd9", 5),
    T("FPucAw==", 8, "\x14\xfb\x9c\x03", 4),
    T("", 0, "", 0),
    T("Zg==", 4, "f", 1),
    T("Zm8=", 4, "fo", 2),
    T("Zm9v", 4, "foo", 3),
    T("Zm9vYg==", 8, "foob", 4),
    T("Zm9vYmE=", 8, "fooba", 5),
    T("Zm9vYmFy", 8, "foobar", 6),

    /* rfc4648 non-conforming tests */
    /* The implementation ignores invalid bytes in the input, making it
     * unsuitable for certain applications without pre-processing the input.
     * See SECURITY CONSIDERATIONS at -
     * http://tools.ietf.org/html/rfc4648#section-12
     */
    TT("AA\nAA\r", 6, "AAAA", 4, "\x00\x00\x00", 3),
    TT("\nZg==\n", 6, "Zg==", 4, "f", 1),
    TT("Zm\x00\x38=", 5, "Zm8=", 4, "fo", 2),
    TT("Zm**9v", 6, "Zm9v", 4, "foo", 3),

    /* Other */
    T("QQ==", 4, "A", 1),
    T("QUE=", 4, "AA", 2),
    T("QUFB", 4, "AAA", 3),
    T("QUFBQQ==", 8, "AAAA", 4),
    T("QUFBQUE=", 8, "AAAAA", 5),
    T("QUFBQUFB", 8, "AAAAAA", 6),

    T("BhNDB52Yvw==", 12, "\x06\x13\x43\x07\x9d\x98\xbf", 7),
    T("a7fkjk5cv1M=", 12, "\x6b\xb7\xe4\x8e\x4e\x5c\xbf\x53", 8),
    T("NDRQxmRIzT7+", 12, "\x34\x34\x50\xc6\x64\x48\xcd\x3e\xfe", 9),
    T("jqLCIY/AoFP+nw==", 16,
      "\x8e\xa2\xc2\x21\x8f\xc0\xa0\x53\xfe\x9f", 10),
    T("f6TFC3wyDY97B3I=", 16,
      "\x7f\xa4\xc5\x0b\x7c\x32\x0d\x8f\x7b\x07\x72", 11),
    T("rvXifip9uCnkr9O+", 16,
      "\xae\xf5\xe2\x7e\x2a\x7d\xb8\x29\xe4\xaf\xd3\xbe", 12),
    T("vRpjbwqE0z9yOsiGqw==", 20,
      "\xbd\x1a\x63\x6f\x0a\x84\xd3\x3f\x72\x3a\xc8\x86\xab", 13),
    T("0KpJWg8yqjjBg4Twchk=", 20,
      "\xd0\xaa\x49\x5a\x0f\x32\xaa\x38\xc1\x83\x84\xf0\x72\x19", 14),
    T("ZGaKhhQqN5NBnBemHCjE", 20,
      "\x64\x66\x8a\x86\x14\x2a\x37\x93\x41\x9c\x17\xa6\x1c\x28\xc4", 15),
    T("zi9G4vhVEnQmdErSRxjb7w==", 24,
      "\xce/\x46\xe2\xf8\x55\x12\x74\x26\x74\x4a\xd2\x47\x18\xdb\xef", 16),

    T("SktOQkl5KComVHVpZ3M5ZDg3dGY5czd1aWc0aSomKFRTSSkoRipERylPKCpnOQ==", 64,
      "JKNBIy(*&Tuigs9d87tf9s7uig4i*&(TSI)(F*DG)O(*g9", 46),

    T("AA==", 4, "\x00", 1),
    T("AAA=", 4, "\x00\x00", 2),
    T("AAAA", 4, "\x00\x00\x00", 3)
};
#define B64UT_MAX_RESULT 64

static const unsigned int block_sizes[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ,13, 14, 15, 16,
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
};

static void
b64_decode_static(void)
{
    b64_t b;
    unsigned i = 0;
    uint8_t result[B64UT_MAX_RESULT];
    for (; i < NUME(tests); ++i) {
        unsigned j = 0;
        assert(tests[i].dec.len <= B64UT_MAX_RESULT);
        for (j = 0; j < NUME(block_sizes); ++j) {
            unsigned k = 0;
            unsigned ibs = block_sizes[j];
            for (k = 0; k < NUME(block_sizes); ++k) {
                unsigned obs = block_sizes[k], idx = 0;
                unsigned in_len = tests[i].t.len;
                unsigned read = 0, written = 0;
                size_t o_len = obs;
                uint8_t *output = calloc(1, obs), *res = result;
                assert(output);
                memset(result, 0x0, sizeof result);
                b64_init(&b);

                if (in_len && ibs > in_len) ibs = in_len;

                for (idx = 0; idx < in_len/ibs; ++idx) {
                    unsigned lr = 0, r = 0;
                    do {
                    o_len = obs;
                    r = b64_decode(&b, tests[i].t.data + read,
                                   in_len - read > ibs - lr ?
                                   ibs - lr : in_len -read,
                                   output, &o_len);
                    memcpy(res + written, output, o_len);
                    lr += r;
                    read += r;
                    written += o_len;
                    } while (lr < ibs);
                }
                if (in_len % ibs) {
                    unsigned lr = 0, r = 0, left = in_len - read;
                    do {
                    o_len = obs;
                    r = b64_decode(&b, tests[i].t.data + read,
                                   in_len - read, output, &o_len);
                    memcpy(res + written, output, o_len);
                    lr += r;
                    read += r;
                    written += o_len;
                    } while (lr < left);
                }
                free(output);
                assert(tests[i].t.len == read);
                assert(tests[i].dec.len == written);
                assert(memcmp(result, tests[i].dec.data, written) == 0);
            }
        }
    }
}

static void
b64_encode_static(void)
{
    b64_t b;
    unsigned i = 0;
    uint8_t result[B64UT_MAX_RESULT];
    for (; i < NUME(tests); ++i) {
        unsigned j = 0;
        assert(tests[i].enc.len <= B64UT_MAX_RESULT);
        for (j = 0; j < NUME(block_sizes); ++j) {
            unsigned k = 0;
            unsigned ibs = block_sizes[j];
            for (k = 0; k < NUME(block_sizes); ++k) {
                unsigned obs = block_sizes[k], idx = 0;
                unsigned in_len = tests[i].dec.len;
                unsigned read = 0, written = 0;
                size_t o_len = obs;
                uint8_t *output = calloc(1, obs), *res = result;
                assert(output);
                memset(result, 0x0, sizeof result);
                b64_init(&b);

                if (in_len && ibs > in_len) ibs = in_len;

                for (idx = 0; idx < in_len/ibs; ++idx) {
                    unsigned lr = 0, r = 0;
                    do {
                    o_len = obs;
                    r = b64_encode(&b, tests[i].dec.data + read,
                                   in_len - read > ibs - lr ?
                                   ibs - lr : in_len -read,
                                   output, &o_len);
                    memcpy(res + written, output, o_len);
                    lr += r;
                    read += r;
                    written += o_len;
                    } while (lr < ibs);
                }
                if (in_len % ibs) {
                    unsigned lr = 0, r = 0, left = in_len - read;
                    do {
                    o_len = obs;
                    r = b64_encode(&b, tests[i].dec.data + read,
                                   in_len - read, output, &o_len);
                    memcpy(res + written, output, o_len);
                    lr += r;
                    read += r;
                    written += o_len;
                    } while (lr < left);
                }
                do {
                    o_len = b64_finish(&b, output, obs);
                    memcpy(res + written, output, o_len);
                    written += o_len;
                } while (o_len);
                free(output);
                assert(tests[i].dec.len == read);
                assert(tests[i].enc.len == written);
                assert(memcmp(result, tests[i].enc.data, written) == 0);
            }
        }
    }
}

static void
b64_encode_zero(void)
{
    b64_t b;
    b64_init(&b);
    size_t olen = 0;
    assert(0 == b64_encode(&b, NULL, 0, NULL, &olen));
    assert(0 == olen);
    b.state = 3; /* REMAINING BYTES */
    assert(0 == b64_encode(&b, NULL, 0, NULL, &olen));
    assert(0 == olen);
    assert(0 == b64_finish(&b, NULL, 0));
}

static void
b64_decode_zero(void)
{
    b64_t b;
    b64_init(&b);
    size_t olen = 0;
    assert(0 == b64_decode(&b, NULL, 0, NULL, &olen));
    assert(0 == olen);
}

static void
b64_finish_out_grow(void)
{
    uint8_t o[3];
    size_t olen = 1;
    b64_t b;
    b64_init(&b);
    b.state = 1;
    b.acc = 0;
    assert(1 == b64_finish(&b, o, olen));
    olen = 2;
    assert(2 == b64_finish(&b, o, olen));
}

static void
b64_invalid_states(void)
{
    uint8_t i[1], o[1];
    size_t olen = 1;
    b64_t b;
    b64_init(&b);
    b.state = 0xde|0xea|0xd;
    assert(1 == b64_decode(&b, i, 1, o, &olen));
    assert(0 == olen);
    olen = 1;
    i[0] = 'Q';
    assert(1 == b64_decode(&b, i, 1, o, &olen));
    assert(0 == olen);
    olen = 1;
    i[0] = '=';
    assert(1 == b64_decode(&b, i, 1, o, &olen));
    assert(0 == olen);
    olen = 1;
    assert(1 == b64_encode(&b, i, 1, o, &olen));
    assert(0 == olen);
    olen = 1;
    assert(0 == b64_finish(&b, o, olen));
}

int
main(int argc, char **argv)
{
    b64_decode_static();
    b64_encode_static();
    b64_decode_zero();
    b64_encode_zero();
    b64_finish_out_grow();
    b64_invalid_states();
    return 0;
}
