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

static uint8_t _b64_table[64] = {
        0X41,0X42,0X43,0X44,0X45,0X46,0X47,0X48,
        0X49,0X4A,0X4B,0X4C,0X4D,0X4E,0X4F,0X50,
        0X51,0X52,0X53,0X54,0X55,0X56,0X57,0X58,
        0X59,0X5A,0X61,0X62,0X63,0X64,0X65,0X66,
        0X67,0X68,0X69,0X6A,0X6B,0X6C,0X6D,0X6E,
        0X6F,0X70,0X71,0X72,0X73,0X74,0X75,0X76,
        0X77,0X78,0X79,0X7A,0X30,0X31,0X32,0X33,
        0X34,0X35,0X36,0X37,0X38,0X39,0X2B,0X2F
};

static uint8_t _ub64_table[256] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0x3E,0xFF,0xFF,0xFF,0x3F,
        0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,
        0x3C,0x3D,0xFF,0xFF,0xFF,0xC0,0xFF,0xFF,
        0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,
        0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
        0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
        0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,
        0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF,

        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

enum b64_state {
    B64_S0 = 0,
    B64_S1,
    B64_S2,
    B64_S3,
    B64_S4,
    B64_S5,
};

void
b64_init(b64_t *bctx)
{
    bctx->state = bctx->acc = 0;
}

size_t
b64_decode(b64_t *bctx, const uint8_t *data, size_t len,
           uint8_t *out, size_t *olen)
{
    size_t i = 0, ol = *olen, written = 0;
    size_t acc = bctx->acc;
    enum b64_state state = bctx->state;
    for (; i < len && written < ol; ++i) {
        uint8_t c = _ub64_table[data[i]];
        switch (c) {
        case 0xff: break;
        case 0xc0: /* = */
            switch (state) {
            case B64_S2: /* Expecting Third Char */
                state = B64_S4; break;
            case B64_S3: /* Expecting Fourth Char */
                /* fall through */
            case B64_S4: /* Equals 1 */
                state = acc = B64_S0; break;
            default: break;
            }
        break;
        default:
            switch (state) {
            case B64_S0: /* Expecting First char */
                acc = c << 2;
                state = B64_S1;
            break;
            case B64_S1: /* Expecting Second char */
                out[written] = acc | ((c & 0x30) >> 4);
                ++written;
                acc =  (c & 0x0f) << 4;
                state = B64_S2;
            break;
            case B64_S2: /* Expecting Third char */
                out[written] = acc | ((c & 0x3c) >> 2);
                ++written;
                acc =  (c & 0x03) << 6;
                state = B64_S3;
            break;
            case B64_S3: /* Expecting Fourth char */
                out[written] = acc | (c & 0x3f);
                ++written;
                acc =  0;
                state = B64_S0;
            break;
            default: break;
            }
        break;
        }
    }
    bctx->acc   = acc;
    bctx->state = state;
    *olen = written;
    return i;
}

size_t
b64_encode(b64_t *bctx, const uint8_t *data, size_t len,
           uint8_t *out, size_t *olen)
{
    size_t i = 0, ol = *olen, written = 0;
    size_t acc = bctx->acc;
    enum b64_state state = bctx->state;
    if (B64_S3 == state && ol > 0) { /* Remaining Bytes */
        *out = _b64_table[acc];
        written = 1;
        state = B64_S0;
        acc =  0;
    }
    for (; i < len && written < ol; ++i) {
        uint8_t c = data[i];
        switch (state) {
        case B64_S0: /* Expecting First char */
            out[written] = _b64_table[c >> 2];
            ++written;
            acc = (c & 0x03) << 4;
            state = B64_S1;
        break;
        case B64_S1: /* Expecting Second char */
            out[written] = _b64_table[acc | ((c & 0xf0) >> 4)];
            ++written;
            acc = (c & 0x0f) << 2;
            state = B64_S2;
        break;
        case B64_S2: /* Expecting Third char */
            out[written] = _b64_table[acc | ((c & 0xc0) >> 6)];
            ++written;
            if (written < ol) {
                out[written] = _b64_table[c & 0x3f];
                ++written;
                state = B64_S0;
                acc =  0;
            } else {
                acc = c & 0x3f;
                state = B64_S3;
            }
        break;
        default: break;
        }
    }
    bctx->acc   = acc;
    bctx->state = state;
    *olen = written;
    return i;
}

size_t
b64_finish(b64_t *bctx, uint8_t *out, size_t olen)
{
    size_t len = 0;
    enum b64_state state = bctx->state;
    if (!olen) return 0;
    switch (state) {
    case B64_S1: /* Output with two pad char */
        out[0] = _b64_table[bctx->acc];
        len = 1;
        if (olen < 2) { bctx->state = B64_S4; break; }
        out[1] = '=';
        len = 2;
        if (olen < 3) { bctx->state = B64_S5; break; }
        out[2] = '=';
        len = 3;
        bctx->state = B64_S0;
    break;
    case B64_S2: /* Output with one pad char */
        out[0] = _b64_table[bctx->acc];
        len = 1;
        if (olen < 2) { bctx->state = B64_S5; break; };
        out[1] = '=';
        len = 2;
        bctx->state = B64_S0;
    break;
    case B64_S3: /* Output with no pad char */
        out[0] = _b64_table[bctx->acc];
        len = 1;
        bctx->state = B64_S0;
    break;
    case B64_S4: /* Two pad char */
        out[0] = '=';
        len = 1;
        if (olen < 2) { bctx->state = B64_S5; break; };
        out[1] = '=';
        len = 2;
        bctx->state = B64_S0;
    break;
    case B64_S5: /* One pad char */
        out[0] = '=';
        len = 1;
        bctx->state = B64_S0;
    break;
    default: break;
    }
    return len;
}

