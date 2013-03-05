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

/** \file b64.h */

#ifndef B64_H__
#define B64_H__

#include <stdint.h>
#include <stddef.h>

typedef struct b64 {
    uint8_t state;
    uint8_t acc;
} b64_t;

/** Initialize the b64 state */
void   b64_init(b64_t *);

/** Decode base64 data
 *  \return Number of bytes read from \a data
 */
size_t b64_decode(b64_t *,
                  const uint8_t *data,  /**<[in] data to encode */
                  size_t len,           /**< length of input \a data */
                  uint8_t *out,         /**<[out] output buffer */
                  size_t *olen          /**<[in,out] available space in \a out;
                                         * bytes written to \a out */
                 );

/** Encode data into base64
 *  \return Number of bytes read from \a data
 */
size_t b64_encode(b64_t *,
                  const uint8_t *data,  /**<[in] data to encode */
                  size_t len,           /**< length of input \a data */
                  uint8_t *out,         /**<[out] output buffer */
                  size_t *olen          /**<[in,out] available space in \a out;
                                         * bytes written to \a out */
                 );

/** Finish the base64 encoding process.
 *  Outputs the final byte and required padding.
 *  \return Number of bytes written to \a out
 */
size_t b64_finish(b64_t *,
                  uint8_t *out, /**<[out] output buffer for remaining bytes */
                  size_t olen   /**< available space in \a out */
                 );

#endif
