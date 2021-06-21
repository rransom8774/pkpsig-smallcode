
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "minipkpsig.h"

#define FOR(i,n) for(i=0; i<n; ++i)
#define sv static void

#ifdef MINIPKPSIG_SINGLEFILE
#define MAYBE_STATIC static
#else
#define MAYBE_STATIC
#endif

#define msv MAYBE_STATIC void
#define NS(fname) minipkpsig_##fname

typedef struct {
    void *p;
    size_t bytes;
} NS(chunkt);

msv NS(u16le_put)(uint8_t *buf, uint16_t x);
#define u16le_put NS(u16le_put)

MAYBE_STATIC u32 NS(u32le_get)(const u8 *p);
msv NS(u32le_put)(uint8_t *buf, uint32_t x);
#define u32le_get NS(u32le_get)
#define u32le_put NS(u32le_put)

