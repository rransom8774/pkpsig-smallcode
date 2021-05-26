
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include <stddef.h>
#include <stdint.h>

#define FOR(i,n) for(i=0; i<n; ++i)
#define sv static void

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifdef MINIPKPSIG_SINGLEFILE
#define MAYBE_STATIC static
#else
#define MAYBE_STATIC
#endif

#define msv MAYBE_STATIC void
#define NS(fname) minipkpsig_##fname
