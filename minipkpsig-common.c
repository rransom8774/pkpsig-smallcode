
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "minipkpsig-common.h"

MAYBE_STATIC u32 NS(u32le_get)(const u8 *p) {
  return (( ((u32)p[0])       ) +
          ((((u32)p[1]) <<  8)) +
          ((((u32)p[2]) << 16)) +
          ((((u32)p[3]) << 24)));
};
#define u32le_get NS(u32le_get)

msv NS(u32le_put)(u8 *buf, u32 x) {
  buf[0] =  x        & 255;
  buf[1] = (x >>  8) & 255;
  buf[2] = (x >> 16) & 255;
  buf[3] = (x >> 24) & 255;
};
#define u32le_put NS(u32le_put)

