
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

typedef struct {
    u32 recip;
    u16 orig;
    u8 shift;
} modt;

#define VEC_LENMAX 111
#define VEC_LIMIT 16384
typedef struct {
    u16 nlower;
    u16 nbytes;
    u8 nS[(VEC_LENMAX+1) >> 1];
    modt M[VEC_LENMAX];
} vclayer;
#define VEC_MAXLAYERS 9
#if (VEC_LENMAX) >= (1 << ((VEC_MAXLAYERS)-2))
#error VEC_MAXLAYERS is too small
#endif
typedef struct {
    vclayer layers[VEC_MAXLAYERS];
} vct;

msv NS(mod_init_)(modt *m, u16 v);
MAYBE_STATIC u32 NS(moddiv_)(const modt *m, u32 *pq, u32 v);
#define mod_init(m,v) NS(mod_init_)(&(m),(v))
#define moddiv(m,q,v) NS(moddiv_)(&(m), &(q), (v))
#define mod(m, v) NS(moddiv_)(&(m), NULL, (v))

msv NS(vc_init_)(vct *vc, const u16 M[], u16 Mlen);
MAYBE_STATIC unsigned int NS(vc_nS_)(const vct *vc);
msv NS(vc_encode_)(const vct *vc, u8 S[], u16 R[]);
msv NS(vc_decode_)(const vct *vc, u16 R[], const u8 S[]);
#define vc_init(vc, M, Mlen) NS(vc_init_)(&(vc), (M), (Mlen))
#define vc_nS(vc) NS(vc_nS_)(&(vc))
#define vc_encode(vc, S, R) NS(vc_encode_)(&(vc), (S), (R))
#define vc_decode(vc, R, S) NS(vc_decode_)(&(vc), (R), (S))
