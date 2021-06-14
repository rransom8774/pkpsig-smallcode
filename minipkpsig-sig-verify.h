
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

typedef struct {
    sigcommonstate cst;

    const u8 *blindingseeds;
    const u8 *longproofs;
} sigverifystate;

msv NS(th_sort_verifyC1)(tht *th);
msv NS(th_sort_verifyC2)(tht *th, const pst *ps);
#define th_sort_verifyC1 NS(th_sort_verifyC1)
#define th_sort_verifyC2 NS(th_sort_verifyC2)

MAYBE_STATIC int NS(svs_set_signature)(sigverifystate *vst, const u8 *sig, size_t len);
#define svs_set_signature NS(svs_set_signature)

