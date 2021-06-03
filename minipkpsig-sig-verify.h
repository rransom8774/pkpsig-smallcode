
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
} sigverifystate;

msv NS(memcswap_ct)(u8 *px, u8 *py, size_t len, int flag);
msv NS(th_minmax_ct)(tht *th, int i, int j);
#define memcswap_ct NS(memcswap_ct)
#define th_minmax_ct NS(th_minmax_ct)

msv NS(th_merge_seqs)(tht *th, int mergelen_l2, int off);
#define th_merge_seqs NS(th_merge_seqs)

msv NS(th_sort_verifyC1)(tht *th);
msv NS(th_sort_verifyC2)(tht *th, const pst *ps);
msv NS(th_sort_keys_full)(tht *th);
#define th_sort_verifyC1 NS(th_sort_verifyC1)
#define th_sort_verifyC2 NS(th_sort_verifyC2)
#define th_sort_keys_full NS(th_sort_keys_full)

