
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "minipkpsig-common.h"
#include "minipkpsig-modvc.h"
#include "minipkpsig-symtypes.h"
#include "minipkpsig-pstypes.h"
#include "minipkpsig-paramsets-auto.h"
#include "minipkpsig-seclevels-auto.h"
#include "minipkpsig-treehash-auto.h"
#include "minipkpsig-sig-common.h"
#include "minipkpsig-sig-thsort.h"
#include "minipkpsig-sig-verify.h"

#include <string.h>

#ifndef MINIPKPSIG_SINGLEFILE
extern slt seclevels[];
extern ppst pkp_paramsets[];
extern symt symalgs[];
extern pst paramsets[];
#endif

#ifdef MINIPKPSIG_SORT_DEBUG
#include <assert.h>
#endif

msv NS(th_sort_verifyC1)(tht *th) {
    int i, nrt = (th->n_blocks >> 1);

    /* th->sortkeys is almost sorted, except that for each i, key 2*i
     * may be swapped with 2*i + 1.  Use th_minmax_ct directly to fix
     * their order. */

    for (i = 0; i < nrt; ++i) {
        th_minmax_ct(th, 2*i, 2*i + 1);
    }
}
#define th_sort_verifyC1 NS(th_sort_verifyC1)

#ifdef MINIPKPSIG_SORT_DEBUG
typedef void (*sort_debug_cb)(tht *th, int nrs, int mergelen_l2, int chunkstart);
static sort_debug_cb verifyC2_debug_cb = NULL;
void NS(th_set_sort_debug_cb)(sort_debug_cb cb) {
    verifyC2_debug_cb = cb;
}
sv verifyC2_debug(tht *th, int nrs, int mergelen_l2, int chunkstart) {
    if (verifyC2_debug_cb != NULL) {
        return verifyC2_debug_cb(th, nrs, mergelen_l2, chunkstart);
    }
}
#else
#define verifyC2_debug(th, nrs, mergelen_l2, chunkstart) /* no-op */
#endif

msv NS(th_sort_verifyC2)(tht *th, const pst *ps) {
    /* th->sortkeys is almost sorted, except that there are two sorted
     * subsequences, one at indices from 0 to nrs-1 and one at indices
     * from nrs to nrt-1.  We can optimize Batcher's odd-even merging
     * network for this case: only perform sorting on the aligned
     * power-of-two blocks that are not already sorted.
     *
     * A chunk of the array needs to be sorted if and only if it contains
     * the boundary between the short-proof runs and long-proof runs, i.e.
     * the boundary between element nrs-1 and nrs.  Only one chunk per
     * merge layer needs to be sorted. */

    /* nrt (number of runs total) must have been computed by the caller. */
    const int nrt = th->n_blocks, nrs = nrt - ps->nrl;

    int mergelen_l2 = 1, mergelen = 1 << mergelen_l2;
    int mergemask = mergelen - 1, chunkstart = nrs & ~mergemask;

    verifyC2_debug(th, nrs, 0, nrs);

    while ((chunkstart != 0) || (mergelen < nrt)) {
        if (chunkstart != nrs) {
            th_merge_seqs(th, mergelen_l2, chunkstart);
        }
        verifyC2_debug(th, nrs, mergelen_l2, chunkstart);

        /* increment mergelen_l2 and set all derived vars accordingly */
        ++mergelen_l2; mergelen += mergelen;
        mergemask += mergemask+1, chunkstart = nrs & ~mergemask;
    }

    th_merge_seqs(th, mergelen_l2, chunkstart);
    verifyC2_debug(th, nrs, mergelen_l2, chunkstart);
}
#define th_sort_verifyC2 NS(th_sort_verifyC2)

MAYBE_STATIC int NS(svs_set_signature)(sigverifystate *vst, const u8 *sig, size_t len) {
    const int ksl_cbytes = vst->cst.ksl.cbytes;
    const int ksl_pbytes = vst->cst.ksl.pbytes;
    const int ssl_cbytes = vst->cst.ssl.cbytes;
    const int ssl_pbytes = vst->cst.ssl.pbytes;
    const int nrt = vst->cst.ps.nrtx + ssl_pbytes*8;
    const int nrs = nrt - vst->cst.ps.nrl;

    if (scs_get_sig_bytes(&(vst->cst)) != len) return -1;

    memcpy(vst->cst.salt_and_msghash, sig, ksl_cbytes);
    memcpy(vst->cst.h_C1, sig + ksl_cbytes, ssl_cbytes);
    memcpy(vst->cst.h_C2, sig + ksl_cbytes + ssl_cbytes, ssl_cbytes);

    vst->blindingseeds = sig + ksl_cbytes + ssl_cbytes*2;
    vst->longproofs = vst->blindingseeds + ksl_pbytes*nrs;

    return 0;
}

