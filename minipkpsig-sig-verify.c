
/*
 * Authors: Robert Ransom, Samuel Neves (ct_isnonzero_u32 function, CC0)
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

msv NS(svs_init)(sigverifystate *vst, const pst *ps) {
    memset(vst, 0, sizeof(*vst));
    scs_init(&(vst->cst), ps);
}

msv NS(svs_set_signature)(sigverifystate *vst, const u8 *sig) {
    const int ksl_cbytes = vst->cst.ksl.cbytes;
    const int ksl_pbytes = vst->cst.ksl.pbytes;
    const int ssl_cbytes = vst->cst.ssl.cbytes;
    const int ssl_pbytes = vst->cst.ssl.pbytes;
    const int nrt = vst->cst.ps.nrtx + ssl_pbytes*8;
    const int nrs = nrt - vst->cst.ps.nrl;

    memcpy(vst->cst.salt_and_msghash, sig, ksl_cbytes);
    memcpy(vst->cst.h_C1, sig + ksl_cbytes, ssl_cbytes);
    memcpy(vst->cst.h_C2, sig + ksl_cbytes + ssl_cbytes, ssl_cbytes);

    vst->coms = sig + ksl_cbytes + ssl_cbytes*2;
    vst->blindingseeds = vst->coms + ssl_cbytes*nrt;
    vst->longproofs = vst->blindingseeds + ksl_pbytes*nrs;
}

msv NS(svs_recover_run_indexes)(sigverifystate *vst) {
    const int ksl_pbytes = vst->cst.ksl.pbytes;
    const int ssl_cbytes = vst->cst.ssl.cbytes;
    const int ssl_pbytes = vst->cst.ssl.pbytes;
    const int nrt = vst->cst.ps.nrtx + ssl_pbytes*8,
        nrl = vst->cst.ps.nrl, nrs = nrt - nrl;
    int i;

    FOR(i, nrt) {
        u32 H = vst->cst.Hbuf[i];
        vst->cst.th.sortkeys[i] = (((H & 0x8000) + i) << 16) + H;
    }

    vst->cst.th.n_blocks = nrt;
    th_sort_keys_full(&(vst->cst.th));

    FOR(i, nrt) {
        u32 sk = vst->cst.th.sortkeys[i];
        vst->run_indexes[i] = ((sk >> 16) & 0x7FFF);
        vst->Hbuf_reordered[i] = (sk & 0xFFFF);
    }
}

sv NS(unsquish_permutation)(u16 *sigma, int n) {
    int i, j;
    i = n;
    sigma[n-1] = 0;
    while (i != 0) {
        int s_i;
        --i;
        s_i = sigma[i];
        for (j = i+1; j < n; ++j) {
            if (sigma[j] >= s_i) ++(sigma[j]);
        }
    }
}

msv NS(svs_process_long_proofs)(sigverifystate *vst) {
    size_t nS_z = vc_nS(vst->cst.vcz), nS_sigma = vc_nS(vst->cst.vcsigma),
        nS = nS_z + nS_sigma;
    const int ksl_cbytes = vst->cst.ksl.cbytes;
    const int ksl_pbytes = vst->cst.ksl.pbytes;
    const int ssl_cbytes = vst->cst.ssl.cbytes;
    const int ssl_pbytes = vst->cst.ssl.pbytes;
    const int nrt = vst->cst.ps.nrtx + ssl_pbytes*8,
        nrl = vst->cst.ps.nrl, nrs = nrt - nrl;
    const int n = vst->cst.pps.n, m = vst->cst.pps.m;
    int i, j;
    u16 sigma_buf[PKPSIG_MAX_N];
    u16 z_sigma_inv[PKPSIG_MAX_N];
    u8 sigma[PKPSIG_MAX_N];
    u8 hashctx = HASHCTX_COMMITMENT;
    u8 runidxbuf[4];
    NS(chunkt) out[1] = {{NULL, ssl_cbytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {vst->cst.salt_and_msghash, ksl_cbytes*2},
        {runidxbuf, 4},
        {sigma, n},
        {vst->cst.hashbuf, m*2},
        {NULL, 0}
    };

    FOR(i, nrl) {
        u32 alpha = (vst->Hbuf_reordered[i+nrs] & 0x7FFF);
        u32 neg_alpha = vst->cst.pps.q - alpha;

        vc_decode(vst->cst.vcz, vst->z[i+nrs], vst->longproofs + i*nS);
        vc_decode(vst->cst.vcsigma, sigma_buf, vst->longproofs + i*nS + nS_z);
        NS(unsquish_permutation)(sigma_buf, n);
        FOR(j, n) sigma[j] = sigma_buf[j];

        u32le_put(runidxbuf, vst->run_indexes[i+nrs]);

        scs_apply_perm_inv(&(vst->cst), z_sigma_inv, vst->z[i+nrs], sigma);
        scs_mult_by_A(&(vst->cst), z_sigma_inv);
        FOR(j, m) {
            u32 Ar_j = vst->cst.multbuf[j] + neg_alpha*vst->cst.w[j];
            Ar_j = scs_mod_q(&(vst->cst), Ar_j);
            u16le_put(vst->cst.hashbuf + 2*j, Ar_j);
        }

        out->p = vst->coms_recovered[i+nrs];
        vst->cst.xof(out, in);
    }
}

msv NS(svs_recover_commitments_short)(sigverifystate *vst) {
    const int ksl_cbytes = vst->cst.ksl.cbytes;
    const int ksl_pbytes = vst->cst.ksl.pbytes;
    const int ssl_cbytes = vst->cst.ssl.cbytes;
    const int ssl_pbytes = vst->cst.ssl.pbytes;
    const int nrt = vst->cst.ps.nrtx + ssl_pbytes*8,
        nrl = vst->cst.ps.nrl, nrs = nrt - nrl;
    const int n = vst->cst.pps.n;
    int i, j;
    u16 r_sigma[PKPSIG_MAX_N];
    u8 pi_sigma_inv[PKPSIG_MAX_N];

    FOR(i, nrs) {
        u32 alpha = (vst->Hbuf_reordered[i] & 0x7FFF);
        scs_expand_blindingseed(&(vst->cst), r_sigma, pi_sigma_inv,
                vst->coms_recovered[i], vst->blindingseeds + i*ksl_pbytes,
                vst->run_indexes[i], 0);
        scs_apply_perm_inv(&(vst->cst), vst->z[i], vst->cst.v, pi_sigma_inv);
        FOR(j, n) {
            u32 zj = r_sigma[j] + vst->z[i][j]*alpha;
            vst->z[i][j] = scs_mod_q(&(vst->cst), zj);
        }
    }
}

MAYBE_STATIC int NS(svs_verify_C2)(sigverifystate *vst) {
    const int ksl_cbytes = vst->cst.ksl.cbytes;
    const int ssl_cbytes = vst->cst.ssl.cbytes;
    const int ssl_pbytes = vst->cst.ssl.pbytes;
    const int nrt = vst->cst.ps.nrtx + ssl_pbytes*8,
        nrl = vst->cst.ps.nrl, nrs = nrt - nrl;
    const int n = vst->cst.pps.n;
    int i, j;
    size_t zbytes = n*2;

    th_init(&(vst->cst.th), &(vst->cst.ps));

    memcpy(vst->cst.th.prefix, vst->cst.salt_and_msghash, ksl_cbytes*2);
    vst->cst.th.prefix_bytes = ksl_cbytes*2;

    vst->cst.th.n_blocks = nrt;
    vst->cst.th.leaf_bytes = zbytes;
    vst->cst.th.hashctx = HASHCTX_CHALLENGE2HASH;

    /* copy z into th.leaves */
    FOR(i, nrt) FOR(j, n) {
        u16le_put(vst->cst.th.leaves + zbytes*i + 2*j, vst->z[i][j]);
    }

    /* prehash */
    FOR(i, nrt) vst->cst.th.sortkeys[i] = vst->run_indexes[i];
    th_prehash(&(vst->cst.th), ssl_cbytes);

    /* reorder z according to run_indexes */
    th_sort_verifyC2(&(vst->cst.th), &(vst->cst.ps));

    /* hash */
    th_hash(&(vst->cst.th), vst->cst.hashbuf, ssl_cbytes);

    return memverify_ct(vst->cst.hashbuf, vst->cst.h_C2, ssl_cbytes);
}

MAYBE_STATIC int NS(svs_verify_C1)(sigverifystate *vst) {
    const int ksl_cbytes = vst->cst.ksl.cbytes;
    const int ssl_cbytes = vst->cst.ssl.cbytes;
    const int ssl_pbytes = vst->cst.ssl.pbytes;
    const int nrt = vst->cst.ps.nrtx + ssl_pbytes*8,
        nrl = vst->cst.ps.nrl, nrs = nrt - nrl;
    const int n = vst->cst.pps.n, m = vst->cst.pps.m;
    int i, j;

    th_init(&(vst->cst.th), &(vst->cst.ps));

    memcpy(vst->cst.th.prefix, vst->cst.salt_and_msghash, ksl_cbytes*2);
    vst->cst.th.prefix_bytes = ksl_cbytes*2;

    vst->cst.th.hashctx = HASHCTX_CHALLENGE1HASH;
    vst->cst.th.leaf_bytes = ssl_cbytes;

    /* reorder coms_recovered according to run_indexes */
    vst->cst.th.n_blocks = nrt;
    FOR(i, nrt) {
        vst->cst.th.sortkeys[i] = vst->run_indexes[i];
        memcpy(vst->cst.th.leaves + ssl_cbytes*i,
               vst->coms_recovered[i], ssl_cbytes);
    }
    th_sort_verifyC2(&(vst->cst.th), &(vst->cst.ps));

    /* shuffle in coms and sort pairwise */
    vst->cst.th.n_blocks = 2*nrt;
    FOR(j, nrt) {
        int b;
        i = nrt-1 - j;
        b = vst->cst.Hbuf[i] >> 15;
        vst->cst.th.sortkeys[2*i] = 2*i + b;
        vst->cst.th.sortkeys[2*i + 1] = 2*i + (1-b);
        memcpy(vst->cst.th.leaves + ssl_cbytes*2*i,
               vst->cst.th.leaves + ssl_cbytes*i, ssl_cbytes);
        memcpy(vst->cst.th.leaves + ssl_cbytes*(2*i + 1),
               vst->coms + ssl_cbytes*i, ssl_cbytes);
    }
    th_sort_verifyC1(&(vst->cst.th));

    /* hash */
    th_hash(&(vst->cst.th), vst->cst.hashbuf, ssl_cbytes);

    return memverify_ct(vst->cst.hashbuf, vst->cst.h_C1, ssl_cbytes);
}

MAYBE_STATIC int NS(svs_verify)(sigverifystate *vst, const u8 *sig, const u8 *msg, size_t msglen) {
    sigcommonstate *cst = &(vst->cst);
    int rv = 0;

    svs_set_signature(vst, sig);
    scs_hash_message(cst, msg, msglen);
    scs_expand_H1(cst);
    scs_expand_H2(cst);
    svs_recover_run_indexes(vst);
    svs_process_long_proofs(vst);
    svs_recover_commitments_short(vst);
    rv |= svs_verify_C2(vst);
    rv |= svs_verify_C1(vst);

    return rv;
}

int NS(simple_detached_verify)(const char *psname, const u8 *sigin, const u8 *msg, size_t msglen, const u8 *pk) {
    sigverifystate vst;
    pst ps;
    if (ps_lookup(ps, psname) < 0) return -1;
    svs_init(&vst, &ps);
    scs_expand_pk(&(vst.cst), pk);
    return svs_verify(&vst, sigin, msg, msglen);
}

