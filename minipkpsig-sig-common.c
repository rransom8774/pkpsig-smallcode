
/*
 * Authors: Robert Ransom, Samuel Neves (ct_lt_u32 function)
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "minipkpsig-common.h"
#include "minipkpsig-symtypes.h"
#include "minipkpsig-pstypes.h"
#include "minipkpsig-paramsets-auto.h"
#include "minipkpsig-seclevels-auto.h"
#include "minipkpsig-treehash-auto.h"
#include "minipkpsig-sig-common.h"

#include <stdio.h>
#include <string.h>

#ifndef MINIPKPSIG_SINGLEFILE
extern slt seclevels[];
extern ppst pkp_paramsets[];
extern symt symalgs[];
extern pst paramsets[];
#endif

static int strheadmatch(const char *head, const char *s) {
    size_t len = strlen(head);
    size_t lens = strlen(s);
    if (lens < len) return 0;
    return !memcmp(head, s, len);
}

#define ps (*(ps_ptr))

MAYBE_STATIC int NS(ps_lookup_)(pst *ps_ptr, const char *name) {
    char buf[32];
    u8 pps;
    u8 sym;
    u8 ssl;
    int i;

    FOR(pps, N_PKP_PARAMSETS) {
        const ppst *pc = &(pkp_paramsets[pps]);
        snprintf(buf, sizeof(buf), "q%dn%dm%dk%s-",
                 pc->q, pc->n, pc->m, seclevels[pc->ksl].name);
        if (strheadmatch(buf, name)) {
            name += strlen(buf);
            break;
        }
    }
    if (pps == N_PKP_PARAMSETS) return -1;

    FOR(sym, N_SYMALGS) {
        const char *symname = symalgs[sym].name;
        snprintf(buf, sizeof(buf), "%s-s", symname);
        if (strheadmatch(symname, name)) {
            name += strlen(buf);
            break;
        }
    }
    if (symalgs[sym].xof_chunked == NULL) return -1;
    if (symalgs[sym].maxsl < pkp_paramsets[pps].ksl) return -1;

    FOR(ssl, N_SECLEVELS) {
        if (strcmp(seclevels[ssl].name, name) == 0) break;
    }
    if (ssl == N_SECLEVELS) return -1;

    FOR(i, N_PARAMSETS) {
        const pst *pc = &(paramsets[i]);
        if (pc->pps == pps && pc->ssl == ssl) {
            ps = *pc;
            ps.sym = sym;
            return 0;
        }
    }
    return -1;
}
#define ps_lookup(ps_, name) NS(ps_lookup_)(&(ps_), (name))

MAYBE_STATIC int NS(ps_enum_names)(NS(enum_names_cb) cb, void *cbdata) {
    char buf[64];
    int rv, i;
    u8 isym, pps;
    FOR(isym, N_SYMALGS) {
        FOR(i, N_PARAMSETS) {
            const pst *ps_ptr = &(paramsets[i]);
            const ppst *pps = &(pkp_paramsets[ps.pps]);
            const symt *sym = &(symalgs[isym]);
            const slt *ksl = &(seclevels[pps->ksl]),
                *ssl = &(seclevels[ps.ssl]);

            if (sym->maxsl < pps->ksl) continue;

            snprintf(buf, sizeof(buf), "q%dn%dm%dk%s-%s-s%s",
                     pps->q, pps->n, pps->m, ksl->name,
                     sym->name,
                     ssl->name);
            rv = cb(cbdata, buf);
            if (rv != 0) return rv;
        }
    }
    return 0;
}
#define ps_enum_names NS(ps_enum_names)

#undef ps

/* two partial versions of Batcher's odd-even merge sort */

msv NS(memcswap_ct)(u8 *px, u8 *py, size_t len, int flag) {
    u8 swapmask = -flag; /* flag must be 0 or 1 */
    size_t i;
    for(i = 0; i < len; ++i) {
        u8 x = px[i], y = py[i];
        u8 z = (x ^ y) & swapmask;
        x ^= z; y ^= z;
        px[i] = x; py[i] = y;
    }
}
#define memcswap_ct NS(memcswap_ct)

/* copied from https://gist.github.com/sneves/10845247;
 * author Samuel Neves, license CC0 */
static int ct_lt_u32(uint32_t x, uint32_t y)
{
    return (x^((x^y)|((x-y)^y)))>>31;
}

msv NS(th_minmax_ct)(tht *th, int i, int j) {
    size_t lb = th->leaf_bytes;
    u32 ki = th->sortkeys[i], kj = th->sortkeys[j];
    int flag = ct_lt_u32(kj, ki); /* note order */
    u32 swapmask = -(u32)flag;
    u32 z = (ki^kj) & swapmask;
    ki ^= z; kj ^= z;
    th->sortkeys[i] = ki; th->sortkeys[j] = kj;
    memcswap_ct(th->leaves + i*lb, th->leaves + j*lb, lb, flag);
}
#define th_minmax_ct NS(th_minmax_ct)

/* Given two sorted sequences of length baselen := 1<<(mergelen_l2-1)
 * starting at indices off and off+baselen, merge them into one sorted
 * sequence of length 1<<mergelen_l2, in data-independent time. */
msv NS(th_merge_seqs)(tht *th, int mergelen_l2, int off) {
    int merge_layer, /* step within the merge; counts down */
        stride,      /* distance between minmax endpoints */
        chunkstart,  /* start of a chunk of conditional swaps */
        firstchunk,  /* start of the first chunk within the layer */
        icswap;      /* index of the current cswap after chunkstart */
    int n = th->n_blocks - off, mergelen = (1<<mergelen_l2);
    if (n <= 0) return;
    if (n > mergelen) n = mergelen;

    for (merge_layer = mergelen_l2 - 1, firstchunk=0, stride = 1<<merge_layer;
         merge_layer >= 0;
         --merge_layer, firstchunk = stride = 1<<merge_layer) {

        for (chunkstart = firstchunk;
             chunkstart + stride < n;
             chunkstart += stride<<1) {

            for (icswap = 0; icswap < stride && icswap+stride < n; ++icswap) {
                th_minmax_ct(th, off+chunkstart+icswap,
                             off+chunkstart+icswap+stride);
            }
        }
    }
}
#define th_merge_seqs NS(th_merge_seqs)

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

    while ((chunkstart != 0) || (nrt != nrt && mergemask)) {
        if (chunkstart != nrs) {
            th_merge_seqs(th, mergelen_l2, chunkstart);
        }

        /* increment mergelen_l2 and set all derived vars accordingly */
        ++mergelen_l2; mergelen += mergelen;
        mergemask += mergemask+1, chunkstart = nrs & ~mergemask;
    }

    th_merge_seqs(th, mergelen_l2, chunkstart);
}
#define th_sort_verifyC2 NS(th_sort_verifyC2)

