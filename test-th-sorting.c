
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#ifdef MINIPKPSIG_SINGLEFILE
#include "minipkpsig.c"
#else
#include "minipkpsig-common.h"
#include "minipkpsig-symtypes.h"
#include "minipkpsig-pstypes.h"
#include "minipkpsig-paramsets-auto.h"
#include "minipkpsig-seclevels-auto.h"
#include "minipkpsig-treehash-auto.h"
#include "minipkpsig-sig-common.h"
#endif

#include <stdio.h>
#include <string.h>

#ifndef MINIPKPSIG_SINGLEFILE
extern slt seclevels[];
extern ppst pkp_paramsets[];
extern symt symalgs[];
extern pst paramsets[];
#endif

static tht th;
static tht *pth = &th;

static int test_memcswap_ct() {
    u8 buf[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    int rv = 0, i;

    memcswap_ct(buf, buf+8, 8, 0);
    for (i = 0; i < 16; ++i) {
        if (buf[i] != i) rv = -1;
    }
    if (rv != 0) printf("memcswap_ct failed, flag=0\n");

    memcswap_ct(buf, buf+8, 8, 1);
    for (i = 0; i < 16; ++i) {
        if (buf[i] != ((i + 8) & 15)) rv = -1;
    }
    if (rv != 0) printf("memcswap_ct failed, flag=1\n");

    return rv;
}

static int test_th_minmax_ct() {
    int rv=0, i;

    th.n_blocks = 2;
    th.leaf_bytes = 8;
    for (i = 0; i < 16; ++i) {
        th.leaves[i] = i;
    }

    th.sortkeys[0] = 0;
    th.sortkeys[1] = 1;
    th_minmax_ct(pth, 0, 1);
    if (th.sortkeys[0] != 0) rv = -1;
    if (th.sortkeys[1] != 1) rv = -1;
    for (i = 0; i < 16; ++i) {
        if (th.leaves[i] != i) rv = -1;
    }
    if (rv != 0) printf("th_minmax_ct failed, no-swap case\n");

    th.sortkeys[0] = 2;
    th.sortkeys[1] = 1;
    th_minmax_ct(pth, 0, 1);
    if (th.sortkeys[0] != 1) rv = -1;
    if (th.sortkeys[1] != 2) rv = -1;
    for (i = 0; i < 16; ++i) {
        if (th.leaves[i] != ((i+8) & 15)) rv = -1;
    }
    if (rv != 0) printf("th_minmax_ct failed, swap case\n");

    return rv;
}

static void test_th_merge_seqs_setup() {
    th.n_blocks = TH_MAX_SORT_BLOCKS;
    th.leaf_bytes = 0;

    printf("testing th_merge_seqs:");
}

static int test_th_merge_seqs_step(int mergelen_l2) {
    int mergelen = 1 << mergelen_l2;
    int subseqlen = 1 << (mergelen_l2 - 1);
    int a, b;
    int i;

    if ((th.n_blocks >> (mergelen_l2-1)) == 0) {
        printf("\n");
        return 1; /* done */
    }

    printf(" %d", mergelen_l2);

    /* Sorting networks can be verified using the 'zero-one principle':
     * if a sorting network correctly sorts every possible sequence of
     * zeros and ones, then it works correctly for all inputs.  If the
     * set of inputs is restricted, as is the case for merging sorted
     * subsequences, this test is almost fast enough to be tolerable
     * for the sizes used here. */

    for (a = 0; a <= subseqlen; ++a) {
        for (b = 0; b <= subseqlen; ++b) {
            for (i = 0; i < subseqlen; ++i) {
                th.sortkeys[i] = (i>a) ? 1 : 0;
                if (i+subseqlen < TH_MAX_SORT_BLOCKS) {
                    th.sortkeys[i+subseqlen] = (i>b) ? 1 : 0;
                }
            }
            th_merge_seqs(pth, mergelen_l2, 0);

            for (i = 1; i < mergelen && i < TH_MAX_SORT_BLOCKS; ++i) {
                if (th.sortkeys[i-1] > th.sortkeys[i]) {
                    printf("\nth_merge_seqs failed, "
                        "mergelen_l2=%d, a=%d, b=%d, i=%d\n",
                        mergelen_l2, a, b, i);
                    return -1;
                }
            }
        }
    }

    return 0;
}

static void test_th_sort_verifyC2_setup() {
    th.leaf_bytes = 0;

    printf("testing th_sort_verifyC2:\n");
}

static int test_th_sort_verifyC2_step(int ips) {
    const pst *ps = &(paramsets[ips]);
    slt *ssl = &(seclevels[ps->ssl]);
    const int nrt = ps->nrtx + (ssl->pbytes * 8),
              nrl = ps->nrl, nrs = nrt - nrl;
    const int max_subseqlen = (nrs > nrl) ? nrs : nrl;
    int a, b, i;

    th.n_blocks = nrt;

    FOR(a, nrs+1) FOR(b, nrl+1) {
        FOR(i, max_subseqlen) {
            if (i < nrs) th.sortkeys[i] = (i >= a);
            if (i < nrl) th.sortkeys[i+nrs] = (i >= b);
        }
        th_sort_verifyC2(&th, ps);
        for (i = 1; i < nrt; ++i) {
            if (th.sortkeys[i-1] > th.sortkeys[i]) {
                    printf("\nth_sort_verifyC2 failed, "
                        "ips=%d, nrt=%d, nrs=%d, nrl=%d, "
                        "a=%d, b=%d, i=%d\n",
                        ips, nrt, nrs, nrl,
                        a, b, i);
                    return -1;
                }
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int rv = 0, i;

    setvbuf(stdout, NULL, _IONBF, 0);

    rv = test_memcswap_ct();
    if (rv < 0) goto err; /* no point in testing anything else */

    rv = test_th_minmax_ct();
    if (rv < 0) goto err; /* again, no point in testing anything else */

    test_th_merge_seqs_setup();
    i = 1; while (!(rv = test_th_merge_seqs_step(i))) ++i;
    if (rv < 0) goto err; /* no point in testing anything that uses it */

    test_th_sort_verifyC2_setup();
    FOR(i, N_PARAMSETS) {
        if ((rv = test_th_sort_verifyC2_step(1)) != 0) break;
    }

    return (rv < 0);

  err:
    return 1;
}

