
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
#include "minipkpsig-sig-sign.h"
#include "minipkpsig-randombytes.h"
#include "minipkpsig-sig-keygen.h"

#ifndef MINIPKPSIG_SINGLEFILE
extern slt seclevels[];
extern ppst pkp_paramsets[];
extern symt symalgs[];
extern pst paramsets[];
#endif

#include <string.h>

MAYBE_STATIC int NS(scs_check_v)(sigcommonstate *cst) {
    const int n = cst->pps.n;
    int i;

    cst->th.n_blocks = n;
    FOR(i, n) cst->th.sortkeys[i] = cst->v[i];
    th_sort_keys_full(&(cst->th));

    FOR(i, n-1) if (cst->th.sortkeys[i] == cst->th.sortkeys[i+1]) return -1;
    return 0;
}

MAYBE_STATIC int NS(sst_keypair)(signstate *sst) {
    const int kf_base = sst->cst.pps.kf_base;
    int rv, seed_rv;

    rv = NS(randombytes)(sst->seckeyseed, kf_base*2);
    if (rv != 0) return rv;
    rv = NS(randombytes)(sst->saltgenseed, kf_base*2);
    if (rv != 0) return rv;

    do {
        rv = NS(randombytes)(sst->cst.pkbytes, kf_base+1);
        if (rv != 0) return rv;

        scs_expand_pk(&(sst->cst), sst->cst.pkbytes);
        seed_rv = scs_check_v(&(sst->cst));
    } while (seed_rv != 0);

    sst_expand_secret_key(sst);
    sst_checksum_seckey(sst);
    memcpy(sst->seckeychecksum, sst->cst.hashbuf, (kf_base+1)/2);
    return 0;
}

msv NS(sst_get_skblob)(signstate *sst, u8 *skbytes) {
    const int kf_base = sst->cst.pps.kf_base;
    memcpy(skbytes, sst->cst.pkbytes, kf_base+1); skbytes += kf_base+1;
    memcpy(skbytes, sst->seckeyseed, 2*kf_base); skbytes += 2*kf_base;
    memcpy(skbytes, sst->saltgenseed, 2*kf_base); skbytes += 2*kf_base;
    memcpy(skbytes, sst->seckeychecksum, (kf_base+1)/2);
}

int NS(simple_keypair)(const char *psname, u8 *pk_out, u8 *sk_out) {
    signstate sst;
    pst ps;
    int rv;
    size_t pksize, sksize;
    if (ps_lookup(ps, psname) < 0) return -1;
    sst_init(&sst, &ps);
    pksize = scs_pksize(&(sst.cst));
    sksize = sst_sksize(&sst);
    rv = sst_keypair(&sst);
    if (rv == 0) {
        memcpy(pk_out, sst.cst.pkbytes, pksize);
        sst_get_skblob(&sst, sk_out);
    } else {
        memset(pk_out, 0, pksize);
        memset(sk_out, 0, sksize);
    }
    sst_erase(&sst);
    return rv;
}

