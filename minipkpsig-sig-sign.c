
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

#ifndef MINIPKPSIG_SINGLEFILE
extern slt seclevels[];
extern ppst pkp_paramsets[];
extern symt symalgs[];
extern pst paramsets[];
#endif

#include <string.h>

msv NS(sst_init)(signstate *sst, const pst *ps) {
    memset(sst, 0, sizeof(*sst));
    scs_init(&(sst->cst), ps);
}

msv NS(sst_erase)(signstate *sst) {
    pst ps = sst->cst.ps;
    sst_init(sst, &ps);
}

MAYBE_STATIC size_t NS(sst_sksize)(signstate *sst) {
    size_t kf_base = sst->cst.pps.kf_base;
    return 1 + 5*kf_base + (kf_base+1)/2;
}

msv NS(sst_expand_secret_key)(signstate *sst) {
    const int kf_base = sst->cst.pps.kf_base,
        n = sst->cst.pps.n, m = sst->cst.pps.m;
    int i;
    u8 hashctx = HASHCTX_SECKEYSEEDEXPAND;
    u8 indexbuf[4];
    NS(chunkt) out[1] = {{sst->cst.hashbuf, n*4}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {sst->cst.pkbytes, kf_base + 1},
        {sst->seckeyseed, 2*kf_base},
        {indexbuf, 4},
        {NULL, 0}
    };

    /* recover pi_inv and w */
    u32le_put(indexbuf, HASHIDX_SECKEYSEEDEXPAND_PI_INV);
    sst->cst.xof(out, in);
    FOR(i, n) sst->cst.th.sortkeys[i] = u32le_get(out->p + 4*i);
    scs_derive_permutation(&(sst->cst), sst->pi_inv, 0);

    scs_apply_perm_inv(&(sst->cst), sst->v_pi, sst->cst.v, sst->pi_inv);
    scs_mult_by_A(&(sst->cst), sst->v_pi);
    memset(sst->v_pi, 0, sizeof(sst->v_pi));

    /* encode w into pkbytes */
    FOR(i, m) sst->cst.w[i] = sst->cst.multbuf[i];
    vc_encode(sst->cst.vcpk, sst->cst.pkbytes + kf_base+1, sst->cst.w);
    FOR(i, m) sst->cst.w[i] = sst->cst.multbuf[i];
}

msv NS(sst_checksum_seckey)(signstate *sst) {
    const int kf_base = sst->cst.pps.kf_base,
        cksum_bytes = (kf_base + 1)/2;
    int i;
    u8 hashctx = HASHCTX_SECKEYCHECKSUM;
    u8 cksum_params[2] = {
        sst->cst.ksl.pbytes,
        sst->cst.ksl.cbytes
    };
    NS(chunkt) out[1] = {{sst->cst.hashbuf, cksum_bytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {cksum_params, 2},
        {sst->cst.pkbytes, scs_pksize(&(sst->cst))},
        {NULL, 0}
    };

    sst->cst.xof(out, in);
}

MAYBE_STATIC int NS(sst_set_secret_key)(signstate *sst, const u8 *sk, int gen) {
    const int kf_base = sst->cst.pps.kf_base,
        cksum_bytes = (kf_base + 1)/2,
        n = sst->cst.pps.n, m = sst->cst.pps.m;
    int i, rv;
    u8 hashctx = HASHCTX_SECKEYSEEDEXPAND;
    u8 indexbuf[4];
    NS(chunkt) out[1] = {{sst->cst.hashbuf, n*4}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {sst->cst.pkbytes, kf_base + 1},
        {sst->seckeyseed, 2*kf_base},
        {indexbuf, 4},
        {NULL, 0}
    };

    memcpy(sst->cst.pkbytes, sk, kf_base + 1);
    memcpy(sst->seckeyseed, sk + kf_base+1, kf_base*2);
    memcpy(sst->saltgenseed, sk + 3*kf_base+1, kf_base*2);

    /* expand A and v */
    scs_expand_pk(&(sst->cst), sst->cst.pkbytes);

    /* recover pi_inv, w, and the rest of pkbytes */
    sst_expand_secret_key(sst);

    /* recompute checksum; check it unless generating a new key */
    sst_checksum_seckey(sst);
    if (gen) {
        memcpy(sst->seckeychecksum, sst->cst.hashbuf, cksum_bytes);
        rv = 0;
    } else {
        rv = memverify_ct(sst->seckeychecksum, sst->cst.hashbuf, cksum_bytes);
    }

    /* clobber secret key if checksum does not match */
    if (rv != 0) {
        sst_erase(sst);
    }

    return rv;
}

msv NS(sst_hash_message)(signstate *sst, const u8 *msg, size_t len) {
    const int kf_base = sst->cst.pps.kf_base,
        ksl_cbytes = sst->cst.ksl.cbytes;
    u8 hashctx = HASHCTX_INTERNAL_GENMSGHASHSALT;
    NS(chunkt) out[1] = {{sst->cst.salt_and_msghash, ksl_cbytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {msg, len},
        {sst->saltgenseed, kf_base*2},
        {NULL, 0}
    };

    sst->cst.xof(out, in);

    return scs_hash_message(&(sst->cst), msg, len);
}

