
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

MAYBE_STATIC size_t NS(sst_sksize)(signstate *sst) {
    size_t kf_base = sst->cst.pps.kf_base;
    return 1 + 5*kf_base + (kf_base+1)/2;
}

MAYBE_STATIC int NS(sst_set_secret_key)(signstate *sst, const u8 *sk, int gen) {
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

    memcpy(sst->cst.pkbytes, sk, kf_base + 1);
    memcpy(sst->seckeyseed, sk + kf_base+1, kf_base*2);
    memcpy(sst->saltgenseed, sk + 3*kf_base+1, kf_base*2);

    /* expand A and v */
    scs_expand_pk(&(sst->cst), sst->cst.pkbytes);

    /* FIXME recover pi_inv and w */
    u32le_put(indexbuf, HASHIDX_SECKEYSEEDEXPAND_PI_INV);
    FOR(i, n) sst->cst.th.sortkeys[i] = u32le_get(out->p + 4*i);
    scs_derive_permutation(&(sst->cst), sst->pi_inv, 0);
    
    
    

    /* FIXME encode w into pkbytes */
    
    

    /* FIXME recompute checksum; check it unless generating a new key */
    
    

    /* FIXME clobber secret key if checksum does not match */
    
    
}

msv NS(sst_hash_message)(signstate *sst, const u8 *msg, size_t len) {
    
    
    
}

