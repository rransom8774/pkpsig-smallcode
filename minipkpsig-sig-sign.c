
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
#include "minipkpsig-tables.h"
#include "minipkpsig-paramsets-auto.h"
#include "minipkpsig-seclevels-auto.h"
#include "minipkpsig-treehash-auto.h"
#include "minipkpsig-sig-common.h"
#include "minipkpsig-sig-thsort.h"
#include "minipkpsig-sig-sign.h"

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
    return 4*kf_base;
}

msv NS(sst_expand_secret_key)(signstate *sst) {
    const int kf_base = sst->cst.pps.kf_base,
        n = sst->cst.pps.n, m = sst->cst.pps.m;
    int i;
    u8 hashctx = HASHCTX_SECKEYSEEDEXPAND;
    u8 indexbuf[4], qbuf[2];
    NS(chunkt) out[1] = {{sst->cst.hashbuf, 0}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {sst->seckeyseed, 2*kf_base},
        {qbuf, 2},
        {indexbuf, 4},
        {NULL, 0}
    };

    u16le_put(qbuf, sst->cst.pps.q);

    /* recover public parameters seed and expand it */
    u32le_put(indexbuf, HASHIDX_SECKEYSEEDEXPAND_PUBPARAMSSEED);
    out[0].bytes = kf_base*2;
    sst->cst.xof(out, in);
    memcpy(sst->cst.pkbytes, sst->cst.hashbuf, kf_base*2);
    scs_expand_pk(&(sst->cst), sst->cst.pkbytes);

    /* recover pi_inv and w */
    u32le_put(indexbuf, HASHIDX_SECKEYSEEDEXPAND_PI_INV);
    out[0].bytes = n*4;
    sst->cst.xof(out, in);
    FOR(i, n) sst->cst.th.sortkeys[i] = u32le_get(out->p + 4*i);
    scs_derive_permutation(&(sst->cst), sst->pi_inv, 0);

    scs_apply_perm_inv(&(sst->cst), sst->v_pi, sst->cst.v, sst->pi_inv);
    scs_mult_by_A(&(sst->cst), sst->v_pi);
    memset(sst->v_pi, 0, sizeof(sst->v_pi));

    /* encode w into pkbytes */
    FOR(i, m) sst->cst.w[i] = sst->cst.multbuf[i];
    vc_encode(sst->cst.vcpk, sst->cst.pkbytes + kf_base*2, sst->cst.w);
    FOR(i, m) sst->cst.w[i] = sst->cst.multbuf[i];
}

msv NS(sst_set_secret_key)(signstate *sst, const u8 *sk) {
    const int kf_base = sst->cst.pps.kf_base;

    memcpy(sst->seckeyseed, sk, kf_base*2);
    memcpy(sst->saltgenseed, sk + 2*kf_base, kf_base*2);

    /* recover pkbytes, A, v, pi_inv, and w */
    sst_expand_secret_key(sst);
}

msv NS(sst_hash_message)(signstate *sst, const u8 *msg, size_t len) {
    const int kf_base = sst->cst.pps.kf_base,
        ksl_cbytes = sst->cst.ksl.cbytes;
    u8 hashctx = HASHCTX_INTERNAL_GENMSGHASHSALT;
    NS(chunkt) out[1] = {{sst->cst.salt_and_msghash, ksl_cbytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {(u8 *)msg, len},
        {sst->saltgenseed, kf_base*2},
        {NULL, 0}
    };

    if (msg == NULL) {
        in[1].p = (u8 *) ""; msg = (u8 *) "";
        in[1].bytes = len = 0;
    }

    sst->cst.xof(out, in);

    return scs_hash_message(&(sst->cst), msg, len);
}

msv NS(sst_apply_compose_perm_inv)(signstate *sst, u16 *v_sigma, u8 *pi_sigma, const u16 *v, const u8 *pi, const u8 *sigma_inv) {
    const int n = sst->cst.pps.n;
    int i;
    sst->cst.th.n_blocks = n;
    FOR(i, n) {
        u32 si = sigma_inv[i], p = pi[i], vi = v[i];
        sst->cst.th.sortkeys[i] = (si << 24) | (vi << 8) | p;
    }
    th_sort_keys_full(&(sst->cst.th));
    FOR(i, n) {
        u32 ski = sst->cst.th.sortkeys[i];
        v_sigma[i] = (ski >> 8) & 0xFFFF;
        pi_sigma[i] = ski & 0xFF;
    }
}

sv NS(sst_gen_blinding_seed_gen_seed)(signstate *sst) {
    const int kf_base = sst->cst.pps.kf_base, bsgs_bytes = 4*kf_base;
    const int ksl_cbytes = sst->cst.ksl.cbytes;
    u8 hashctx = HASHCTX_INTERNAL_GENBLINDINGSEEDGENSEED, qbuf[2];
    NS(chunkt) out[1] = {{sst->bsgs, bsgs_bytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {sst->seckeyseed, 2*kf_base},
        {qbuf, 2},
        {sst->cst.salt_and_msghash, 2*ksl_cbytes},
        {NULL, 0}
    };

    u16le_put(qbuf, sst->cst.pps.q);
    sst->cst.xof(out, in);
}

sv NS(sst_gen_com1)(signstate *sst, int i) {
    const int ksl_cbytes = sst->cst.ksl.cbytes;
    const int ssl_cbytes = sst->cst.ssl.cbytes;
    const int n = sst->cst.pps.n;
    const int m = sst->cst.pps.m;
    u8 hashctx = HASHCTX_COMMITMENT;
    u8 indexbuf[4];
    NS(chunkt) out[1] = {{sst->coms[i][1], ssl_cbytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {sst->cst.salt_and_msghash, ksl_cbytes*2},
        {indexbuf, 4},
        {sst->sigma[i], n},
        {sst->Ar_buf, m*2},
        {NULL, 0}
    };

    u32le_put(indexbuf, i);
    sst->cst.xof(out, in);
}

msv NS(sst_zkp_pass1)(signstate *sst) {
    const int kf_base = sst->cst.pps.kf_base, bsgs_bytes = 4*kf_base;
    const int ksl_cbytes = sst->cst.ksl.cbytes;
    const int ksl_pbytes = sst->cst.ksl.pbytes;
    const int ssl_cbytes = sst->cst.ssl.cbytes;
    const int ssl_pbytes = sst->cst.ssl.pbytes;
    const int nrt = sst->cst.ps.nrtx + ssl_pbytes*8;
    const int m = sst->cst.pps.m;
    int i, j, rv;
    u8 hashctx = HASHCTX_INTERNAL_GENBLINDINGSEED;
    u8 indexbuf[4], qbuf[2];
    NS(chunkt) out[1] = {{sst->bsg_buf, bsgs_bytes + ksl_pbytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {sst->bsg_buf, bsgs_bytes},
        {qbuf, 2},
        {indexbuf, 4},
        {NULL, 0}
    };

    NS(sst_gen_blinding_seed_gen_seed)(sst);
    u16le_put(qbuf, sst->cst.pps.q);

    FOR(i, nrt) {
        memcpy(sst->bsg_buf, sst->bsgs, bsgs_bytes);
        u32le_put(indexbuf, i);

        do {
            sst->cst.xof(out, in);
            memcpy(sst->blindingseeds[i], sst->bsg_buf + bsgs_bytes,
                ksl_pbytes);
            rv = scs_expand_blindingseed(&(sst->cst),
                sst->r_sigma[i], sst->pi_sigma_inv,
                sst->coms[i][0], sst->blindingseeds[i], i, 1);
        } while (rv != 0);

        sst_apply_compose_perm_inv(sst,
            sst->v_pi_sigma[i], sst->sigma[i],
            sst->cst.v, sst->pi_inv, sst->pi_sigma_inv);
        scs_apply_perm_inv(&(sst->cst),
            sst->r,
            sst->r_sigma[i], sst->sigma[i]);
        scs_mult_by_A(&(sst->cst), sst->r);
        FOR(j, m) u16le_put(sst->Ar_buf + 2*j, sst->cst.multbuf[j]);
        NS(sst_gen_com1)(sst, i);
    }

    th_init(&(sst->cst.th), &(sst->cst.ps));
    sst->cst.th.hashctx = HASHCTX_CHALLENGE1HASH;
    sst->cst.th.leaf_bytes = ssl_cbytes;
    sst->cst.th.n_blocks = 2*nrt;
    memcpy(sst->cst.th.prefix, sst->cst.salt_and_msghash, ksl_cbytes*2);
    sst->cst.th.prefix_bytes = ksl_cbytes*2;
    FOR(i, nrt) {
        memcpy(sst->cst.th.leaves + ssl_cbytes*2*i, sst->coms[i][0],
            ssl_cbytes);
        memcpy(sst->cst.th.leaves + ssl_cbytes*(2*i+1), sst->coms[i][1],
            ssl_cbytes);
    }
    th_hash(&(sst->cst.th), sst->cst.h_C1, ssl_cbytes);
}

msv NS(sst_zkp_pass3)(signstate *sst) {
    const int ksl_cbytes = sst->cst.ksl.cbytes;
    const int ssl_cbytes = sst->cst.ssl.cbytes;
    const int ssl_pbytes = sst->cst.ssl.pbytes;
    const int nrt = sst->cst.ps.nrtx + ssl_pbytes*8;
    const int n = sst->cst.pps.n;
    int i, j;

    FOR(i, nrt) {
        u32 alpha = sst->cst.Hbuf[i] & 0x7FFF;
        FOR(j, n) {
            u32 zj = sst->r_sigma[i][j] + alpha*sst->v_pi_sigma[i][j];
            sst->z[i][j] = scs_mod_q(&(sst->cst), zj);
        }
    }

    th_init(&(sst->cst.th), &(sst->cst.ps));
    sst->cst.th.hashctx = HASHCTX_CHALLENGE2HASH;
    sst->cst.th.leaf_bytes = 2*n;
    sst->cst.th.n_blocks = nrt;
    memcpy(sst->cst.th.prefix, sst->cst.salt_and_msghash, ksl_cbytes*2);
    sst->cst.th.prefix_bytes = ksl_cbytes*2;
    FOR(i, nrt) {
        u8 *zbuf = sst->cst.th.leaves + i*2*n;
        FOR(j, n) {
            u16le_put(zbuf + 2*j, sst->z[i][j]);
        }
        sst->cst.th.sortkeys[i] = i;
    }
    th_prehash(&(sst->cst.th), ssl_cbytes);
    th_hash(&(sst->cst.th), sst->cst.h_C2, ssl_cbytes);
}

sv NS(squish_permutation)(u16 *sigma, int n) {
    int i, j;
    FOR(i, n) {
        int s_i = sigma[i];
        for (j = i+1; j < n; ++j) {
            if (sigma[j] > s_i) --(sigma[j]);
        }
    }
}

msv NS(sst_gen_signature)(signstate *sst, u8 *out) {
    const int ksl_cbytes = sst->cst.ksl.cbytes;
    const int ksl_pbytes = sst->cst.ksl.pbytes;
    const int ssl_cbytes = sst->cst.ssl.cbytes;
    const int ssl_pbytes = sst->cst.ssl.pbytes;
    const int nrt = sst->cst.ps.nrtx + ssl_pbytes*8;
    const int nrl = sst->cst.ps.nrl, nrs = nrt - nrl;
    const int n = sst->cst.pps.n;
    int i, j;
    u8 *prs, *prl;
    size_t nS_z, nS_sigma;

    memcpy(out, sst->cst.salt_and_msghash, ksl_cbytes); out += ksl_cbytes;
    memcpy(out, sst->cst.h_C1, ssl_cbytes); out += ssl_cbytes;
    memcpy(out, sst->cst.h_C2, ssl_cbytes); out += ssl_cbytes;

    prs = out + ssl_cbytes*nrt;
    prl = prs + ksl_pbytes*nrs;
    nS_z = vc_nS(sst->cst.vcz);
    nS_sigma = vc_nS(sst->cst.vcsigma);

    FOR(i, nrt) {
        int H = (sst->cst.Hbuf[i] >> 15), not_H = 1-H;

        memcpy(out, sst->coms[i][not_H], ssl_cbytes);
        out += ssl_cbytes;

        if (sst->cst.Hbuf[i] & 0x8000) {
            vc_encode(sst->cst.vcz, prl, sst->z[i]);
            prl += nS_z;
            FOR(j, n) sst->sigma_buf[j] = sst->sigma[i][j];
            NS(squish_permutation)(sst->sigma_buf, n);
            vc_encode(sst->cst.vcsigma, prl, sst->sigma_buf);
            prl += nS_sigma;
        } else {
            memcpy(prs, sst->blindingseeds[i], ksl_pbytes);
            prs += ksl_pbytes;
        }
    }
}

msv NS(sst_sign)(signstate *sst, u8 *sig, const u8 *msg, size_t msglen) {
    sigcommonstate *cst = &(sst->cst);

    sst_hash_message(sst, msg, msglen);
    sst_zkp_pass1(sst);
    scs_expand_H1(cst);
    sst_zkp_pass3(sst);
    scs_expand_H2(cst);
    sst_gen_signature(sst, sig);
}

ssize_t NS(simple_get_secretkey_bytes)(const char *psname) {
    signstate sst;
    pst ps;
    if (ps_lookup(ps, psname) < 0) return -1;
    sst_init(&sst, &ps);
    return sst_sksize(&sst);
}

int NS(simple_detached_sign)(const char *psname, u8 *sigout, const u8 *msg, size_t msglen, const u8 *sk) {
    signstate sst;
    pst ps;
    if (ps_lookup(ps, psname) < 0) return -1;
    sst_init(&sst, &ps);

    sst_set_secret_key(&sst, sk);
    sst_sign(&sst, sigout, msg, msglen);

    sst_erase(&sst);
    return 0;
}

int NS(simple_secretkey_to_publickey)(const char *psname, u8 *pk_out, const u8 *sk) {
    signstate sst;
    pst ps;
    size_t pksize;
    if (ps_lookup(ps, psname) < 0) return -1;
    sst_init(&sst, &ps);

    sst_set_secret_key(&sst, sk);

    pksize = scs_pksize(&(sst.cst));
    memcpy(pk_out, sst.cst.pkbytes, pksize);

    sst_erase(&sst);
    return 0;
}

