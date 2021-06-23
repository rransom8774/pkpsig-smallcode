
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

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

int NS(ps_enum_names)(NS(enum_names_cb) cb, void *cbdata) {
    char buf[64];
    int rv, i;
    u8 isym, pps;
    FOR(isym, N_SYMALGS) {
        const symt *sym = &(symalgs[isym]);
        if (sym->xof_chunked == NULL) continue;

        FOR(i, N_PARAMSETS) {
            const pst *ps_ptr = &(paramsets[i]);
            const ppst *pps = &(pkp_paramsets[ps.pps]);
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

msv NS(th_init)(tht *th, const pst *ps) {
    const ppst *pps = &(pkp_paramsets[ps->pps]);
    int ksl_cbytes = seclevels[pps->ksl].cbytes;
    int ssl_pbytes = seclevels[ps->ssl].pbytes;
    int ssl_cbytes = seclevels[ps->ssl].cbytes;
    int nrt = ps->nrtx + ssl_pbytes*8, nrs = nrt - ps->nrl;

    memset(th, 0, sizeof(*th));

    th->xof = symalgs[ps->sym].xof_chunked;
    th->prefix_bytes = ksl_cbytes * 2;
    th->degree = (136*4 - 16 - th->prefix_bytes) / ssl_cbytes;
    th->next_node_index = 0;
    th->params[0] = th->degree;
    th->params[1] = th->node_bytes = ssl_cbytes;
    u16le_put(th->params + 3, nrs);
    u16le_put(th->params + 5, ps->nrl);
}

sv th_hash_level(tht *th) {
    u32 node_index = th->next_node_index; u8 nibuf[4];
    size_t in_node_bytes = th->leaf_bytes, out_node_bytes = th->node_bytes;
    NS(chunkt) outchunk[1] = {NULL, out_node_bytes};
    NS(chunkt) in[TH_MAX_DEGREE + 5] = {
        {&(th->hashctx), 1},
        {th->prefix, th->prefix_bytes},
        {th->params, TH_PARAM_BYTES},
        {nibuf, 4},
        {NULL, 0}
    };
    const int degree = th->degree, n = th->n_blocks;
    int i, idx_in, idx_out;

    FOR(i, TH_MAX_DEGREE+1) in[4+i].p = NULL;

    i = idx_in = idx_out = 0;
    while (idx_in < n) {
        FOR(i, degree) {
            if (idx_in >= n) {
                in[4+i].p = NULL;
                break;
            }
            in[4+i].p = th->leaves + idx_in*in_node_bytes;
            in[4+i].bytes = in_node_bytes;
            ++idx_in;
        }

        u32le_put(nibuf, node_index);
        outchunk->p = th->leaves + idx_out*out_node_bytes;
        th->xof(outchunk, in);
        ++idx_out; ++node_index;
    }

    th->next_node_index = node_index;
    th->leaf_bytes = out_node_bytes;
    th->n_blocks = idx_out;
}

msv NS(th_prehash)(tht *th, size_t outbytes) {
    size_t in_node_bytes = th->leaf_bytes, out_node_bytes = th->node_bytes;
    u8 nibuf[4];
    NS(chunkt) outchunk[1] = {NULL, out_node_bytes};
    NS(chunkt) in[] = {
        {&(th->hashctx), 1},
        {th->prefix, th->prefix_bytes},
        {th->params, TH_PARAM_BYTES},
        {nibuf, 4},
        {NULL, in_node_bytes},
        {NULL, 0}
    };
    int i, n = th->n_blocks;

    assert(outbytes <= th->node_bytes);
    th->params[2] = outbytes;

    assert(out_node_bytes <= in_node_bytes);

    FOR(i, n) {
        outchunk->p = th->leaves + out_node_bytes*i;
        in[4].p = th->leaves + in_node_bytes*i;
        u32le_put(nibuf, th->sortkeys[i]);
        th->xof(outchunk, in);
    }

    th->leaf_bytes = out_node_bytes;
    th->next_node_index = n;
}

msv NS(th_hash)(tht *th, u8 *out, size_t outbytes) {
    assert(th->node_bytes >= outbytes);
    th->params[2] = outbytes;

    while (th->n_blocks != 1) {
        th_hash_level(th);
    }

    memcpy(out, th->leaves, outbytes);
}

/* copied from https://gist.github.com/sneves/10845247;
 * author Samuel Neves, license CC0 */
static int ct_isnonzero_u32(uint32_t x)
{
    return (x|-x)>>31;
}

MAYBE_STATIC int NS(memverify_ct)(const u8 *x, const u8 *y, size_t len) {
    size_t i;
    u8 acc = 0;
    FOR(i, len) acc |= (x[i] ^ y[i]);
    return -ct_isnonzero_u32(acc);
}

MAYBE_STATIC u16 NS(scs_mod_q)(const sigcommonstate *cst, u32 x) {
    x = (x & 0xFFFFFFUL) + (cst->q_reduce_2_24 * (x>>24));
    return mod(cst->q_mod, x);
}
#define scs_mod_q NS(scs_mod_q)

msv NS(scs_init)(sigcommonstate *cst, const pst *ps) {
    u16 M[PKPSIG_MAX_N];
    int i, n;

    memset(cst, 0, sizeof(cst));

    cst->ps = *ps;
    cst->pps = pkp_paramsets[ps->pps];
    cst->ksl = seclevels[cst->pps.ksl];
    cst->ssl = seclevels[ps->ssl];

    cst->xof = symalgs[ps->sym].xof_chunked;

    mod_init(cst->q_mod, cst->pps.q);
    cst->q_reduce_2_24 = (1UL << 24) % (u32)cst->pps.q;
    cst->q_uniform_bound = -(u32)scs_mod_q(cst, cst->q_reduce_2_24 * 256);

    th_init(&(cst->th), ps);

    n = cst->pps.n;
    FOR(i, n) M[i] = cst->pps.q;
    vc_init(cst->vcpk, M, cst->pps.m);
    vc_init(cst->vcz, M, cst->pps.n);

    FOR(i, n-1) M[i] = cst->pps.n - i;
    vc_init(cst->vcsigma, M, cst->pps.n - 1);
}
#define scs_init NS(scs_init)

MAYBE_STATIC size_t NS(scs_get_sig_bytes)(const sigcommonstate *cst) {
    size_t saltbytes = cst->ksl.cbytes;
    size_t h_C1_bytes = cst->ssl.cbytes;
    size_t h_C2_bytes = cst->ssl.cbytes;
    size_t nrt = cst->ps.nrtx + 8*cst->ssl.pbytes;
    size_t nrl = cst->ps.nrl, nrs = nrt - nrl;
    size_t runbytes_common = cst->ssl.cbytes;
    size_t runbytes_short = cst->ksl.pbytes;
    size_t runbytes_long = vc_nS(cst->vcz) + vc_nS(cst->vcsigma);
    return (saltbytes + h_C1_bytes + h_C2_bytes + runbytes_common*nrt +
            runbytes_short*nrs + runbytes_long*nrl);
}

MAYBE_STATIC size_t NS(scs_pksize)(sigcommonstate *cst) {
    return cst->pps.kf_base+1 + vc_nS(cst->vcpk);
}
#define scs_pksize NS(scs_pksize)

msv NS(scs_expand_pk)(sigcommonstate *cst, const u8 *pkbytes) {
    const int n = cst->pps.n, m = cst->pps.m;
    u32 i, j; u8 ibuf[4];
    u8 hashctx = HASHCTX_PUBPARAMS;
    NS(chunkt) out[1] = {cst->hashbuf, n*4};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {cst->pkbytes, cst->pps.kf_base+1},
        {ibuf, 4},
        {NULL, 0}
    };

    if (cst->pkbytes != pkbytes) {
        memcpy(cst->pkbytes, pkbytes, scs_pksize(cst));
    }

    vc_decode(cst->vcpk, cst->w, pkbytes + cst->pps.kf_base+1);

    u32le_put(ibuf, 0);
    cst->xof(out, in);
    FOR(j, n) cst->v[j] = scs_mod_q(cst, u32le_get(cst->hashbuf + 4*j));

    for (i = m; i < n; ++i) {
        u32le_put(ibuf, i);
        cst->xof(out, in);
        FOR(j, m) cst->A[i-m][j] = scs_mod_q(cst, u32le_get(cst->hashbuf + 4*j));
    }
}
#define scs_expand_pk NS(scs_expand_pk)

msv NS(scs_mult_by_A)(sigcommonstate *cst, const u16 *z) {
    const int n = cst->pps.n, m = cst->pps.m;
    int i, j;

    FOR(i, m) cst->multbuf[i] = z[i];
    for (i = m; i < n; ++i) {
        u32 z_i = z[i];
        FOR(j, m) cst->multbuf[j] += z_i * (u32)cst->A[i-m][j];
    }

    FOR(i, m) cst->multbuf[i] = scs_mod_q(cst, cst->multbuf[i]);

    /* leaves result in multbuf[] */
}

msv NS(scs_hash_message)(sigcommonstate *cst, const u8 *msg, size_t len) {
    const int ksl_cbytes = cst->ksl.cbytes;
    u8 hashctx = HASHCTX_MESSAGEHASH;
    NS(chunkt) out[1] = {{cst->salt_and_msghash + ksl_cbytes, ksl_cbytes}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {cst->salt_and_msghash, ksl_cbytes},
        {cst->pkbytes, scs_pksize(cst)},
        {(u8 *)msg, len},
        {NULL, 0}
    };
    cst->xof(out, in);
}

MAYBE_STATIC int NS(scs_derive_vector)(sigcommonstate *cst, u16 *v, int gen) {
    const int n = cst->pps.n;
    int i, rv = 0;
    FOR(i, n) v[i] = scs_mod_q(cst, cst->th.sortkeys[i]);
    if (gen) FOR(i, n) {
        rv |= (cst->th.sortkeys[i] >= cst->q_uniform_bound);
    }
    return -rv;
}

MAYBE_STATIC int NS(scs_derive_permutation)(sigcommonstate *cst, u8 *perm, int gen) {
    const int n = cst->pps.n;
    int i, rv = 0;
    FOR(i, n) {
        cst->th.sortkeys[i] &= PERMSAMPLER_RANDOM_MASK;
        cst->th.sortkeys[i] |= (i & PERMSAMPLER_INDEX_MASK);
    }
    cst->th.n_blocks = n;
    th_sort_keys_full(&(cst->th));
    FOR(i, n) perm[i] = cst->th.sortkeys[i] & PERMSAMPLER_INDEX_MASK;
    if (gen) FOR(i, n-1) {
        rv |= ((cst->th.sortkeys[i] & PERMSAMPLER_RANDOM_MASK) ==
               (cst->th.sortkeys[i+1] & PERMSAMPLER_RANDOM_MASK));
    }
    return -rv;
}

MAYBE_STATIC int NS(scs_expand_blindingseed)(sigcommonstate *cst, u16 *r_sigma, u8 *pi_sigma_inv, u8 *com0, const u8 *bseed, u32 runidx, int gen) {
    const int ksl_pbytes = cst->ksl.pbytes;
    const int ksl_cbytes = cst->ksl.cbytes;
    const int ssl_cbytes = cst->ssl.cbytes;
    const int n = cst->pps.n;
    int i, rv = 0;
    u8 hashctx = HASHCTX_EXPANDBLINDINGSEED;
    u8 runidxbuf[4];
    NS(chunkt) out[1] = {{NULL, 0}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {cst->salt_and_msghash, ksl_cbytes*2},
        {runidxbuf, 4},
        {(u8 *)bseed, ksl_pbytes},
        {NULL, 0}
    };

    u32le_put(runidxbuf, HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR*runidx +
              HASHIDX_EXPANDBLINDINGSEED_COMMITMENT);
    out->p = com0;
    out->bytes = ssl_cbytes;
    cst->xof(out, in);

    u32le_put(runidxbuf, HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR*runidx +
              HASHIDX_EXPANDBLINDINGSEED_PI_SIGMA_INV);
    out->p = cst->hashbuf;
    out->bytes = n * 4;
    cst->xof(out, in);
    FOR(i, n) cst->th.sortkeys[i] = u32le_get(out->p + 4*i);
    rv |= scs_derive_permutation(cst, pi_sigma_inv, gen);

    u32le_put(runidxbuf, HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR*runidx +
              HASHIDX_EXPANDBLINDINGSEED_R_SIGMA);
    cst->xof(out, in);
    FOR(i, n) cst->th.sortkeys[i] = u32le_get(out->p + 4*i);
    rv |= scs_derive_vector(cst, r_sigma, gen);

    return rv;
}

msv NS(scs_expand_H1)(sigcommonstate *cst) {
    u16 nrt = cst->ssl.pbytes*8 + cst->ps.nrtx;
    u8 hashctx = HASHCTX_CHALLENGE1EXPAND;
    NS(chunkt) out[1] = {{cst->hashbuf, nrt*4}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {cst->salt_and_msghash, 2*cst->ksl.cbytes},
        {cst->th.params, TH_PARAM_BYTES},
        {cst->h_C1, cst->ssl.cbytes},
        {NULL, 0}
    };
    int i;

    cst->th.params[2] = cst->ssl.cbytes;

    cst->xof(out, in);

    FOR(i, nrt) {
        u32 x = u32le_get(cst->hashbuf + 4*i);
        cst->Hbuf[i] = (cst->Hbuf[i] & 0x8000) | scs_mod_q(cst, x);
    }
}

msv NS(scs_expand_H2)(sigcommonstate *cst) {
    u16 nrt = cst->ssl.pbytes*8 + cst->ps.nrtx, nrl = cst->ps.nrl;
    u8 hashctx = HASHCTX_CHALLENGE2EXPAND;
    NS(chunkt) out[1] = {{cst->hashbuf, nrt*4}};
    NS(chunkt) in[] = {
        {&hashctx, 1},
        {cst->salt_and_msghash, 2*cst->ksl.cbytes},
        {cst->th.params, TH_PARAM_BYTES},
        {cst->h_C1, cst->ssl.cbytes},
        {cst->h_C2, cst->ssl.cbytes},
        {NULL, 0}
    };
    int i;

    cst->th.params[2] = cst->ssl.cbytes;

    cst->xof(out, in);

    cst->th.n_blocks = nrt;
    cst->th.leaf_bytes = 0;
    FOR(i, nrt) {
        u32 x = u32le_get(cst->hashbuf + 4*i) & ~(u32)1;
        x |= (i < nrl);
        cst->th.sortkeys[i] = x;
    }

    th_sort_keys_full(&(cst->th));

    FOR(i, nrt) {
        int x = cst->th.sortkeys[i] & 1;
        cst->Hbuf[i] = (cst->Hbuf[i] & 0x7FFF) | (x << 15);
    }
}

msv NS(scs_apply_perm_inv)(sigcommonstate *cst, u16 *v_sigma_inv, const u16 *v, const u8 *sigma) {
    const int n = cst->pps.n;
    int i;
    FOR(i, n) cst->th.sortkeys[i] = (((u32)sigma[i]) << 16) + (u32)v[i];
    cst->th.n_blocks = n;
    th_sort_keys_full(&(cst->th));
    FOR(i, n) v_sigma_inv[i] = cst->th.sortkeys[i] & 0xFFFF;
}

ssize_t NS(simple_get_publickey_bytes)(const char *psname) {
    sigcommonstate cst;
    pst ps;
    if (ps_lookup(ps, psname) < 0) return -1;
    scs_init(&cst, &ps);
    return scs_pksize(&cst);
}

ssize_t NS(simple_get_signature_bytes)(const char *psname) {
    sigcommonstate cst;
    pst ps;
    if (ps_lookup(ps, psname) < 0) return -1;
    scs_init(&cst, &ps);
    return scs_get_sig_bytes(&cst);
}

