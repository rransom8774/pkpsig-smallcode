
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

static u64 ceildiv(u64 x, u32 div) {
    u64 y = x + (u64)(div-1);
    return y / (u64)div;
}
msv NS(mod_init_)(modt *m, u16 v) {
    u64 r;
    u16 o = v;
    u8 s = 0; while(v != 0) {++s; v >>= 1;}
    r = ceildiv(1ULL << (31 + s), o);
    if ((r & 1) == 0) {
        r >>= 1;
        --s;
    }
    m->recip = r;
    m->orig = o;
    m->shift = s;
}

MAYBE_STATIC u32 NS(moddiv_)(const modt *m, u32 *pq, u32 v) {
    u32 q = (((u64)v)*((u64)m->recip)) >> (31+m->shift);
    if (pq) *pq=q;
    return v - (q * (u32)(m->orig));
}

sv vclayer_init_final(vct *vc, int layer) {
    vclayer *lc = &(vc->layers[layer]), *lp = &(vc->layers[layer-1]);
    int i;
    u8 nS = 0;
    u16 M = lc->M[0].orig;
    /* lc->nlower == 1 */
    lc->nbytes = lc->nS[0] = 0;
    while (M > 1) {
        ++nS; M = (M + 255) / 256;
    }
    lp->nS[0] += nS; lp->nbytes += nS;
    for (i = layer+1; i < VEC_MAXLAYERS; ++i) {
        vc->layers[i].nlower = 0;
        vc->layers[i].nbytes = 0;
    }
}

sv vclayer_init_next(vct *vc, int layer) {
    vclayer *lc = &(vc->layers[layer]), *ln = &(vc->layers[layer+1]);
    u16 nlower = vc->layers[layer].nlower;
    u16 nabove = ln->nlower = (nlower + 1) >> 1;
    u16 nbytes = 0;
    int i;
    if (nlower == 1) return vclayer_init_final(vc, layer);
    for (i=0; i < nlower-1; i += 2) {
        u32 merged = (u32)(lc->M[i].orig) * (u32)(lc->M[i+1].orig);
        u8 nS = 0;
        while (merged >= VEC_LIMIT) {
            ++nS; merged = (merged + 255) / 256;
        }
        nbytes += lc->nS[i/2] = nS;
        mod_init(ln->M[i/2], merged);
    }
    if (nlower & 1) {
        ln->nS[nabove-1] = 0;
        ln->M[nabove-1] = lc->M[nlower-1];
    }
    lc->nbytes = nbytes;
}

msv NS(vc_init_)(vct *vc, const u16 M[], u16 Mlen) {
    int i;
    vc->layers[0].nlower = Mlen;
    FOR(i, Mlen) mod_init(vc->layers[0].M[i], M[i]);
    FOR(i, VEC_MAXLAYERS-1) {
        vclayer_init_next(vc, i);
    }
}

MAYBE_STATIC unsigned int NS(vc_nS_)(const vct *vc) {
    unsigned int nS = 0;
    int i;
    FOR(i, VEC_MAXLAYERS) {
        const vclayer *l = &(vc->layers[i]);
        nS += l->nbytes;
    }
    return nS;
}

msv NS(vc_encode_)(const vct *vc, u8 S[], u16 R[]) {
    int k, j, i;
    k = 0;
    FOR(j, VEC_MAXLAYERS) {
        const vclayer *l = &(vc->layers[j]);
        int nlower = l->nlower;
        for (i=0; i+1 < nlower; i += 2) {
            u32 merged = R[i] + (u32)(l->M[i].orig) * (u32)R[i+1];
            u8 nS = l->nS[i/2];
            while (nS > 0) {
                S[k] = merged & 255;
                merged >>= 8;
                ++k; --nS;
            }
            R[i/2] = merged;
        }
        if (nlower & 1) {
            R[(nlower-1)/2] = R[nlower-1];
        }
    }
}

msv NS(vc_decode_)(const vct *vc, u16 R[], const u8 S[]) {
    int k, j, i;
    R[0] = 0;
    k=-1; FOR(j, VEC_MAXLAYERS) k += vc->layers[j].nbytes;
    for (j = VEC_MAXLAYERS - 1; j >= 0; --j) {
        const vclayer *l = &(vc->layers[j]);
        int nlower = l->nlower;
        if (nlower == 0) continue;
        if (nlower & 1) {
            R[nlower-1] = R[(nlower-1)/2];
            --nlower;
        }
        for (i = nlower-2; i >= 0; i -= 2) {
            u32 merged = R[i/2];
            u8 nS = l->nS[i/2];
            while (nS > 0) {
                merged = (merged << 8) + S[k];
                --k; --nS;
            }
            R[i] = moddiv(l->M[i], merged, merged);
            R[i+1] = mod(l->M[i+1], merged);
        }
    }
}

