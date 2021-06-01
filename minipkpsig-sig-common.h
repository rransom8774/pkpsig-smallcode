
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#define HASHCTX_PUBPARAMS 0
#define HASHCTX_SECKEYSEEDEXPAND 1
#define HASHCTX_SECKEYCHECKSUM 2
#define HASHCTX_MESSAGEHASH 3
#define HASHCTX_EXPANDBLINDINGSEED 4
#define HASHCTX_COMMITMENT 5
#define HASHCTX_CHALLENGE1HASH 6
#define HASHCTX_CHALLENGE1EXPAND 7
#define HASHCTX_CHALLENGE2HASH 8
#define HASHCTX_CHALLENGE2EXPAND 9

#define HASHCTX_INTERNAL_GENMSGHASHSALT 0x80
#define HASHCTX_INTERNAL_GENBLINDINGSEEDGENSEED 0x81
#define HASHCTX_INTERNAL_GENBLINDINGSEED 0x82

MAYBE_STATIC int NS(ps_lookup_)(pst *ps_ptr, const char *name);
MAYBE_STATIC int NS(ps_enum_names)(NS(enum_names_cb) cb, void *cbdata);
#define ps_lookup(ps_, name) NS(ps_lookup_)(&(ps_), (name))
#define ps_enum_names NS(ps_enum_names)

typedef struct {
    size_t leaf_bytes;
    int n_blocks;
    u32 next_node_index;
    u32 sortkeys[TH_MAX_SORT_BLOCKS];
    u8 leaves[TH_MAX_TOTAL_LEAF_BYTES];
} tht;

typedef struct {
    tht th;
    vct vcpk, vcz, vcrho;

    u16 A[PKPSIG_MAX_A_COLS][PKPSIG_MAX_M];
    u16 v[PKPSIG_MAX_N], w[PKPSIG_MAX_M];
    u32 multbuf[PKPSIG_MAX_M];
    u32 Hbuf[TH_MAX_SORT_BLOCKS];

    modt q_mod;
    u16 q_reduce_2_24;
    pst ps;
    ppst pps;
    slt ksl, ssl;
    sym_xof_chunked xof;

    u8 pkbytes[PKPSIG_MAX_PUBLIC_KEY_BYTES];
    u8 hashbuf[TH_MAX_SORT_BLOCKS * 4];
} sigcommonstate;

MAYBE_STATIC u16 NS(scs_mod_q)(const sigcommonstate *cst, u32 x);
msv NS(scs_init)(sigcommonstate *cst, const pst *ps);
MAYBE_STATIC size_t NS(scs_pksize)(sigcommonstate *cst);
msv NS(scs_expand_pk)(sigcommonstate *cst, const u8 *pkbytes);
#define scs_mod_q NS(scs_mod_q)
#define scs_init NS(scs_init)
#define scs_pksize NS(scs_pksize)
#define scs_expand_pk NS(scs_expand_pk)

