
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
    u32 sortkeys[TH_MAX_SORT_BLOCKS];
    u8 leaves[TH_MAX_TOTAL_LEAF_BYTES];
} tht;

msv NS(memcswap_ct)(u8 *px, u8 *py, size_t len, int flag);
msv NS(th_minmax_ct)(tht *th, int i, int j);
#define memcswap_ct NS(memcswap_ct)
#define th_minmax_ct NS(th_minmax_ct)

msv NS(th_merge_seqs)(tht *th, int mergelen_l2, int off);
#define th_merge_seqs NS(th_merge_seqs)

