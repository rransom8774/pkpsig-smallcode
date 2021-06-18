
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

typedef struct {
    sigcommonstate cst;

    u8 seckeyseed[PKPSIG_MAX_KF_BASE*2];
    u8 saltgenseed[PKPSIG_MAX_KF_BASE*2];
    u8 seckeychecksum[(PKPSIG_MAX_KF_BASE+1)/2];

    u8 pi_inv[PKPSIG_MAX_N];

    u8 blindingseeds[PKPSIG_MAX_N_RUNS_TOTAL][PKPSIG_MAX_KEY_PREIMAGE_BYTES];
    u16 z[PKPSIG_MAX_N_RUNS_TOTAL][PKPSIG_MAX_N];
    u8 sigma[PKPSIG_MAX_N_RUNS_TOTAL][PKPSIG_MAX_N];
} signstate;

msv NS(sst_init)(signstate *sst, const pst *ps);
MAYBE_STATIC size_t NS(sst_sksize)(signstate *sst);
#define sst_init NS(sst_init)
#define sst_sksize NS(sst_sksize)

