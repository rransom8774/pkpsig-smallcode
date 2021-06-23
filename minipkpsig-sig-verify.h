
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

    const u8 *coms;
    const u8 *blindingseeds;
    const u8 *longproofs;

    u16 run_indexes[PKPSIG_MAX_N_RUNS_TOTAL];
    u16 Hbuf_reordered[PKPSIG_MAX_N_RUNS_TOTAL];
    u16 z[PKPSIG_MAX_N_RUNS_TOTAL][PKPSIG_MAX_N];
    u8 coms_recovered[PKPSIG_MAX_N_RUNS_TOTAL][PKPSIG_MAX_SIG_CRHASH_BYTES];
} sigverifystate;

msv NS(th_sort_verifyC1)(tht *th);
msv NS(th_sort_verifyC2)(tht *th, int nrs);
#define th_sort_verifyC1 NS(th_sort_verifyC1)
#define th_sort_verifyC2 NS(th_sort_verifyC2)

msv NS(svs_init)(sigverifystate *vst, const pst *ps);
msv NS(svs_set_signature)(sigverifystate *vst, const u8 *sig);
msv NS(svs_recover_run_indexes)(sigverifystate *vst);
msv NS(svs_process_long_proofs)(sigverifystate *vst);
msv NS(svs_recover_commitments_short)(sigverifystate *vst);
MAYBE_STATIC int NS(svs_verify_C2)(sigverifystate *vst);
MAYBE_STATIC int NS(svs_verify_C1)(sigverifystate *vst);
MAYBE_STATIC int NS(svs_verify)(sigverifystate *vst, const u8 *sig, const u8 *msg, size_t msglen);
#define svs_init NS(svs_init)
#define svs_set_signature NS(svs_set_signature)
#define svs_recover_run_indexes NS(svs_recover_run_indexes)
#define svs_process_long_proofs NS(svs_process_long_proofs)
#define svs_recover_commitments_short NS(svs_recover_commitments_short)
#define svs_verify_C2 NS(svs_verify_C2)
#define svs_verify_C1 NS(svs_verify_C1)
#define svs_verify NS(svs_verify)

