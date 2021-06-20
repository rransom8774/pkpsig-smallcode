
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

MAYBE_STATIC int NS(scs_check_v)(sigcommonstate *cst);
MAYBE_STATIC int NS(sst_keypair)(signstate *sst);
msv NS(sst_get_skblob)(signstate *sst, u8 *skbytes);
#define scs_check_v NS(scs_check_v)
#define sst_keypair NS(sst_keypair)
#define sst_get_skblob NS(sst_get_skblob)

int NS(simple_keypair)(const char *psname, u8 *pk_out, u8 *sk_out);

