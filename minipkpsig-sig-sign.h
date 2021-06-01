
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

    u8 pi_inv[PKPSIG_MAX_N];
    u8 skbytes[PKPSIG_MAX_SECRET_KEY_BYTES];
} signstate;

