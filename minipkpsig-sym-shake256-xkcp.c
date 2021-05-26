
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "minipkpsig-common.h"
#include "minipkpsig-symtypes.h"

#include <XKCP/KeccakSponge.h>

msv NS(shake256_xof_chunked)(NS(chunkt) *out, NS(chunkt) in[]) {
    KeccakWidth1600_SpongeInstance hst;

    /* constants from XKCP SimpleFIPS202.c */
    KeccakWidth1600_SpongeInitialize(&hst, 1088, 512);
    while (in->p != NULL) {
        KeccakWidth1600_SpongeAbsorb(&hst, in->p, in->bytes);
        ++in;
    }
    KeccakWidth1600_SpongeAbsorbLastFewBits(&hst, 0x1F);
    KeccakWidth1600_SpongeSqueeze(&hst, out->p, out->bytes);
}

