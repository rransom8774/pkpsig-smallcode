
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
#include "minipkpsig-seclevels-auto.h"

msv NS(shake256_xof_chunked)(NS(chunkt) *out, NS(chunkt) in[]);

#define N_SYMALGS 3
MAYBE_STATIC const symt symalgs[] = {
    {"shake256", SECLEVEL_c6, NS(shake256_xof_chunked)},
    {"xoesch256", SECLEVEL_c2, NULL},
    {"xoesch384", SECLEVEL_c4, NULL},
    {"", 0, NULL}
};

