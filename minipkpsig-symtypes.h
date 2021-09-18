
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

typedef void (*sym_xof_chunked)(NS(chunkt) *out, NS(chunkt) in[]);
typedef struct {
    char name[15];
    u8 maxsl;
    sym_xof_chunked xof_chunked;
} symt;

#define N_SYMALGS 3
#define symalgs NS(symalgs)

