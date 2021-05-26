
typedef struct {
    char name[15];
    u8 maxsl;
    void (*xof_chunked)(NS(chunkt) *out, NS(chunkt) *in[]);
} symt;

