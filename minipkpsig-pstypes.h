
typedef struct {
    const char *name;
    u8 pbytes, cbytes;
} slt;
typedef struct {
    u16 q; u8 n, m;
    u8 kf_base;
    u8 ksl;
} ppst;
typedef struct {
    u8 pps;
    u8 sym;
    u8 ssl;
    u8 nrtx, nrl;
} pst;

#define seclevels NS(seclevels)
#define pkp_paramsets NS(pkp_paramsets)
#define paramsets NS(paramsets)

