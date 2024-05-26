#include "minipkpsig-common.h"
#include "minipkpsig-pstypes.h"
#include "minipkpsig-seclevels-auto.h"
#define PPS_q53n106m53kc5 0
#define PPS_q59n118m59kc5 1
MAYBE_STATIC const ppst NS(pkp_paramsets)[] = {
    {53,106,53,32,SECLEVEL_c5},
    {59,118,59,32,SECLEVEL_c5},
    {0,0,0,0,0}
};
MAYBE_STATIC const pst NS(paramsets)[] = {
    {PPS_q53n106m53kc5,0,SECLEVEL_c5,113,138},
    {PPS_q53n106m53kc5,0,SECLEVEL_c4,117,135},
    {PPS_q59n118m59kc5,0,SECLEVEL_c5,110,136},
    {0,0,0,0,0}
};
