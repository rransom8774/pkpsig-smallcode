
import itertools

c_psets = """\
DEFINE_PARAMSET(B256,53,106,53,c5,c5,shake256,231,138)
DEFINE_PARAMSET(B256,53,106,53,c5,c4,shake256,238,135)
"""

keyfmt_bases = { "B256": 32 }

seclevels = (
    ('c4', 32, 48),
    ('c5', 32, 64),
    ('c6', 48, 64),
)
seclevels_dict = dict()
seclevels_enumdefs = list()
seclevels_array = list()
seclevels_array.append('#include "minipkpsig-common.h"\n')
seclevels_array.append('#include "minipkpsig-pstypes.h"\n')
seclevels_array.append("MAYBE_STATIC const slt NS(seclevels)[] = {\n")
for i, seclevel in zip(itertools.count(0), seclevels):
    name, pbytes, cbytes = seclevel
    seclevels_dict[name] = (i, pbytes, cbytes)
    seclevels_enumdefs.append("#define SECLEVEL_%s %d\n" % (name, i))
    seclevels_array.append('    {"%s",%d,%d},\n' % (name, pbytes, cbytes))
    pass
seclevels_enumdefs.append("#define N_SECLEVELS %d" % len(seclevels))
seclevels_array.append("    {NULL,0,0}\n")
seclevels_array.append("};\n")

pkp_paramsets = list()
paramsets = list()
th_max_total_leaf_bytes = 0
th_max_sort_blocks = 0
th_max_prefix_bytes = 0
th_max_degree = 0
max_n, max_m, max_A_cols = 0, 0, 0
max_kfbase, max_skbytes, max_pkbytes = 0, 0, 0
max_ksl_pbytes, max_ssl_pbytes = 0, 0
max_ksl_cbytes, max_ssl_cbytes = 0, 0
max_nrt, max_nrl = 0, 0

def encode_bytes(M):
    M2 = list()
    if len(M) == 0:
        return 0
    if len(M) == 1:
        nS, m = 0, M[0]
        while m > 1:
            nS += 1
            m = (m+255)//256
            pass
        return nS
    nS = 0
    for i in range(0, len(M)-1, 2):
        m2 = M[i]*M[i+1]
        while m2 >= 16384:
            nS += 1
            m2 = (m2+255)//256
            pass
        M2.append(m2)
        pass
    if len(M) & 1:
        M2.append(M[-1])
        pass
    return nS + encode_bytes(M2)

pset_def_lines = c_psets.strip().split('\n')
for pdline in pset_def_lines:
    if not (pdline.startswith("DEFINE_PARAMSET(") and
            pdline.endswith(")")):
        raise Exception("oops 1")
    pdline = pdline[len("DEFINE_PARAMSET("):-1]
    pdelts = pdline.split(',')
    if len(pdelts) != 9:
        raise Exception("oops 2")
    kf, qs, ns, ms, ksl, ssl, sym, nrss, nrls = pdelts
    kfbase = keyfmt_bases[kf]
    q, n, m = int(qs), int(ns), int(ms)
    max_n = max(max_n, n)
    max_m = max(max_m, m)
    max_A_cols = max(max_A_cols, n - m)
    max_kfbase = max(max_kfbase, kfbase)
    max_skbytes = max(max_skbytes, kfbase*4)
    max_pkbytes = max(max_pkbytes, kfbase*2 + encode_bytes((q,)*m))
    nrs, nrl = int(nrss), int(nrls) # number of runs, short- and long-proof
    pps = (q, n, m, kfbase, ksl)
    if pps not in pkp_paramsets:
        pkp_paramsets.append(pps)
        pass
    ppsname = "q%dn%dm%dk%s" % (q, n, m, ksl)
    nrt = nrs+nrl # number of runs total
    ssl_pbytes, ssl_cbytes = seclevels_dict[ssl][1:]
    ssl_minimal_runs = ssl_pbytes * 8 # easily computed lower bound on nrt
    nrtx = nrt - ssl_minimal_runs
    leaves_C1 = nrt*2
    leaf_bytes_C1 = ssl_cbytes
    leaves_C2 = nrt
    leaf_bytes_C2 = n*2
    th_max_total_leaf_bytes = max(th_max_total_leaf_bytes,
        leaves_C1 * leaf_bytes_C1, leaves_C2 * leaf_bytes_C2)
    th_max_sort_blocks = max(th_max_sort_blocks, nrt*2)
    ksl_pbytes, ksl_cbytes = seclevels_dict[ksl][1:]
    max_ksl_pbytes = max(max_ksl_pbytes, ksl_pbytes)
    max_ssl_pbytes = max(max_ssl_pbytes, ssl_pbytes)
    max_ksl_cbytes = max(max_ksl_cbytes, ksl_cbytes)
    max_ssl_cbytes = max(max_ssl_cbytes, ssl_cbytes)
    max_nrt = max(max_nrt, nrt)
    max_nrl = max(max_nrl, nrl)
    th_max_prefix_bytes = 2 * ksl_cbytes
    th_degree = (136*4 - 16 - 2*ksl_cbytes) / ssl_cbytes
    th_max_degree = max(th_max_degree, th_degree)
    if sym == "shake256":
        paramsets.append((ppsname, ssl, nrtx, nrl))
        pass
    pass

pps_enumdefs = list()
pps_array = list()
pps_array.append("MAYBE_STATIC const ppst NS(pkp_paramsets)[] = {\n")
for i, pps in zip(itertools.count(0), pkp_paramsets):
    q, n, m, kfbase, ksl = pps
    ppsname = "q%dn%dm%dk%s" % (q, n, m, ksl)
    pps_enumdefs.append("#define PPS_%s %d\n" % (ppsname, i))
    pps_array.append("    {%d,%d,%d,%d,SECLEVEL_%s},\n" % (q,n,m,kfbase,ksl))
    pass
pps_array.append("    {0,0,0,0,0}\n")
pps_array.append("};\n")

ps_array = list()
ps_array.append("MAYBE_STATIC const pst NS(paramsets)[] = {\n")
for pset in paramsets:
    ps_array.append("    {PPS_%s,0,SECLEVEL_%s,%d,%d},\n" % pset)
    pass
ps_array.append("    {0,0,0,0,0}\n")
ps_array.append("};\n")

with open("minipkpsig-seclevels-auto.h", "w") as f:
    for l in seclevels_enumdefs:
        f.write(l)
        pass
    pass
with open("minipkpsig-seclevels-auto.c", "w") as f:
    for l in seclevels_array:
        f.write(l)
        pass
    pass

with open("minipkpsig-paramsets-auto.h", "w") as f:
    f.write("#define PKPSIG_MAX_N %d\n" % max_n)
    f.write("#define PKPSIG_MAX_M %d\n" % max_m)
    f.write("#define PKPSIG_MAX_A_COLS %d\n" % max_A_cols)
    f.write("#define PKPSIG_MAX_KF_BASE %d\n" % max_kfbase)
    f.write("#define PKPSIG_MAX_SECRET_KEY_BYTES %d\n" % max_skbytes)
    f.write("#define PKPSIG_MAX_PUBLIC_KEY_BYTES %d\n" % max_pkbytes)
    f.write("#define PKPSIG_MAX_KEY_PREIMAGE_BYTES %d\n" % max_ksl_pbytes)
    f.write("#define PKPSIG_MAX_KEY_CRHASH_BYTES %d\n" % max_ksl_cbytes)
    f.write("#define PKPSIG_MAX_SIG_CRHASH_BYTES %d\n" % max_ssl_cbytes)
    f.write("#define PKPSIG_MAX_N_RUNS_TOTAL %d\n" % max_nrt)
    f.write("#define PKPSIG_MAX_N_RUNS_LONG %d\n" % max_nrl)
    f.write("#define N_PKP_PARAMSETS %d\n" % len(pkp_paramsets))
    f.write("#define N_PARAMSETS %d\n" % len(paramsets))
    pass
with open("minipkpsig-paramsets-auto.c", "w") as f:
    f.write('#include "minipkpsig-common.h"\n')
    f.write('#include "minipkpsig-pstypes.h"\n')
    f.write('#include "minipkpsig-seclevels-auto.h"\n')
    for l in pps_enumdefs + pps_array + ps_array:
        f.write(l)
        pass
    pass

with open("minipkpsig-treehash-auto.h", "w") as f:
    f.write("#define TH_MAX_TOTAL_LEAF_BYTES %d\n" % th_max_total_leaf_bytes)
    f.write("#define TH_MAX_SORT_BLOCKS %d\n" % th_max_sort_blocks)
    f.write("#define TH_MAX_PREFIX_BYTES %d\n" % th_max_prefix_bytes)
    f.write("#define TH_MAX_DEGREE %d\n" % th_max_degree)
    pass

