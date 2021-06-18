
import itertools

c_psets = """\
DEFINE_PARAMSET(B128,797,55,25,c1a,c1a,shake256,127,73)
DEFINE_PARAMSET(B128,797,55,25,c1a,c1,shake256,105,57)
DEFINE_PARAMSET(B128,797,55,25,c1a,b112,shake256,99,47)
DEFINE_PARAMSET(B128,797,55,25,c1a,b112git,shake256,99,47)
DEFINE_PARAMSET(B128,797,55,25,c1a,b96,shake256,83,41)
DEFINE_PARAMSET(B128,797,55,25,c1a,b80,shake256,67,35)
DEFINE_PARAMSET(B128,977,61,28,c1,c1,shake256,108,55)
DEFINE_PARAMSET(B128,977,61,28,c2,c2,shake256,158,84)
DEFINE_PARAMSET(B128,977,61,28,c2,c1a,shake256,135,69)
DEFINE_PARAMSET(B128,977,61,28,c2,c1,shake256,108,55)
DEFINE_PARAMSET(B128,977,61,28,c2,b112,shake256,95,48)
DEFINE_PARAMSET(B128,977,61,28,c2,b112git,shake256,95,48)
DEFINE_PARAMSET(B128,977,61,28,c2,b96,shake256,80,42)
DEFINE_PARAMSET(B128,977,61,28,c2,b80,shake256,72,33)
DEFINE_PARAMSET(B192,1409,87,42,c4,c4,shake256,216,108)
DEFINE_PARAMSET(B192,1409,87,42,c4,c3,shake256,160,82)
DEFINE_PARAMSET(B192,1409,87,42,c4,c2,shake256,178,76)
DEFINE_PARAMSET(B192,1409,87,42,c4,c1a,shake256,143,65)
DEFINE_PARAMSET(B192,1409,87,42,c4,c1,shake256,115,52)
DEFINE_PARAMSET(B192,1409,87,42,c4,b112,shake256,105,44)
DEFINE_PARAMSET(B192,1409,87,42,c4,b112git,shake256,105,44)
DEFINE_PARAMSET(B192,1409,87,42,c4,b96,shake256,83,40)
DEFINE_PARAMSET(B192,1409,87,42,c4,b80,shake256,77,31)
DEFINE_PARAMSET(B256,1789,111,55,c5,c5,shake256,232,102)
DEFINE_PARAMSET(B256,1789,111,55,c5,c4,shake256,242,99)
DEFINE_PARAMSET(B256,1789,111,55,c5,c3,shake256,176,76)
DEFINE_PARAMSET(B256,1789,111,55,c5,c2,shake256,199,70)
DEFINE_PARAMSET(B256,1789,111,55,c5,c1a,shake256,163,59)
DEFINE_PARAMSET(B256,1789,111,55,c5,c1,shake256,136,46)
DEFINE_PARAMSET(B256,1789,111,55,c5,b112,shake256,112,42)
DEFINE_PARAMSET(B256,1789,111,55,c5,b112git,shake256,121,40)
DEFINE_PARAMSET(B256,1789,111,55,c5,b96,shake256,100,35)
DEFINE_PARAMSET(B256,1789,111,55,c5,b80,shake256,85,29)
DEFINE_PARAMSET(B256,1789,111,55,c6,c6,shake256,314,164)
DEFINE_PARAMSET(B256,1789,111,55,c6,c5,shake256,203,112)
DEFINE_PARAMSET(B256,1789,111,55,c6,c4,shake256,211,109)
DEFINE_PARAMSET(B256,1789,111,55,c6,c3,shake256,158,82)
DEFINE_PARAMSET(B256,1789,111,55,c6,c2,shake256,176,76)
DEFINE_PARAMSET(B256,1789,111,55,c6,c1a,shake256,148,63)
DEFINE_PARAMSET(B256,1789,111,55,c6,c1,shake256,113,52)
DEFINE_PARAMSET(B256,1789,111,55,c6,b112,shake256,100,45)
DEFINE_PARAMSET(B256,1789,111,55,c6,b112git,shake256,100,45)
DEFINE_PARAMSET(B256,1789,111,55,c6,b96,shake256,85,39)
DEFINE_PARAMSET(B256,1789,111,55,c6,b80,shake256,72,32)
"""

keyfmt_bases = { "B128": 16, "B192": 24, "B256": 32 }

seclevels = (
    ('b80', 10, 20),
    ('b96', 12, 24),
    ('b112git', 14, 20),
    ('b112', 14, 28),
    ('c1', 16, 32),
    ('c1a', 20, 32),
    ('c2', 24, 32),
    ('c3', 24, 48),
    ('c4', 32, 48),
    ('c5', 32, 64),
    ('c6', 48, 64),
)
seclevels_dict = dict()
seclevels_enumdefs = list()
seclevels_array = list()
seclevels_array.append('#include "minipkpsig-common.h"\n')
seclevels_array.append('#include "minipkpsig-pstypes.h"\n')
seclevels_array.append("MAYBE_STATIC const slt seclevels[] = {\n")
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
    max_skbytes = max(max_skbytes, (kfbase//2)*11 + 1)
    max_pkbytes = max(max_pkbytes, kfbase+1 + encode_bytes((q,)*m))
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
    leaf_bytes_C2 = n*3
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
pps_array.append("MAYBE_STATIC const ppst pkp_paramsets[] = {\n")
for i, pps in zip(itertools.count(0), pkp_paramsets):
    q, n, m, kfbase, ksl = pps
    ppsname = "q%dn%dm%dk%s" % (q, n, m, ksl)
    pps_enumdefs.append("#define PPS_%s %d\n" % (ppsname, i))
    pps_array.append("    {%d,%d,%d,%d,SECLEVEL_%s},\n" % (q,n,m,kfbase,ksl))
    pass
pps_array.append("    {0,0,0,0,0}\n")
pps_array.append("};\n")

ps_array = list()
ps_array.append("MAYBE_STATIC const pst paramsets[] = {\n")
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

