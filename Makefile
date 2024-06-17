
.PHONY: test-bin clean

CFLAGS = -g -Wall

test-bin: generate-test-vectors gentestvecs-modvc test-th-sorting

clean:
	-rm -v generate-test-vectors gentestvecs-modvc test-th-sorting
	-rm -v *.o


generate-test-vectors: generate-test-vectors.o randombytes_shake256_deterministic.o minipkpsig-sig-keygen.o minipkpsig-sig-sign.o minipkpsig-sig-verify.o minipkpsig-sig-thsort.o minipkpsig-sig-common.o minipkpsig-paramsets-auto.o minipkpsig-seclevels-auto.o minipkpsig-symalgs.o minipkpsig-sym-shake256-xkcp.o minipkpsig-modvc.o minipkpsig-common.o
	$(CC) $(CFLAGS) -o $@ $+ -lXKCP

gentestvecs-modvc: gentestvecs-modvc.o minipkpsig-modvc.o minipkpsig-common.o
	$(CC) $(CFLAGS) -o $@ $+ -lXKCP

test-th-sorting: test-th-sorting.o minipkpsig-sig-verify.o minipkpsig-sig-thsort.o minipkpsig-sig-common.o minipkpsig-paramsets-auto.o minipkpsig-seclevels-auto.o minipkpsig-symalgs.o minipkpsig-sym-shake256-xkcp.o minipkpsig-modvc.o minipkpsig-common.o
	$(CC) $(CFLAGS) -o $@ $+ -lXKCP

debug-th-sorting: debug-th-sorting.o minipkpsig-sig-verify-debug.o minipkpsig-sig-thsort.o minipkpsig-sig-common.o minipkpsig-paramsets-auto.o minipkpsig-seclevels-auto.o minipkpsig-symalgs.o minipkpsig-sym-shake256-xkcp.o minipkpsig-modvc.o minipkpsig-common.o
	$(CC) $(CFLAGS) -o $@ $+ -lXKCP -lpng16


minipkpsig-common.o: minipkpsig-common.c minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-modvc.o: minipkpsig-modvc.c minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-seclevels-auto.o: minipkpsig-seclevels-auto.c minipkpsig-pstypes.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<
minipkpsig-paramsets-auto.o: minipkpsig-paramsets-auto.c minipkpsig-seclevels-auto.h minipkpsig-pstypes.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<
minipkpsig-seclevels-auto.c minipkpsig-seclevels-auto.h minipkpsig-paramsets-auto.c minipkpsig-paramsets-auto.h minipkpsig-treehash-auto.h: declare_paramsets.py
	python3 declare_paramsets.py

minipkpsig-sym-shake256-xkcp.o: minipkpsig-sym-shake256-xkcp.c minipkpsig-symtypes.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-symalgs.o: minipkpsig-symalgs.c minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-sig-common.o: minipkpsig-sig-common.c minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-tables.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-sig-thsort.o: minipkpsig-sig-thsort.c minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-sig-verify.o: minipkpsig-sig-verify.c minipkpsig-sig-verify.h minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-tables.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-sig-verify-debug.o: minipkpsig-sig-verify.c minipkpsig-sig-verify.h minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-tables.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -DMINIPKPSIG_SORT_DEBUG -o $@ $<

minipkpsig-sig-sign.o: minipkpsig-sig-sign.c minipkpsig-sig-sign.h minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-tables.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

minipkpsig-sig-keygen.o: minipkpsig-sig-keygen.c minipkpsig-sig-keygen.h minipkpsig-sig-sign.h minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<


generate-test-vectors.o: generate-test-vectors.c minipkpsig.h randombytes_shake256_deterministic.h
	$(CC) $(CFLAGS) -c -o $@ $<

randombytes_shake256_deterministic.o: randombytes_shake256_deterministic.c randombytes_shake256_deterministic.h
	$(CC) $(CFLAGS) -c -o $@ $<

gentestvecs-modvc.o: gentestvecs-modvc.c minipkpsig-modvc.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

test-th-sorting.o: test-th-sorting.c minipkpsig-sig-verify.h minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -o $@ $<

debug-th-sorting.o: debug-th-sorting.c minipkpsig-sig-verify.h minipkpsig-sig-thsort.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-common.h minipkpsig.h
	$(CC) $(CFLAGS) -c -I/usr/include/libpng16 -o $@ $<

