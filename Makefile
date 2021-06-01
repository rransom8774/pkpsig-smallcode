
.PHONY: test-bin clean

test-bin: gentestvecs-modvc test-th-sorting

clean:
	-rm -v gentestvecs-modvc test-th-sorting
	-rm -v *.o


gentestvecs-modvc: gentestvecs-modvc.o minipkpsig-modvc.o minipkpsig-common.o
	cc -g -o $@ $+ -lXKCP

test-th-sorting: test-th-sorting.o minipkpsig-sig-verify.o minipkpsig-sig-common.o minipkpsig-paramsets-auto.o minipkpsig-seclevels-auto.o minipkpsig-symalgs.o minipkpsig-sym-shake256-xkcp.o minipkpsig-modvc.o minipkpsig-common.o
	cc -g -o $@ $+ -lXKCP

debug-th-sorting: debug-th-sorting.o minipkpsig-sig-verify-debug.o minipkpsig-sig-common.o minipkpsig-paramsets-auto.o minipkpsig-seclevels-auto.o minipkpsig-symalgs.o minipkpsig-sym-shake256-xkcp.o minipkpsig-modvc.o minipkpsig-common.o
	cc -g -o $@ $+ -lXKCP -lpng16


minipkpsig-common.o: minipkpsig-common.c minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-modvc.o: minipkpsig-modvc.c minipkpsig-modvc.h minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-seclevels-auto.o: minipkpsig-seclevels-auto.c minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -o $@ $<
minipkpsig-paramsets-auto.o: minipkpsig-paramsets-auto.c minipkpsig-seclevels-auto.h minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -o $@ $<
minipkpsig-seclevels-auto.c minipkpsig-seclevels-auto.h minipkpsig-paramsets-auto.c minipkpsig-paramsets-auto.h minipkpsig-treehash-auto.h: declare_paramsets.py
	python3 declare_paramsets.py

minipkpsig-sym-shake256-xkcp.o: minipkpsig-sym-shake256-xkcp.c minipkpsig-symtypes.h minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-symalgs.o: minipkpsig-symalgs.c minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-sig-common.o: minipkpsig-sig-common.c minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-sig-verify.o: minipkpsig-sig-verify.c minipkpsig-sig-verify.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-sig-verify-debug.o: minipkpsig-sig-verify.c minipkpsig-sig-verify.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -DMINIPKPSIG_SORT_DEBUG -o $@ $<


gentestvecs-modvc.o: gentestvecs-modvc.c minipkpsig-modvc.h minipkpsig-common.h
	cc -g -c -o $@ $<

test-th-sorting.o: test-th-sorting.c minipkpsig-sig-verify.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -o $@ $<

debug-th-sorting.o: debug-th-sorting.c minipkpsig-sig-verify.h minipkpsig-sig-common.h minipkpsig-treehash-auto.h minipkpsig-paramsets-auto.h minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -I/usr/include/libpng16 -o $@ $<

