
.PHONY: test-bin clean

test-bin: gentestvecs-modvc

clean:
	-rm -v gentestvecs-modvc
	-rm -v *.o


gentestvecs-modvc: gentestvecs-modvc.o minipkpsig-modvc.o
	cc -g -o $@ $+ -lXKCP


minipkpsig-modvc.o: minipkpsig-modvc.c minipkpsig-modvc.h minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-seclevels-auto.o: minipkpsig-seclevels-auto.c minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -o $@ $<
minipkpsig-paramsets-auto.o: minipkpsig-paramsets-auto.c minipkpsig-seclevels-auto.h minipkpsig-pstypes.h minipkpsig-common.h
	cc -g -c -o $@ $<
minipkpsig-seclevels-auto.c minipkpsig-seclevels-auto.h minipkpsig-paramsets-auto.c minipkpsig-paramsets-auto.h: declare_paramsets.py
	python3 declare_paramsets.py

minipkpsig-sym-shake256-xkcp.o: minipkpsig-sym-shake256-xkcp.c minipkpsig-symtypes.h minipkpsig-common.h
	cc -g -c -o $@ $<

minipkpsig-symalgs.o: minipkpsig-symalgs.c minipkpsig-seclevels-auto.h minipkpsig-symtypes.h minipkpsig-common.h
	cc -g -c -o $@ $<


gentestvecs-modvc.o: gentestvecs-modvc.c minipkpsig-modvc.h minipkpsig-common.h
	cc -g -c -o $@ $<



