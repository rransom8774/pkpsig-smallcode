
.PHONY: test-bin clean

test-bin: gentestvecs-modvc

clean:
	-rm -v gentestvecs-modvc
	-rm -v *.o


gentestvecs-modvc: gentestvecs-modvc.o minipkpsig-modvc.o
	cc -g -o $@ $+ -lXKCP


minipkpsig-modvc.o: minipkpsig-modvc.c minipkpsig-modvc.h minipkpsig-common.h
	cc -g -c -o $@ $<

gentestvecs-modvc.o: gentestvecs-modvc.c minipkpsig-modvc.h minipkpsig-common.h
	cc -g -c -o $@ $<



