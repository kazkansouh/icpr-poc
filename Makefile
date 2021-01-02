CFLAGS=-Wall -Wpedantic -Werror -g\
	$(shell pkg-config dcerpc samba-credentials samba-hostconfig tevent --cflags)
LDLIBS=$(shell pkg-config dcerpc samba-credentials samba-hostconfig tevent --libs) \
	-ltevent-util

default: main

# pidl is part of samba, easiest just get samba source tree
# https://github.com/samba-team/samba/tree/master/pidl
icpr.h ndr_icpr.c ndr_icpr_c.c ndr_icpr_c.h ndr_icpr.h: icpr.idl
	pidl icpr.idl --client --header --ndr-parser

main.o: main.c icpr.h

main: main.o ndr_icpr.o ndr_icpr_c.o

.PHONEY: clean
clean:
	rm -vf main main.o icpr.h ndr_icpr.c ndr_icpr_c.c ndr_icpr_c.h ndr_icpr.h ndr_icpr.o ndr_icpr_c.o
