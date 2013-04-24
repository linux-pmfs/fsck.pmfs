WARN=-Wall -Wwrite-strings -Wconversion -Wformat=2 -Wno-parentheses \
       -Wno-conversion -Wbad-function-cast -Wstrict-prototypes \
       -Wmissing-prototypes -Wmissing-declarations

CFLAGS=$(WARN) -Werror -O2
LDFLAGS=-O2

fsck.pmfs : fsck.pmfs.o crc16.o

fsck.pmfs.o : types.h crc16.h pmfs_def.h
crc16.o : types.h crc16.h
