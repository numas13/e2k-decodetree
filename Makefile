CFLAGS := -O2

.PHONY : all build clean

all : build

build : main

clean :
	$(RM) main

main : main.c e2k-opc.c e2k.h
	$(CC) $(CFLAGS) main.c e2k-opc.c -o $@

