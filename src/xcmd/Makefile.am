bin_PROGRAMS = xcmd

xcmd_SOURCES = ecr_xcmd_main.c

xcmd_CFLAGS     =-Wall $(shell pkg-config --cflags libmongoc-1.0)
xcmd_LDADD              = \
        /usr/local/lib/libecr.a \
        /usr/local/lib/libzmq.a

xcmd_LDFLAGS    =-lpthread -latomic_ops -lrt -lcrypto -lstdc++
