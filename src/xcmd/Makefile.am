bin_PROGRAMS = xcmd

xcmd_SOURCES = ecr_xcmd_main.c

xcmd_CFLAGS     =-Wall $(shell pkg-config --cflags libmongoc-1.0) -I${EXTRA_PACKAGE_INCLUDE_DIR}

xcmd_LDADD	= \
	${EXTRA_PACKAGE_LIB_DIR}/libzmq.a

xcmd_LDFLAGS	=-lpthread -latomic_ops -lrt -lstdc++

