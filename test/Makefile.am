bin_PROGRAMS=ecr_test

ecr_test_SOURCES=ecr_test.c

ecr_test_CFLAGS	=-Wall $(shell pkg-config --cflags libmongoc-1.0)

ecr_test_LDADD		= \
	/usr/local/lib/libecr.a \
	/usr/local/lib/libzmq.a \
	/usr/local/lib/libmongoc-1.0.a \
	/usr/local/lib/libbson-1.0.a \
	/usr/local/lib/libz.a \
	/usr/local/lib/libpcap.a \
	/usr/local/lib/liblzo2.a

ecr_test_LDFLAGS	=-lpthread -latomic_ops -lrt -lcrypto -lstdc++ -lssl