bin_PROGRAMS=ecr_test run_test

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

ecr_test_LDFLAGS	=-lpthread -latomic_ops -lrt -lcrypto -lstdc++ -lssl -lsasl2


run_test_SOURCES	= \
	run_test.c \
	http_decoder_test.c

run_test_CFLAGS	=-Wall $(shell pkg-config --cflags libmongoc-1.0)

run_test_LDADD		= \
	/usr/local/lib/libecr.a \
	/usr/local/lib/libzmq.a \
	/usr/local/lib/libmongoc-1.0.a \
	/usr/local/lib/libbson-1.0.a \
	/usr/local/lib/libz.a \
	/usr/local/lib/libpcap.a \
	/usr/local/lib/liblzo2.a \
	/usr/local/lib/libcunit.a

run_test_LDFLAGS	= \
	-lpthread -latomic_ops -lrt -lcrypto -lstdc++ -lssl -lcurses -lsasl2
