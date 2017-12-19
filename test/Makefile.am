bin_PROGRAMS=ecr_test run_test stoi

ecr_test_SOURCES=ecr_test.c

ecr_test_CFLAGS	=-Wall $(shell pkg-config --cflags libmongoc-1.0) -I${EXTRA_PACKAGE_INCLUDE_DIR}

ecr_test_LDADD		= \
	${EXTRA_PACKAGE_LIB_DIR}/libecr.a \
	${EXTRA_PACKAGE_LIB_DIR}/libzmq.a \
	${EXTRA_PACKAGE_LIB_DIR}/libmongoc-1.0.a \
	${EXTRA_PACKAGE_LIB_DIR}/libbson-1.0.a \
	${EXTRA_PACKAGE_LIB_DIR}/libz.a \
	${EXTRA_PACKAGE_LIB_DIR}/librdkafka.a \
	${EXTRA_PACKAGE_LIB_DIR}/libpcap.a \
	${EXTRA_PACKAGE_LIB_DIR}/liblzo2.a

ecr_test_LDFLAGS	=-lpthread -latomic_ops -lrt -lcrypto -lstdc++ -lssl


run_test_SOURCES	= \
	run_test.c \
	buf_test.c \
	util_crypto_test.c \
	uri_test.c \
	http_decoder_test.c \
	hypermatch_test.c \
	ipdb_test.c \
	template_test.c \
	tlv_test.c

run_test_CFLAGS	=-Wall $(shell pkg-config --cflags libmongoc-1.0) -I${EXTRA_PACKAGE_INCLUDE_DIR}

run_test_LDADD		= \
	${EXTRA_PACKAGE_LIB_DIR}/libecr.a \
	${EXTRA_PACKAGE_LIB_DIR}/libzmq.a \
	${EXTRA_PACKAGE_LIB_DIR}/libmongoc-1.0.a \
	${EXTRA_PACKAGE_LIB_DIR}/libbson-1.0.a \
	${EXTRA_PACKAGE_LIB_DIR}/libz.a \
	${EXTRA_PACKAGE_LIB_DIR}/libpcap.a \
	${EXTRA_PACKAGE_LIB_DIR}/liblzo2.a \
	${EXTRA_PACKAGE_LIB_DIR}/libcunit.a

run_test_LDFLAGS	= -L${EXTRA_PACKAGE_LIB_DIR}\
	-lpthread -latomic_ops -lrt -lcrypto -lstdc++ -lssl -lcurses -luriparser

	
stoi_SOURCES=stoi.c
