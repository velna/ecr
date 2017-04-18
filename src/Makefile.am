bin_PROGRAMS = xcmd

xcmd_SOURCES = ecr/ecr_xcmd_main.c

xcmd_CFLAGS	=-Wall $(shell pkg-config --cflags libmongoc-1.0)
xcmd_LDADD		= \
	/usr/local/lib/libecr.a \
	/usr/local/lib/libzmq.a

xcmd_LDFLAGS	=-lpthread -latomic_ops -lrt -lcrypto -lstdc++

#######################################
# The list of libraries we are building seperated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = libecr.la


#######################################
# Build information for each library
nobase_include_HEADERS = ecr.h ecrconf.h \
	ecr/ecr_app.h \
	ecr/ecr_bloomfilter.h \
	ecr/ecr_buf.h \
	ecr/ecr_bwlist.h \
	ecr/ecr_cmd.h \
	ecr/ecr_config.h \
	ecr/ecr_counter.h \
	ecr/ecr_fixedhashmap.h \
	ecr/ecr_getopt.h \
	ecr/ecr_hashmap.h \
	ecr/ecr_heap.h \
	ecr/ecr_http_decoder.h \
	ecr/ecr_httpparser.h \
	ecr/ecr_io.h \
	ecr/ecr_ipdb.h \
	ecr/ecr_kafka.h \
	ecr/ecr_list.h \
	ecr/ecr_logger.h \
	ecr/ecr_macbind.h \
	ecr/ecr_mempool.h \
	ecr/ecr_pcap.h \
	ecr/ecr_pkware.h \
	ecr/ecr_pub.h \
	ecr/ecr_radius.h \
	ecr/ecr_rebalancer.h \
	ecr/ecr_rollingfile.h \
	ecr/ecr_server.h \
	ecr/ecr_skiplist.h \
	ecr/ecr_template.h \
	ecr/ecr_tlv.h \
	ecr/ecr_uncap.h \
	ecr/ecr_urlmatch.h \
	ecr/ecr_util.h \
	ecr/ecr_wumanber.h

# Sources for ecr
libecr_la_SOURCES = \
	ecr_version.c \
	ecr/ecr_app.c \
	ecr/ecr_bloomfilter.c \
	ecr/ecr_buf.c \
	ecr/ecr_bwlist.c \
	ecr/ecr_bwlist_equals.c \
	ecr/ecr_bwlist_wumanber.c \
	ecr/ecr_bwlist_exists.c \
	ecr/ecr_bwlist_regex.c \
	ecr/ecr_bwlist_urlmatch.c \
	ecr/ecr_cmd.c \
	ecr/ecr_config.c \
	ecr/ecr_counter.c \
	ecr/ecr_fixedhashmap.c \
	ecr/ecr_getopt.c \
	ecr/ecr_hashmap.c \
	ecr/ecr_heap.c \
	ecr/ecr_http_decoder.c \
	ecr/ecr_httpparser.c \
	ecr/ecr_io_gzip.c \
	ecr/ecr_io_lzop.c \
	ecr/ecr_io_rollingfile.c \
	ecr/ecr_ipdb.c \
	ecr/ecr_kafka.c \
	ecr/ecr_list.c \
	ecr/ecr_logger.c \
	ecr/ecr_macbind.c \
	ecr/ecr_mempool.c \
	ecr/ecr_pcap.c \
	ecr/ecr_pkware.c \
	ecr/ecr_pub.c \
	ecr/ecr_radius.c \
	ecr/ecr_rebalancer.c \
	ecr/ecr_rollingfile.c \
	ecr/ecr_server.c \
	ecr/ecr_skiplist.c \
	ecr/ecr_template.c \
	ecr/ecr_tlv.c \
	ecr/ecr_uncap.c \
	ecr/ecr_urlmatch.c \
	ecr/ecr_util.c \
	ecr/ecr_util_base64.c \
	ecr/ecr_util_hash.c \
	ecr/ecr_util_inet.c \
	ecr/ecr_util_string.c \
	ecr/ecr_util_zmq.c \
	ecr/ecr_wumanber.c


# Linker options libTestProgram
libecr_la_LDFLAGS = -version-info @ECR_VERSION@

# Compiler options. Here we are adding the include directory
# to be searched for headers included in the source code.

libecr_la_CFLAGS = -Wall $(shell pkg-config --cflags libmongoc-1.0 zlib)
