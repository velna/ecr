ACLOCAL_AMFLAGS=-I m4

COMMIT_SHA0=`cat commit_sha.h`
COMMIT_SHA1=\#define COMMIT_SHA \"`git log -n 1 --pretty=format:%H`\"
$(shell test "${COMMIT_SHA0}" = "${COMMIT_SHA1}" || echo "${COMMIT_SHA1}" > commit_sha.h )


SUBDIRS=src src/xcmd test
