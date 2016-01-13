#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([libecr], [1.0], [velna@vicfast.com])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

ECR_VERSION="1:0:0"
AC_SUBST(ECR_VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_PROG_CC_C_O

AC_DEFINE([_GNU_SOURCE], [], [use gnu source])
AC_DEFINE([MONGO_HAVE_UNISTD], [], [mongo have unistd])

AC_ARG_ENABLE([mongo],
    [AS_HELP_STRING([--enable-mongo], [default disable])],
    [mongo=$enableval],
    [mongo=no])
if test $mongo != no; then
	AC_DEFINE([ECR_ENABLE_MONGO], [], [enable mongo])
fi

AC_ARG_ENABLE([pfring],
    [AS_HELP_STRING([--enable-pfring], [default disable])],
    [pfring=$enableval],
    [pfring=no])
if test $pfring != no; then
	AC_DEFINE([ECR_ENABLE_PFRING], [], [enable pfring])
fi

AC_ARG_ENABLE([kafka],
    [AS_HELP_STRING([--enable-kafka], [default disable])],
    [kafka=$enableval],
    [kafka=no])
AM_CONDITIONAL([ECR_ENABLE_KAFKA], [test x$kafka != xno])
if test $kafka != no; then
	AC_DEFINE([ECR_ENABLE_KAFKA], [], [enable kafka])
fi

AC_ARG_ENABLE([lzo],
    [AS_HELP_STRING([--enable-lzo], [default disable])],
    [lzo=$enableval],
    [lzo=no])
AM_CONDITIONAL([ECR_ENABLE_LZO], [test x$lzo != xno])
if test $lzo != no; then
	AC_DEFINE([ECR_ENABLE_LZO], [], [enable lzo])
fi

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/socket.h unistd.h netinet/in.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memmove memset strchr strdup strerror])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 test/Makefile])
AC_OUTPUT

echo "
========================
configure results:
------------------------
enable_mongo:           $mongo
enable_pfring:          $pfring
enable_kafka:           $kafka
enable_lzo:             $lzo
========================
"
