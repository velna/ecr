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

AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_PROG_CC_C_O

AC_DEFINE([_GNU_SOURCE], [], [use gnu source])
AC_DEFINE([MONGO_HAVE_UNISTD], [], [mongo have unistd])

# Checks for libraries.

AC_ARG_ENABLE([pfring],
    [AS_HELP_STRING([--enable-pfring], [enable pfring, default disable])],
    [pfring=$enableval],
    [pfring=no])
AM_CONDITIONAL([ENABLE_PFRING], [test x$pfring != xno])
if test $pfring != no; then
        AC_DEFINE([ENABLE_PFRING], [], [enable pfring])
fi


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
                 src/xcmd/Makefile
                 test/Makefile])
AC_OUTPUT

echo "
========================
configure results:
------------------------
enable_pfring:          $pfring
========================
"
