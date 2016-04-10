define([CMSE_VERSION_MAJOR], [0])
define([CMSE_VERSION_MINOR], [1])
define([CMSE_VERSION_PATCH], [0])
define([VERSION_SUFFIX], [])

AC_PREREQ(2.64)
AC_INIT([cms-encrypt],[CMSE_VERSION_MAJOR.CMSE_VERSION_MINOR.CMSE_VERSION_PATCH[]VERSION_SUFFIX])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects)
AC_USE_SYSTEM_EXTENSIONS

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_EGREP

AC_C_BIGENDIAN

AC_CHECK_HEADERS([getopt.h])
AC_CHECK_FUNCS([getopt_long])

AX_CHECK_OPENSSL
if test x"$OPENSSL_LIBS" != x""; then
   AC_DEFINE_UNQUOTED([HAVE_OPENSSL], [1], [Compiled with OpenSSL])
   CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
fi
AC_SUBST([HAVE_OPENSSL])

AC_CONFIG_FILES([Makefile])

AC_CACHE_SAVE

AC_OUTPUT

AC_MSG_RESULT([
        $PACKAGE $VERSION
        =====

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}

        openssl binary:         ${OPENSSL_BIN}
])
