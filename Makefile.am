ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

MAINTAINERCLEANFILES = \
    $(srcdir)/Makefile.in \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/compile \
    $(srcdir)/configure \
    $(srcdir)/config.guess \
	$(srcdir)/config.log \
	$(srcdir)/config.status \
	$(srcdir)/config.sub \
    $(srcdir)/depcomp \
    $(srcdir)/install-sh \
	$(srcdir)/ltmain.sh \
	$(srcdir)/missing \
    $(srcdir)/src/config.h.in

EXTRA_DIST = \
		$(srcdir)/README.md \
		$(srcdir)/src/*.h \
		$(srcdir)/m4/*.m4

AM_CFLAGS = @OPENSSL_INCLUDES@ \
	 ${my_CFLAGS} \
	-I$(srcdir)/src

bin_PROGRAMS = cmse

cmse_SOURCES = \
	src/cmse.c \
	src/common.c \
	src/encrypt.c

cmse_LDFLAGS = @OPENSSL_LDFLAGS@
cmse_LDADD = @OPENSSL_LIBS@

PWD=Vl0RJlAKiUMf

test: cmse
