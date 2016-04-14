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
	src/decrypt.c \
	src/encrypt.c

cmse_LDFLAGS = @OPENSSL_LDFLAGS@
cmse_LDADD = @OPENSSL_LIBS@

PWD=Vl0RJlAKiUMf
CLEAR=configure.ac

test: cmse
	if ! [ -f rsa1.pem -a -f crt1.pem ] ; then \
		@OPENSSL_BIN@ req -new -x509 -newkey rsa:1024 -keyout rsa1.pem -out crt1.pem -subj /CN=Foo -set_serial 1 -nodes ; \
	fi
	if ! [ -f rsa2.pem -a -f crt2.pem ] ; then \
		@OPENSSL_BIN@ req -new -x509 -newkey rsa:1024 -keyout rsa2.pem -out crt2.pem -subj /CN=Bar -set_serial 2 -nodes ; \
	fi
#	Encrypt single certificate
	./cmse -e -i $(CLEAR) -o test.enc -r crt1.pem
#	Decrypt back
	./cmse -d -i test.enc -o test.dec -r crt1.pem -k rsa1.pem
	cmp $(CLEAR) test.dec
#	Encrypt two certificates and one password
	./cmse -e -i $(CLEAR) -o test.enc -r crt1.pem -r crt2.pem -p $(PWD)
#	Decrypt back with key/certificate
	./cmse -d -i test.enc -o test.dec -r crt1.pem -k rsa1.pem
	cmp $(CLEAR) test.dec
#	Decrypt back with password
	./cmse -d -i test.enc -o test.dec -p $(PWD)
	cmp $(CLEAR) test.dec
