top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
includedir = ${prefix}/include

CC = gcc
CFLAGS  = -g -Wall \
	-I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include   \
	 \
	-I/usr/include/pbc -I/usr/local/include/pbc \
	-DPACKAGE_NAME=\"libcelia\" -DPACKAGE_TARNAME=\"libcelia\" -DPACKAGE_VERSION=\"0.3\" -DPACKAGE_STRING=\"libcelia\ 0.3\" -DPACKAGE_BUGREPORT=\"zhengyao@wpi.edu\" -DPACKAGE_URL=\"\" -DBSWABE_DEBUG=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_STDINT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 -DHAVE_VPRINTF=1 -DHAVE_LIBCRYPTO=1 -DHAVE_STRDUP=1 -DHAVE_GMP=1 -DHAVE_PBC=1
LDFLAGS = -g -Wall \
	-lglib-2.0   \
	-lgmp \
	-lpbc \
	-lcrypto 

DISTNAME = libcelia-0.3

all: libcelia.a TAGS

# compilation and library making

libcelia.a: core.o misc.o
	rm -f $@
	ar rc $@ $^

# test: test.o libcelia.a
# 	$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c *.h Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

# installation

dist: AUTHORS COPYING INSTALL NEWS README \
	aclocal.m4 acinclude.m4 configure configure.ac Makefile.in \
	install-sh missing mkinstalldirs \
	core.c misc.c celia.h
	rm -rf $(DISTNAME)
	mkdir $(DISTNAME)
	cp $^ $(DISTNAME)
	tar zc $(DISTNAME) > $(DISTNAME).tar.gz
	rm -rf $(DISTNAME)

install: libcelia.a celia.h
	$(top_srcdir)/mkinstalldirs -m 755 $(libdir)
	$(top_srcdir)/mkinstalldirs -m 755 $(includedir)
	$(top_srcdir)/install-sh -m 755 libcelia.a $(libdir)
	$(top_srcdir)/install-sh -m 644 celia.h $(includedir)

uninstall:
	/bin/rm -f $(libdir)/libcelia.a
	/bin/rm -f $(includedir)/celia.h

# development and meta stuff

TAGS: *.c *.h
	@(etags $^ || true) 2> /dev/null

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

configure: configure.ac aclocal.m4
	autoconf

# cleanup

# remove everything an installing user can rebuild
clean:
	rm -rf *.o *.a $(DISTNAME) *.tar.gz TAGS *~

# remove everything a package developer can rebuild
distclean: clean
	rm -rf autom4te.cache Makefile config.status config.log config.cache \
		configure configure.scan autoscan*.log
