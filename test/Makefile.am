bin_PROGRAMS = opensslapis_test
opensslapis_test_SOURCES = api_test.c evp.c cert.c
opensslapis_test_LDADD = $(srcdir)/../lib/libopensslapis.la

AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/../lib
AM_CFLAGS = -Wall -Werror
