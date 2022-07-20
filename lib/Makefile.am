lib_LTLIBRARIES = libopensslapis.la
libopensslapis_la_SOURCES = rsa.c evp.c cert.c passwd.c
libopensslapis_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror -DOPENSSL_SUPPRESS_DEPRECATED
AUTOMAKE_OPTIONS = foreign subdir-objects
