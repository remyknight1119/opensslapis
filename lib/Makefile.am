lib_LTLIBRARIES = libosslapis.la
libosslapis_la_SOURCES = rsa.c evp.c cert.c passwd.c aes.c hmac.c des.c dsa.c \
						 ec.c camellia.c log.c providers.c rc4.c \
						 chacha20_poly1305.c chacha20.c
libosslapis_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror -DOPENSSL_SUPPRESS_DEPRECATED
AUTOMAKE_OPTIONS = foreign subdir-objects
