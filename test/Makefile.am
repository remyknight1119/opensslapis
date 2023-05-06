bin_PROGRAMS = osslapis_test
osslapis_test_SOURCES = api_test.c evp.c cert.c rsa.c hmac.c aes.c des.c dsa.c \
						ec.c camellia.c rc4.c chacha20_poly1305.c chacha20.c
osslapis_test_LDADD = $(srcdir)/../lib/libosslapis.la

AM_CPPFLAGS = -I$(srcdir)/../include -I$(srcdir)/../lib
AM_CFLAGS = -Wall -Werror -DOPENSSL_SUPPRESS_DEPRECATED
