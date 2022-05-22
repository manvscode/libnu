# Add new files in alphabetical order. Thanks.
libnu_src = netutils.c icmp.c ping.c send.c recv.c

# Add new files in alphabetical order. Thanks.
libnu_headers = netutils.h

library_includedir      = $(includedir)/nu-@VERSION@/
library_include_HEADERS = $(libnu_headers)


# Library
lib_LTLIBRARIES                      = $(top_builddir)/lib/libnu.la
__top_builddir__lib_libnu_la_SOURCES = $(libnu_src)
__top_builddir__lib_libnu_la_CFLAGS  = -fPIC
__top_builddir__lib_libnu_la_LDFLAGS = -lm
