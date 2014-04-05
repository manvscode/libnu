# Add new files in alphabetical order. Thanks.
libnetutils_src = netutils.c icmp.c ping.c send.c recv.c

# Add new files in alphabetical order. Thanks.
libnetutils_headers = netutils.h 

library_includedir      = $(includedir)/libnetutils/
library_include_HEADERS = $(libnetutils_headers)

# Library
lib_LTLIBRARIES                            = $(top_builddir)/lib/libnetutils.la
__top_builddir__lib_libnetutils_la_SOURCES = $(libnetutils_src)
__top_builddir__lib_libnetutils_la_LDFLAGS = -lm 
