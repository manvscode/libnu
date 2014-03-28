if ENABLE_TESTS

AM_CFLAGS = -std=c11 -pg -g -ggdb -O0 -I$(top_builddir)/src/ -I. -I.. -I/usr/local/include/
AM_CXXFLAGS = -std=c++0x -pg -g -ggdb -O0 -I$(top_builddir)/src/ -I. -I.. -I/usr/local/include/
LDADD = -lm 

bin_PROGRAMS = \
$(top_builddir)/bin/test-ping \
$(top_builddir)/bin/test-traceroute

__top_builddir__bin_test_ping_SOURCES          = test-ping.c
__top_builddir__bin_test_ping_LDFLAGS          = -lm $(top_builddir)/lib/libnetutils.la
__top_builddir__bin_test_traceroute_SOURCES    = test-traceroute.c
__top_builddir__bin_test_traceroute_LDFLAGS    = -lm $(top_builddir)/lib/libnetutils.la

endif
