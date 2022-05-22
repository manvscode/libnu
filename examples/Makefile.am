if ENABLE_EXAMPLES

#AM_CFLAGS = -std=c11 -pg -g -ggdb -O0 -D _DEFAULT_SOURCE -I$(top_builddir)/src/ -I. -I.. -I/usr/local/include/
LDADD = -lm

bin_PROGRAMS = \
$(top_builddir)/bin/ping \
$(top_builddir)/bin/icmp-echo \
$(top_builddir)/bin/traceroute

__top_builddir__bin_icmp_echo_SOURCES     = icmp-echo.c
__top_builddir__bin_icmp_echo_LDFLAGS     = -lm $(top_builddir)/lib/libnu.la
__top_builddir__bin_ping_SOURCES          = ping.c
__top_builddir__bin_ping_LDFLAGS          = -lm $(top_builddir)/lib/libnu.la
__top_builddir__bin_traceroute_SOURCES    = traceroute.c
__top_builddir__bin_traceroute_LDFLAGS    = -lm $(top_builddir)/lib/libnu.la

endif
