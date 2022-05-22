
AC_PREREQ(2.67)
AC_INIT([libnu], [1.0], [manvscode@manvscode.com], [libnu], [http://joemarrero.com/])
AM_INIT_AUTOMAKE([1.13 foreign silent-rules -Wall -Werror])

AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([src/libnu-config.h])

AC_PROG_CC
AC_PROG_CC_C99
AC_C_INLINE
AC_HEADER_STDC

AH_TOP([
#ifndef _LIBNETUTILS_H_
#define _LIBNETUTILS_H_
])
AH_BOTTOM([
#endif /* _LIBNETUTILS_H_ */
])

AM_PROG_AR
LT_INIT([static])
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

# -------------------------------------------------
AC_ARG_ENABLE([examples],
	[AS_HELP_STRING([--disable-examples], [Enable example programs.])],
	[:],
	[enable_examples=no])

AM_CONDITIONAL([ENABLE_EXAMPLES], [test "$enable_examples" = "yes"])
# -------------------------------------------------

AC_PROG_INSTALL

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    examples/Makefile
    nu.pc
])

AC_OUTPUT

