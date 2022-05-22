SUBDIRS = src examples
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nu.pc

Android.mk: Makefile.am
	@androgenizer -:PROJECT libnetutils \
    -:REL_TOP $(top_srcdir)/src -:ABS_TOP $(abs_top_srcdir)/src \
    -:SHARED libnetutils \
    -:SOURCES src/shaders.c \
    -:CFLAGS -std=c99 -Wall -O3 \
    -:LDFLAGS -lGL \
    > $@

android: Android.mk
	ndk-build V=1 NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_OUT=./lib

android-clean:
	@ndk-build clean NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_OUT=./lib
	echo "Removing Android.mk"; rm -f Android.mk

