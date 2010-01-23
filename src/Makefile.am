AM_LDFLAGS = -avoid-version -module -shared
lib_LTLIBRARIES = libccwrap.la
include_HEADERS = libccwrap.h

libccwrap_la_SOURCES = libccwrap.c
libccwrap_la_LIBADD = $(PTHREAD_LIBS) $(LTDL_LIBS)
libccwrap_la_CFLAGS = $(PTHREAD_CFLAGS) $(AM_CFLAGS)
