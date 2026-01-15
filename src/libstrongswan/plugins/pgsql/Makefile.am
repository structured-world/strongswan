AM_CPPFLAGS = \
    -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
    $(PLUGIN_CFLAGS) $(PGSQL_CFLAGS)

AM_LDFLAGS = \
    $(PGSQL_LIBS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pgsql.la
else
plugin_LTLIBRARIES = libstrongswan-pgsql.la
endif

libstrongswan_pgsql_la_SOURCES = \
    pgsql_database.h pgsql_database.c \
    pgsql_plugin.h pgsql_plugin.c

libstrongswan_pgsql_la_LDFLAGS = -module -avoid-version
libstrongswan_pgsql_la_LIBADD = -lpq
