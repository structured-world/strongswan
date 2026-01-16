AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-dhcp-inform.la
else
plugin_LTLIBRARIES = libstrongswan-dhcp-inform.la
endif

libstrongswan_dhcp_inform_la_SOURCES = \
	dhcp_inform_plugin.h dhcp_inform_plugin.c \
	dhcp_inform_responder.h dhcp_inform_responder.c

libstrongswan_dhcp_inform_la_LDFLAGS = -module -avoid-version
