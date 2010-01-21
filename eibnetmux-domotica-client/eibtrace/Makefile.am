#
# eibnetmux - eibnet/ip multiplexer
# sample: eibtrace
#

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -Wall  -Wstrict-prototypes -I ../mylib

MAINTAINERCLEANFILES    = Makefile.in

noinst_PROGRAMS = eibtrace

eibtrace_SOURCES = eibtrace.c
eibtrace_LDADD = ../mylib/libmy.a @LIBENMX_LIBS@ -lm
