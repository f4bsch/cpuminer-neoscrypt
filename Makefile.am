
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  sha2.c scrypt.c \
		  neoscrypt.c neoscrypt.h
if USE_ASM
minerd_SOURCES += neoscrypt_asm.S
if ARCH_x86
minerd_SOURCES += sha2-x86.S scrypt-x86.S 
endif
if ARCH_x86_64
minerd_SOURCES += sha2-x64.S scrypt-x64.S
endif
if ARCH_ARM
minerd_SOURCES += sha2-arm.S scrypt-arm.S
endif
endif
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= /local/lib/libcurl.a @JANSSON_LIBS@ /c/MinGW/lib/libpthread.a -lwldap32 @WS2_LIBS@
minerd_CPPFLAGS = -I/local/include -DCURL_STATICLIB -O3 -fomit-frame-pointer -DASM -DOPT -DMINER_4WAY -DSHA256
#minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@

