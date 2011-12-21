
# Local macros
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS	= testasm
lib_LTLIBRARIES	= libor1ktrace.la 

BINUTILS_DIR = @BINUTILS_BLD_DIR@

# the actual libor1ktrace
libor1ktrace_la_SOURCES	=	or1ktrace.c \
				or1ktrace.h \
				spr-defs.h

libor1ktrace_la_CFLAGS = -I$(BINUTILS_DIR)/bfd \
			-I$(BINUTILS_DIR)/opcodes

libor1ktrace_la_LDFLAGS = \
			-Wl,--whole-archive		\
			-L$(BINUTILS_DIR)/bfd 		\
			-L$(BINUTILS_DIR)/opcodes 	\
			-lopcodes -lbfd			\
			-Wl,--no-whole-archive

# A little command-line interface program
testasm_SOURCES 	= test-asm.c
testasm_LDADD	= libor1ktrace.la
testasm_LDFLAGS = -lor1ktrace -liberty -lz



