
# Local macros
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS	= testasm
lib_LTLIBRARIES	= libor1ktrace.la 

BINUTILS_BUILD_DIR = @BINUTILS_BLD_DIR@
BINUTILS_SOURCE_DIR = @BINUTILS_SRC_DIR@

# the actual libor1ktrace
libor1ktrace_la_SOURCES	=	or1ktrace.c \
				or1ktrace.h \
				spr-defs.h

libor1ktrace_la_CFLAGS = -I$(BINUTILS_BUILD_DIR)/bfd 		\
			-I$(BINUTILS_BUILD_DIR)/opcodes 	\
			-I$(BINUTILS_SOURCE_DIR)/opcodes 	\
			-I$(BINUTILS_SOURCE_DIR)/include

libor1ktrace_la_LDFLAGS = \
			-Wl,--whole-archive			\
			-L$(BINUTILS_BUILD_DIR)/bfd 		\
			-L$(BINUTILS_BUILD_DIR)/libiberty 	\
			-L$(BINUTILS_BUILD_DIR)/opcodes 	\
			-lopcodes -lbfd	-liberty		\
			-Wl,--no-whole-archive

# A little command-line interface program
testasm_SOURCES 	= test-asm.c
testasm_LDADD	= libor1ktrace.la
testasm_LDFLAGS = -lor1ktrace -liberty -lz



