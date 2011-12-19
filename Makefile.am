
# Local macros
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS	= test-asm
lib_LTLIBRARIES	= libor1ktrace.la 

BINUTILS_DIR = @BINUTILS_BLD_DIR@

# the actual libor1ktrace
libor1ktrace_la_SOURCES	=	or1ktrace.c \
				or1ktrace.h \
				spr-defs.h

libor1ktrace_la_CFLAGS = -I$(BINUTILS_DIR)/bfd \
			-I$(BINUTILS_DIR)/opcodes


#libor1ktrace_la_LIBADD = $(BINUTILS_DIR)/bfd/libbfd.la \
#			$(BINUTILS_DIR)/opcodes/libopcodes.la

#libor1ktrace_la_LDFLAGS = -liberty -lz

# A little command-line interface program
test-asm_SOURCES 	= test-asm.c
test-asm_LDADD	= libor1ktrace.la
test-asm_LDFLAGS =	-L$(BINUTILS_DIR)/bfd \
			-L$(BINUTILS_DIR)/opcodes \
			-lbfd -lopcodes -lbfd -lopcodes -liberty -lz



