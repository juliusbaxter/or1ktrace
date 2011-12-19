
AC_INIT([or1ktrace], [2011-12-18], [juliusbaxter@gmail.com])
AC_CONFIG_MACRO_DIR([m4])

# Generically use extensions such as _GNU_SOURCE if available.
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_TARGET([])



AC_PROG_LIBTOOL
AM_INIT_AUTOMAKE

# make sure we are using a recent autoconf version
AC_PREREQ(2.59)


AC_CONFIG_HEADERS([config.h])
# make sure we are using a recent autoconf version
AC_PREREQ(2.59)

AM_PROG_AS
AC_PROG_CC
AC_PROG_CC_C_O


AC_PROG_MAKE_SET

AC_PROG_INSTALL
AC_CHECK_PROG(AR, ar, ar)

AC_ARG_VAR(BINUTILS_BLD_DIR, Directory where OpenRISC binutils has been compiled and we can find libbfd.la and libopcodes.la)
AC_SUBST(BINUTILS_BLD_DIR)


AC_CONFIG_FILES([Makefile])


AC_OUTPUT