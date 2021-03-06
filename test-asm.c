
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <bfd.h>
#include <dis-asm.h>		/* libopcodes header from binutils */
#include "or1ktrace.h"

static int current_test = 0;
static int or1ktrace_debug_on = 0;

/* test set of binary to disassemble */
#include "test-asm-input.h"

unsigned long int get_mem32 (unsigned long int addr)
{
  if (or1ktrace_debug_on)
    {
      printf ("debug - get_mem32(): asked for insn at addr 0x%08x\n    Returning insn binary 0x%08x\n\n", 
	      addr, test_or1k_bin[current_test]);
    }

#define SWAP_ENDIAN32(x)                        \
      (((x>>24)&0xff)|                          \
        ((x>>8)&0xff00)|                        \
        ((x<<8)&0xff0000)|                      \
       ((x<<24)&0xff000000))


  return  SWAP_ENDIAN32(test_or1k_bin[current_test]);

}


unsigned long int get_gpr ( int gpr)
{
  return 0;
}


unsigned long int get_spr (int spr)
{
  return 0;
}

int main(int argc, char* argv[])
{
  
  char trace_string[100];
  int trace_string_length;
  int errors_found = 0;
  current_test = 0;
  int i=0;
  int limit = 0;

  // Allow user to pass a number of tests to run
  if (argc > 1 )
    limit = atoi(argv[1]);
  
  // Check for a -d flag
  for (i=1;i<argc;i++)
    if (strcmp("-d", argv[i])==0)
      or1ktrace_debug_on = 1;

  printf("Running tests on instruction disassembly\n");

  or1ktrace_init(get_mem32, get_gpr, get_spr, or1ktrace_debug_on);

  while (test_or1k_bin[current_test] != 0xffffffff)
     
    {      
      
      if ((limit!=0) && (current_test==limit))
	break;
      
      if (or1ktrace_debug_on)
	printf ("debug - main(): trying insn binary 0x%08x\n\n", 
		test_or1k_bin[current_test]);

      
      trace_string_length = or1ktrace_gen_insn_string(test_or1k_pc[current_test],
						      trace_string);

      trace_string[trace_string_length] = '\0';

      if (0 != strncmp(test_or1k_disas[current_test], trace_string,
		       strlen(test_or1k_disas[current_test])))
	{
	  printf("disas not OK!\n");
	  printf ("%s != %s\n", test_or1k_disas[current_test],
		  trace_string);
	  errors_found++;
	}
      /*
      else if (or1ktrace_debug_on==1);
      {
	trace_string[trace_string_length] = '\n';
	trace_string[trace_string_length+1] = '\0';
	printf(trace_string);
      }
      */
      current_test++;
    }

  printf("%d errors found in %d tests\n", errors_found, current_test);
    
  return errors_found;
  
}
