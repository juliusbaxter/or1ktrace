
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <bfd.h>
#include <dis-asm.h>		/* libopcodes header from binutils */

#include "spr-defs.h"

/* global libopdcode disassembler struct, defined in dis-asm.h */
static int or1ktrace_debug;
static disassemble_info or1ktrace_disinfo;
static disassembler_ftype or1ktrace_disassemble;
static char *or1ktrace_dis_string;
static int or1ktrace_dis_string_offset;
static unsigned long int or1ktrace_current_addr;
static unsigned long int  (*or1ktrace_get_mem32)(unsigned long int);
static unsigned long int  (*or1ktrace_get_gpr)(int);
static unsigned long int  (*or1ktrace_get_spr)(int);
static char or1ktrace_insn_disassembly_string[60];
static int or1ktrace_insn_disassembly_string_len;

/* ---------------------------------------------------------------------- */
/* libopcodes callbacks */

static int libopcode_insn_fprintf( void * stream, const char * format, ... ) {
	int rv;

	va_list args;
	va_start (args, format);

	rv = vsnprintf(or1ktrace_insn_disassembly_string+or1ktrace_insn_disassembly_string_len, 
		       59, format, args );

	va_end (args);
	
	or1ktrace_insn_disassembly_string_len += rv;
	
	return rv;
}

static void 
or1ktrace_report_memory_error( int status, bfd_vma vma, 
			       struct disassemble_info * info ) 
{
  
  if (or1ktrace_debug)
    {
      printf("or1ktrace_report_memory_error():\n\n");
    }
  
  char msg[48];
  
  //snprintf( msg, 47, "VMA %p (status %d)\n", (void *) vma, status );
  printf("VMA %p (status %d)\n", (void *) vma, status );

}

static void 
or1ktrace_custom_print_address ( bfd_vma address, 
				 struct disassemble_info * info)
{

  if (or1ktrace_debug)
    {
      printf("or1ktrace_custom_print_address(): 0x%08x\n\n",address);
    }

  libopcode_insn_fprintf(NULL, "%x", address);

}


/* Get LENGTH bytes from memory, at target address memaddr.
   Transfer them to myaddr.  */
int
read_memory_func (bfd_vma memaddr,
		  bfd_byte *myaddr,
		  unsigned int length,
		  struct disassemble_info *info)
{

  if (or1ktrace_debug)
    {
      printf("read_memory_func():\n");
    }

  /* confirm the address is the one we're currently disassembling */
  if (memaddr != or1ktrace_current_addr)
    {
      printf("read_memory_func: error, %08x != %08x\n",
	     (unsigned int) memaddr,
	     (unsigned int) or1ktrace_current_addr);
      return -1;
    }

  if (length == 4)
    {
      
      /* read the memory */
      unsigned long int insn = (*or1ktrace_get_mem32)
	((unsigned long int)memaddr);

#define SWAP_ENDIAN32(x)			\
      (((x>>24)&0xff)|				\
       ((x>>8)&0xff00)|				\
       ((x<<8)&0xff0000)|			\
       ((x<<24)&0xff000000))
      
      insn = SWAP_ENDIAN32(insn);

      memcpy((void *)myaddr, (void*)&insn, length);

      if (or1ktrace_debug)
	{
	  printf("    returned data: %d bytes: %08x\n", length, 
		 *((unsigned int*) myaddr));
	  printf("\n");
	}
      
    }
  else
    {
      printf("read_memory_func: error, length != 4, was %d\n", length);
      return -1;
    }

  return 0;
}

int or1ktrace_gen_insn_string(unsigned long int addr,
			      unsigned long int insn,
			      char* insn_string_ptr)
{
  or1ktrace_insn_disassembly_string_len = 0;
  or1ktrace_dis_string_offset = 0;

  or1ktrace_current_addr = addr;

  if (or1ktrace_debug)
    {
      printf("or1ktrace_gen_insn_string():\n");
      printf("    addr: %08x\n", addr);
      printf("    insn: %08x\n", insn);
      printf("\n");
    }
  
  or1ktrace_disassemble((bfd_vma) addr, &or1ktrace_disinfo);

  memcpy((void*)insn_string_ptr,  (void*)or1ktrace_insn_disassembly_string,
	 or1ktrace_insn_disassembly_string_len);
  
  return or1ktrace_insn_disassembly_string_len;
}

static int or1ktrace_gen_result_string(char* disas_string_ptr,
				       char* trace_string_ptr)
{
  /* determine from the disassembled string what the result we want to 
   print out is*/

  int trace_dest_reg=-1, trace_store_width=0,
    trace_store_addr_reg = -1, trace_store_val_reg = -1;
  unsigned long int trace_store_imm=-1, trace_dest_spr=0;

#define DISAS_HAS(x) (0 == strncmp (x, disas_string_ptr, strlen(x)))

#define TRACE_SPRINTF(fmt, value) \
  or1ktrace_dis_string_offset += sprintf (trace_string_ptr+or1ktrace_dis_string_offset, fmt, value)

  if DISAS_HAS(".word ")
		/* nothing to see here */
		return 0;
  
  if DISAS_HAS("l.mtspr")
		trace_dest_spr = 1;
  
  /* skip over instruction mnemonic and get to first interesting information */
  if DISAS_HAS("l.sw") trace_store_width = 4;
  if DISAS_HAS("l.sh") trace_store_width = 2;
  if DISAS_HAS("l.sb") trace_store_width = 1;
  
  if (trace_store_width)
    {
      /* skip over the instruction and space, to the '0' of the 0x.. */
      while (*disas_string_ptr != '0')
	*disas_string_ptr++;
      
      sscanf(disas_string_ptr, "0x%x",(unsigned int *)&trace_store_imm);

      while (*disas_string_ptr != 'r')
	*disas_string_ptr++;
      
       sscanf(disas_string_ptr, "r%d", &trace_store_addr_reg);
       
       *disas_string_ptr++;
       while (*disas_string_ptr != 'r')
	 *disas_string_ptr++;
       
       sscanf(disas_string_ptr, "r%d", &trace_store_val_reg);
       
       unsigned long int store_addr = 
	 (*or1ktrace_get_gpr)(trace_store_addr_reg) + trace_store_imm;

       TRACE_SPRINTF("[%08X] = ", store_addr);

       switch (trace_store_width)
	 {
	 case 1:
	   TRACE_SPRINTF("%02x      ",
			 (*or1ktrace_get_gpr)(trace_store_val_reg)&0xff);
	   break;
	 case 2:
	   TRACE_SPRINTF("%04x    ",
			 (*or1ktrace_get_gpr)(trace_store_val_reg)&0xffff);
	   break;
	 case 4:
	   TRACE_SPRINTF("%08x",(*or1ktrace_get_gpr)(trace_store_val_reg));
	   break;
	 default:
	   TRACE_SPRINTF("                     ",NULL);
	   break;
	 }
    }
  else
    {
      /* Skip to the space after the mnemonic */
      while (*disas_string_ptr != ' ')
	*disas_string_ptr++;

      if (disas_string_ptr[1] == 'r')
	{
	  *disas_string_ptr++;
	  /* destination register */
	  sscanf(disas_string_ptr, "r%d", &trace_dest_reg);
	}

      if (trace_dest_spr)
	{
	  /* get the gpt with part of the SPR address */
	  trace_dest_spr = (*or1ktrace_get_gpr)(trace_dest_reg);
	  /* now extract the immediate */
	  while (!(disas_string_ptr[0]=='0' && disas_string_ptr[1]=='x'))
	    *disas_string_ptr++;

	  sscanf(disas_string_ptr, "0x%x", &trace_store_imm);
	  
	  trace_dest_spr |=  trace_store_imm;

	  TRACE_SPRINTF("SPR[%04x]  = ", trace_dest_spr);
	  
	  TRACE_SPRINTF("%08x", (*or1ktrace_get_spr)(trace_dest_spr));
	  
	}
      else if (trace_dest_reg != -1)
	{
	  TRACE_SPRINTF("r%-2u        = ", trace_dest_reg);
	  TRACE_SPRINTF("%08x", (*or1ktrace_get_gpr)(trace_dest_reg));
	}
      else
	TRACE_SPRINTF("                     ",NULL);
    }
}

int or1ktrace_gen_trace_string(unsigned long int addr,
			       unsigned long int insn,
			       char* trace_string_ptr)
{

  or1ktrace_dis_string_offset = 0;
  or1ktrace_insn_disassembly_string_len = 0;
  or1ktrace_dis_string = trace_string_ptr;

  or1ktrace_current_addr = addr;

  TRACE_SPRINTF("%c ",
		(SPR_SR_SM == ((*or1ktrace_get_spr)(SPR_SR) & SPR_SR_SM)) ? 'S' : 'U');

   /* The address */
  TRACE_SPRINTF("%08X: ", addr);

  /* Instruction binary */
  TRACE_SPRINTF("%08X ", 
		(*or1ktrace_get_mem32)	
			      ((unsigned long int)addr));
  
  or1ktrace_disassemble((bfd_vma) addr, &or1ktrace_disinfo);
  
  TRACE_SPRINTF("%-26s", or1ktrace_insn_disassembly_string);
  
  or1ktrace_gen_result_string(or1ktrace_insn_disassembly_string,
			      insn, trace_string_ptr);
  TRACE_SPRINTF("  flag: %u", 
		(*or1ktrace_get_spr)(SPR_SR) & SPR_SR_F ? 1 : 0);
  
  return or1ktrace_dis_string_offset;
  
}
			       

void or1ktrace_init( unsigned long int  (*get_mem32)(unsigned long int),
		     unsigned long int  (*get_gpr)(int),
		     unsigned long int  (*get_spr)(int),
		     int or1ktrace_debug_on
		     )
{
  or1ktrace_debug = or1ktrace_debug_on;
  if (or1ktrace_debug)
    printf("or1ktrace_init()\n\n");
  init_disassemble_info ( &or1ktrace_disinfo, NULL, libopcode_insn_fprintf );
  or1ktrace_disinfo.print_address_func = or1ktrace_custom_print_address;
  or1ktrace_disinfo.memory_error_func = or1ktrace_report_memory_error;
  or1ktrace_disinfo.read_memory_func = read_memory_func;
  /* set or32 architecture */
  or1ktrace_disinfo.arch = bfd_arch_or32;
  disassemble_init_for_target(&or1ktrace_disinfo);
  /* We know our target is big endian 32-bit OpenRISC 1000 */
  or1ktrace_disassemble = (disassembler_ftype) print_insn_big_or32;

  /* Save the getter functions */
  or1ktrace_get_mem32 = get_mem32;
  or1ktrace_get_gpr = get_gpr;
  or1ktrace_get_spr = get_spr;

}
