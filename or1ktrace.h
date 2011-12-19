


int or1ktrace_gen_insn_string(unsigned long int addr,
			      unsigned long int insn,
			      char* insn_string_ptr);

int or1ktrace_gen_trace_string(unsigned long int addr,
			       unsigned long int insn,
			       char* trace_string_ptr);

void or1ktrace_init( unsigned long int  (*get_mem32)(unsigned long int),
		     unsigned long int  (*get_gpr)(int),
		     unsigned long int  (*get_spr)(int),
		     int or1ktrace_debug_on);
