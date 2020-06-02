#include "porder.h"

void print_usage(char **argv)
{
	  fprintf(stderr, "Usage: %s [-i][-s][-d] command [args]\n", argv[0]);
	  fprintf(stderr, "          -i print instructions\n");
	  fprintf(stderr, "          -s print system calls\n");
	  fprintf(stderr, "          -v print verbosely\n");
	  fprintf(stderr, "          -d debug mode it self\n");
}

void args_copy(char **dest, char **argv, int index, size_t argc) 
{
	int i, j;
	for (i = index, j = 0; i < argc && j < 10; i++, j++)
		dest[j] = argv[i];
	dest[j] = NULL;
}

void opt_parse(int *mode, char **argv, size_t argc)
{
	int opt;
	while ((opt = getopt(argc, argv, "isdv")) != -1) {
		switch (opt) {
			case 'i': *mode = PORDER_INST_MODE; break;
			case 's': *mode = PORDER_SYSCALL_MODE; break;
			case 'd': *mode = PORDER_DEBUG_MODE; break;
			case 'v': *mode |= PORDER_VERBOSE_MODE; break;
			default:  print_usage(argv); exit(1);
		}
	}
}

int valid_argc(size_t argc)
{
	return  (optind < argc);
}

void args_parse(int *mode, char **dest, char **argv, size_t argc)
{
	if (argc < 2) {
		print_usage(argv);
		exit(0);
	}

	opt_parse(mode, argv, 2);

	if (!valid_argc(argc)) {
		print_usage(argv);
		exit(1);
	}

	args_copy(dest, argv, optind, argc);
}

int is_singlestep_mode(int mode) { return ((mode&PORDER_MODE_MASK)==PORDER_INST_MODE); }
int is_syscall_mode(int mode)    { return ((mode&PORDER_MODE_MASK)==PORDER_SYSCALL_MODE); }
int is_debug_mode(int mode) { return ((mode&PORDER_MODE_MASK)==PORDER_DEBUG_MODE); }
int is_verbose_mode(int mode) { return ((mode&PORDER_VERBOSE_MODE)>0); }
