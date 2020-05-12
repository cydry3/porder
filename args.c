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
			case 'i': *mode = 0; break;
			case 's': *mode = 1; break;
			case 'd': *mode = 2; break;
			case 'v': *mode |= (1u<<4); break;
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
	opt_parse(mode, argv, 2);

	if (!valid_argc(argc)) {
		print_usage(argv);
		exit(1);
	}

	args_copy(dest, argv, optind, argc);
}

int is_singlestep_mode(int mode) { return ((mode&0x0f)==0); }
int is_syscall_mode(int mode)    { return ((mode&0x0f)==1); }
int is_debug_mode(int mode) { return ((mode&0x0f)==2); }
int is_verbose_mode(int mode) { return ((mode&(1u<<4))>0); }
