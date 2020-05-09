#include "porder.h"

void print_usage(char **argv)
{
	  fprintf(stderr, "Usage: %s [-i][-s] command [args]\n", argv[0]);
	  fprintf(stderr, "          -i print instructions\n");
	  fprintf(stderr, "          -s print system calls\n");

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
	while ((opt = getopt(argc, argv, "is")) != -1) {
		switch (opt) {
			case 'i': *mode = 0; break;
			case 's': *mode = 1; break;
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
	opt_parse(mode, argv, argc);

	if (!valid_argc(argc)) {
		print_usage(argv);
		exit(1);
	}

	args_copy(dest, argv, optind, argc);
}
