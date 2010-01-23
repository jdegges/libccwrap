/*
 * Simple Test program for libccwrap
 *
 * libccwrap can be useful to use tcc as a "backend" for a code generator.
 *
 * This test was adapted from libtcc_test.c:
 * http://repo.or.cz/w/tinycc.git/blob/HEAD:/tests/libtcc_test.c
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libccwrap.h"

char my_program[] =
"#include <stdio.h>\n"
"int add(int a, int b)\n"
"{\n"
"    return a + b;\n"
"}\n"
"int fib(int n)\n"
"{\n"
"    if (n <= 2)\n"
"        return 1;\n"
"    else\n"
"        return fib(n-1) + fib(n-2);\n"
"}\n"
"\n"
"int foo(int n)\n"
"{\n"
"    printf(\"Hello World!\\n\");\n"
"    printf(\"fib(%d) = %d\\n\", n, fib(n));\n"
"    printf(\"add(%d, %d) = %d\\n\", n, 2 * n, add(n, 2 * n));\n"
"    return 0;\n"
"}\n";

int main(int argc, char **argv)
{
    ccw_context s;
    int (*func)(int);

    s = ccw_new();
    if (!s) {
        fprintf(stderr, "Could not create tcc state\n");
        exit(1);
    }

    /* if tcclib.h and libtcc1.a are not installed, where can we find them */
    if (argc == 2 && !memcmp(argv[1], "lib_path=",9))
        ccw_add_library_path(s, argv[1]+9, 0);

    /* MUST BE CALLED before any compilation */
    ccw_set_output_type(s, CCW_OUTPUT_MEMORY);

    if (ccw_compile_string(s, my_program, 0) != 0)
        return 1;

    /* get entry symbol */
    func = ccw_get_symbol(s, "foo", NULL);
    if (!func)
        return 1;

    /* run the code */
    func(32);

    /* delete the state */
    ccw_delete(s);

    return 0;
}
