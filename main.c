#include <stdio.h>
#include "helpers/vector.h"
#include "compiler.h"

int main()
{
    int res = compile_file("./test.c", "./test", 0);

    if (res == COMPILER_FILE_COMPILED_OK) {
        printf("everything compiled nicely\n");
    } else if (res == COMPILER_FAILED_WITH_ERRORS) {
        printf("things did not compile :(\n");
    } else {
        printf("idk bro\n");
    }
    
    return 0;
}