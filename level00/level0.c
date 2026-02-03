#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fwrite("Usage: ./level0 <number>\n", 1, 26, stderr);
        return 1;
    }

    int n = atoi(argv[1]);

    if (n == 423) {                 // 0x1a7
        system("/bin/sh");
        return 0;
    }

    fwrite("Nope.\n", 1, 6, stderr);
    return 1;
}
