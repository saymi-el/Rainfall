#include <stdio.h>
#include <stdlib.h>

static void run(void)
{
    static const char msg[] = "Good... Wait what?\n"; 
    fwrite(msg, 1, 19, stdout);

    system("/bin/sh");
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char buf[64];

    gets(buf);

    return 0;
}
