#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *gets(char *s);

static char *p(void)
{
    char buf[76];   
    unsigned int saved_eip; 

    fflush(stdout);

    gets(buf);

#if defined(__i386__)
    saved_eip = (unsigned int)__builtin_return_address(0);
#else
    saved_eip = 0;
#endif

    if ( (saved_eip & 0xb0000000U) == 0xb0000000U )
    {
        printf("(%p)\n", (void*)saved_eip);
        _exit(1);
    }

    puts(buf);

    return strdup(buf);

}

int main(void)
{
    (void)p();
    return 0;
}