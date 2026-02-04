#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void n(void)
{
    system("/bin/cat /home/user/level7/.pass");
}

static void m(void)
{
    puts("Nope");
}

int main(int argc, char **argv)
{
    char *buf = (char *)malloc(0x40); //64
    void (**fp)(void) = (void (**)(void))malloc(0x4); //4

    *fp = m;

    if (argc > 1)
        strcpy(buf, argv[1]);

    (*fp)();
    return 0;
}
