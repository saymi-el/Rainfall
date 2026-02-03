#include <stdio.h>
#include <stdlib.h>

int g = 0; // en vrai, variable globale située à 0x804988c

void v(void) {
    char buf[512];

    fgets(buf, sizeof(buf), stdin);
    printf(buf); // vulnérabilité format string

    if (g == 0x40) {
        fwrite("Wait what?!\n", 1, 0xc, stdout); // chaîne à 0x8048600
        system("/bin/sh");
    }
}

int main(void) {
    v();
    return 0;
}
