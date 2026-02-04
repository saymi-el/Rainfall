#include <stdio.h>
#include <stdlib.h>

int m; // situé à 0x8049810 (global)

static void p(char *s) {
    printf(s);           // vulnérable : format string contrôlé
}

static void n(void) {
    char buf[0x208];     // taille approx, cohérente avec lea -0x208(%ebp)
    fgets(buf, 0x200, stdin);
    p(buf);

    if (m == 0x01025544) {
        system(/* 0x8048590 */);
    }
}

int main(void) {
    n();
    return 0;
}
