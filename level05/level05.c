#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void o(void)
{
    // Fonction sensible présente dans le binaire
    system("/bin/sg");
    _exit(1);
}
static void n(void)
{
    char buf[520];
    // Lecture de l'entrée utilisateur
    fgets(buf, 512, stdin);
    // VULNÉRABILITÉ: format string (printf avec entrée brute)
    printf(buf);
    // Fin du programme
    exit(1);
}
int main(void)
{
    n();
    return 0;
}
