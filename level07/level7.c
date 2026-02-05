/*
** Rainfall - level7 (reconstruction C haut-niveau)
** Objectif : refléter la logique du binaire, pas compiler “à l’identique”.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct s_node {
    int   id;     // 4 bytes
    char *buf;    // 4 bytes (i386)
} t_node;

/* Fonction présente dans le binaire (non appelée directement dans main) */
void m(void)
{
    time_t t = time(NULL);
    /* fmt est une chaîne .rodata du binaire, style: "%s - %d\n" */
    printf("%s - %d\n", (char *)0x8049960, (int)t);
}

int main(int argc, char **argv)
{
    t_node *n1;
    t_node *n2;
    FILE   *fp;

    /* Deux "nodes" + deux buffers de 8 bytes */
    n1 = (t_node *)malloc(8);
    n1->id = 1;
    n1->buf = (char *)malloc(8);

    n2 = (t_node *)malloc(8);
    n2->id = 2;
    n2->buf = (char *)malloc(8);

    /* Vulnérable : copies non bornées dans des buffers de 8 bytes */
    strcpy(n1->buf, argv[1]);
    strcpy(n2->buf, argv[2]);

    /* Lecture du flag dans une zone globale (adresse fixe dans le binaire) */
    fp = fopen((char *)0x80486eb, (char *)0x80486e9);
    fgets((char *)0x8049960, 0x44, fp);

    /* Appel final, détourné via GOT vers m() dans l'exploit */
    puts("~~");

    return 0;
}
