Voici le README correspondant, dans le même format clair et précis que les précédents :

---

## Rapport de Vulnérabilité : Manipulation de Valeur Retour via Débogueur (GDB)

### Description

Cette vulnérabilité exploite un programme (`level13`) qui vérifie explicitement l’UID réel de l’utilisateur qui l’exécute grâce à la fonction système `getuid()`. Le programme refuse de révéler le token s’il n’est pas lancé par un utilisateur spécifique (ici l’UID `4242`). Cependant, en interceptant la fonction `getuid()` via un débogueur (`gdb`), il est possible de manipuler sa valeur de retour, ce qui permet de contourner cette vérification et de récupérer le flag.

---

### Comment Exploiter la Faille

**Étape 1 : Analyser le comportement du programme**

Exécutez d'abord directement le binaire :

```shell
./level13
```

Résultat :

```
UID 2013 started us but we we expect 4242
```

Cela indique clairement que le programme attend un UID spécifique (4242), différent de votre UID réel (2013).

---

**Étape 2 : Utiliser GDB pour intercepter l’appel système `getuid()`**

Lancez le programme sous gdb :

```shell
gdb -q level13
```

Définissez un breakpoint sur la fonction `getuid` :

```gdb
(gdb) break getuid
```

Lancez le programme :

```gdb
(gdb) run
```

Le breakpoint s’active :

```gdb
Breakpoint 1, 0xb7ee4cc0 in getuid () from /lib/i386-linux-gnu/libc.so.6
```

---

**Étape 3 : Modifier la valeur de retour de `getuid()`**

Continuez jusqu’à la fin de l’appel à `getuid()` :

```gdb
(gdb) finish
```

À la fin de l’appel, affichez la valeur retournée (`$eax`) :

```gdb
(gdb) print $eax
$1 = 2013
```

Cette valeur correspond à votre UID réel.

Changez-la en `4242`, comme attendu par le programme :

```gdb
(gdb) set $eax = 4242
```

Poursuivez l’exécution :

```gdb
(gdb) continue
```

Le programme donne alors le flag :

```
your token is 2A31L79asukciNyi8uppkEuSx
```

---

**Étape 4 : Passer au niveau suivant**

Utilisez le token obtenu pour vous connecter à l’utilisateur suivant :

```shell
su level14
Mot de passe : 2A31L79asukciNyi8uppkEuSx
```

---

### Comment Résoudre la Faille

1. **Ne pas compter exclusivement sur des vérifications côté client :**

   * Une vérification de sécurité (UID) côté utilisateur ou facilement manipulable (comme ici) n’offre aucune sécurité réelle.

2. **Vérifier l’environnement d’exécution :**

   * Ajoutez des vérifications anti-debugging plus avancées si nécessaire.
   * Évitez de dépendre uniquement de l’UID réel retourné par `getuid()` sans authentification complémentaire robuste.

3. **Compiler les binaires avec des protections appropriées :**

   * Utilisez des outils pour détecter ou empêcher le debugging (stripping des symboles, protection anti-débogueur).

---

### Conclusion

Cette faille démontre l'importance de ne jamais considérer comme sûr le résultat d'une fonction système, lorsque celle-ci peut être interceptée ou manipulée via un débogueur. Une protection fiable nécessite une authentification robuste et des protections anti-debug appropriées.
