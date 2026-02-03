
---

# Rainfall — Flag 0

## Objectif

Comprendre le fonctionnement du binaire `level0` et récupérer le mot de passe du niveau suivant (`level1`).

---

## Analyse initiale

Le binaire `level0` prend un argument en ligne de commande.
L’analyse statique du code assembleur (via GDB ou `objdump`) montre la séquence suivante dans la fonction `main` :

```
0x08048ed4 <+20>: call 0x8049710 <atoi>
0x08048ed9 <+25>: cmp  $0x1a7, %eax
```

### Interprétation

* `atoi` convertit le **premier argument passé au programme** (`argv[1]`) en entier.
* La valeur retournée par `atoi` est placée dans le registre `%eax`.
* Le programme compare ensuite cette valeur à `0x1a7`.

Conversion hexadécimal → décimal :

```
0x1a7 = 423
```

Le comportement du programme est donc le suivant :

* si l’argument fourni est **égal à 423**, l’exécution suit le chemin valide
* sinon, le programme affiche un message d’erreur via `fwrite` et termine

---

## Exploitation

Aucune vulnérabilité mémoire n’est présente dans ce niveau.
Il s’agit uniquement d’une **vérification logique** basée sur la valeur passée en argument.

Il suffit donc de lancer le programme avec la valeur attendue :

```
./level0 423
```

Cette commande permet d’atteindre le chemin d’exécution valide.

---

## Vérification des droits

Une fois dans le shell obtenu, on vérifie l’identité de l’utilisateur :

```
whoami
```

Résultat :

```
level1
```

Le programme s’exécute donc avec les droits du niveau suivant.

---

## Récupération du flag

Le flag est stocké dans le répertoire personnel de `level1` :

```
cat /home/user/level1/.pass
```

Résultat :

```
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

Ce mot de passe permet ensuite de se connecter au niveau suivant :

```
su level1
```

---

## Résumé

* Le binaire convertit l’argument fourni via `atoi`
* Il compare la valeur obtenue à `423`
* Si la valeur est correcte, un shell est lancé avec les droits `level1`
* Le flag est accessible dans `/home/user/level1/.pass`
* Le niveau ne repose pas sur une faille d’exploitation, mais sur une **simple observation du code assembleur**