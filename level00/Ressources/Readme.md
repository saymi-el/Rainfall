Rainfall - Flag 0

⚡ Objectif

Comprendre et exploiter le niveau 0 du challenge Rainfall pour récupérer le mot de passe du niveau suivant (level1).

📝 Analyse initiale

En démarrant le binaire level0 dans GDB et en listant le début de la fonction main, on observe ceci :

0x08048ed4 <+20>: call 0x8049710 <atoi>
0x08048ed9 <+25>: cmp $0x1a7,%eax

atoi convertit le premier argument passé en ligne de commande en entier (ex: ./level0 123) et le met dans %eax.

Ensuite, on compare %eax à 0x1a7.

En décimal, 0x1a7 = 423.

Cela signifie que le programme vérifie si l'argument fourni est égal à 423. Si c'est le cas, l'exécution continue, sinon on exécute un fwrite d'un message d'erreur.

🔢 Exploitation

On lance donc simplement :

./level0 423

Cela nous ouvre un shell.

🤔 Vérification des droits

Dans le shell :

whoami
# user_level1

Nous avons les droits du niveau suivant.

🔐 Récupération du flag

cat /home/user/level1/.pass
# 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a

Puis :

su level1
# Entrer le flag comme mot de passe

📅 Résumé

Le binaire vérifie un argument = 423 (via atoi + cmp).

Si OK, on entre dans un shell avec droits level1.

Le flag est accessible en lisant /home/user/level1/.pass.

Le niveau ne contient aucune faille à exploiter, juste de l'observation d'assembleur.