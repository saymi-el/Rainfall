🔩 Les principaux registres
Registre	Rôle
EIP	Instruction Pointer (adresse de la prochaine instruction à exécuter)
ESP	Stack Pointer (pointe vers le haut de la stack)
EBP	Base Pointer (base du cadre courant sur la stack)
EAX/EBX/ECX/EDX	Registres généraux utilisés pour les calculs

🧱 Structure typique de la stack
lua
Copier
Modifier
+------------------------+
|  Ret addr (EIP)        | ← EIP est ici
+------------------------+
|  Saved EBP             | ← EBP pointe ici
+------------------------+
|  Buffer local variable |
|  (ex: char buffer[64]) |
+------------------------+
🧠 Instructions assembleur fréquentes
Instruction	Explication simple
call <addr>	Saute à l'adresse et empile l’adresse de retour
ret	Dépile et saute à cette adresse
jmp <addr>	Saut direct à une adresse
mov dst, src	Copie la valeur src dans dst
sub esp, 0x50	Réserve 80 octets sur la stack (char buf[80])
leave	Fait mov esp, ebp puis pop ebp

💣 Comment fonctionne un buffer overflow
Un buffer comme char buf[64] est stocké sur la stack.

Si on écrit plus de 64 octets, on écrase le saved EBP, puis le ret/EIP.

En contrôlant EIP, on peut rediriger le flux du programme (ex: vers un shellcode).

🧪 Trouver l’offset pour écraser EIP
Générer un motif unique (pattern) :

bash
Copier
Modifier
pattern_create.rb -l 200
L’envoyer dans le programme et faire un crash :

bash
Copier
Modifier
./vuln $(pattern)
Trouver l’offset exact :

bash
Copier
Modifier
pattern_offset.rb -q <valeur_EIP_crashée>
📊 Schéma simple de stack avec overflow
css
Copier
Modifier
ESP → [ shellcode (NOP + code) ]
       ...
       [ AAAAAAAA ]
       [ EIP = adresse_de_saut ] ← overwrite ici
Tu envoies :
"A"*offset + <nouvel EIP> + <shellcode>
ou
"A"*offset + <adresse_buffer> # si shellcode déjà dans le buffer

🎯 Techniques
Overflow classique : Écraser EIP avec adresse du buffer contenant un shellcode

ret2libc : Écraser EIP avec une fonction système (ex: system("/bin/sh"))

ROP : Enchaîner des gadgets (pop; ret, mov, call, etc.)

