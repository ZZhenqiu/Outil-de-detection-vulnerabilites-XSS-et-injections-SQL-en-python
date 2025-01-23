# Outil pentesting basique (port scan, dirbuster, LFI / Command Injection / XSS / SQLi scans). 

Bonjour, 

Ce programme est réalisé dans un cadre pédagogique avec comme objectif une meilleure compréhension des vulnérabilités et attaques possibles. 
Les tests ont été effectués sur des CTFs de TryHackMe. 


Ce script effectue les actions suivantes : 

-scan de port, avec énumération des services, des versions et de l’OS. 

-recherche d’exploits sur ExploitDB à partir des résultats du scan précédent sur les versions.

-énumération de répertoires (à la manière d’un dirbuster) et de sous-domaines

-recherche de formulaires à partir des répertoires trouvés précédemment

-recherche de vulnérabilités (Local File Inclusion, Command Injection, XSS et SQLi) grâce à des injections de payloads dans les formulaires trouvés. 



Pour lancer ce programme : 

-créez un fichier « nom_du_script.py », copiez-collez le code

-créez une wordlist avec des noms de domaines/sous-domaines. Si vous avez Kali, l’option simple serait de prendre un fichier tel que directory-list-2.3-medium.txt ou n’importe quel fichier dans /usr/share/wordlists/dirbuster. 

-Utilisez -u pour indiquer l’url et -w pour indiquer la wordlist. Votre commande devrait ressembler à cela : 

python3 nom_du_script.py -u IP_à_scanner -w wordlist


Voilà. 
 
![1](https://github.com/user-attachments/assets/72908fbe-632c-4935-a228-79cdb3f75160)


![2](https://github.com/user-attachments/assets/4d9ef0d7-d0d4-4813-ac58-45a3e045dd83)

 


Notes : 

-Dans l’exemple ci-dessus, le script a été nommé « a.py » et la worldlist « a.txt » pour des raisons de rapidité, mais vous pouvez les nommer comme bon vous semble. 

-Si vous testez le code sur l’attack box proposée par TryHackMe, il est à noter qu’il faudra effectuer une petite modification. En effet, le script utilise Scapy et BeautifulSoup, or dans ces machines, elles sont installées pour Python 2.7 mais pas Python 3. Si vous rencontrez des problèmes au lancement, effectuez les commandes suivantes : 

apt update

pip3 install scapy

pip3 install bs4



Normalement tout devrait être bon. 



