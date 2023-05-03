- [Livrables](#livrables)

- [Échéance](#échéance)

- [Travail à réaliser](#travail-à-réaliser)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 Sécurité WPA

__A faire en équipes de deux personnes__

__Développement à faire en Python 3__

### Pour cette partie pratique, vous devez être capable de :

* Extraire à partir d’une capture Wireshark les données nécessaires pour dériver les clés de chiffrement et intégrité WPA utilisant Scapy
* Coder votre propre version du logiciel [aircrack](https://www.aircrack-ng.org) pour trouver la passphrase d’un réseau WPA à partir d’une capture utilisant Python et Scapy
* A partir d’une capture Wireshark, extraire la valeur de la PMKID utilisant Scapy et l'utiliser pour Cracker la passphrase WPA
* (Challenge bonus) Coder votre propre version des outils [airodump](https://www.aircrack-ng.org/doku.php?id=airodump-ng) et [aireplay](https://www.aircrack-ng.org/doku.php?id=aireplay-ng) pour déauthentifier un client, sniffer un handshake et l’utiliser pour trouver une passphrase WPA utilisant Python et Scapy

__Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). __Si vous utilisez une VM, il vous faudra une interface WiFi usb (uniquement pour l'exercice "chellenge" qui est optionnel), disponible sur demande__.

__ATTENTION :__ Pour l'exercise "challenge", il est très important de bien fixer le canal lors de vos captures et vos injections. Si vous en avez besoin, la méthode la plus sure est d'utiliser l'option :

```--channel``` de ```airodump-ng```

et de garder la fenêtre d'airodump ouverte en permanence pendant que vos scripts tournent ou vos manipulations sont effectuées.


## Travail à réaliser

### 1. Obtention des paramètres pour la dérivation des clés WPA  

Dans cette première partie, vous allez récupérer le script **Python3** [wpa\_key\_derivation.py](files/wpa_key_derivation.py). Il vous faudra également le fichier de capture [wpa\_handshake.cap](files/wpa_handshake.cap) contenant un processus d’authentification WPA. Vous aurez aussi besoin du fichier [pbkdf2.py](files/pbkdf2.py), qui permet de calculer les 4096 tours pour le hash de la passphrase. Tous ces fichiers doivent être copiés dans le même répertoire local sur vos machines.

- Ouvrir le fichier de capture [wpa\_handshake.cap](files/wpa_handshake.cap) avec Wireshark

- Exécuter le script avec ```python3 wpa_key_derivation.py```

  > ![](img/1.2_script_output.png)

- Essayer d’identifier les valeurs affichées par le script dans la capture Wireshark

  > Au niveau de la couche MAC de n'importe quel paquet, on retrouve les adresses MAC du client et de l'AP.
  >
  > Le paquet 1 est un beacon émis par l'AP. On retrouve dans celui-ci le SSID.
  >
  > Les paquets 2 et 3 sont l'authentification Open System. On remarque que nous avons d'abord capturé la confirmation envoyée par l'AP avant la requête d'authentification envoyée par le client. Ceci est certainement dû à une erreur lors du nettoyage de la trace initiale.
  >
  > Les paquets 4 et 5 sont l'association.
  >
  > Les paquets 6-9 sont l'échange de clés WPA.
  >
  > - Dans le paquet 6, on retrouve le nonce de l'AP
  >
  > - Dans le paquet 7, on retrouve le nonce du client
  >
  > Toutes les autres valeurs du script sont dérivée et pas récupérables directement dans Wireshark

- Analyser le fonctionnement du script. En particulier, __faire attention__ à la variable ```data``` qui contient la payload de la trame et la comparer aux données de la quatrième trame du 4-way handshake. Lire [la fin de ce document](#quelques-éléments-à-considérer-) pour l’explication de la différence.

  > Le script commence par lire une capture `.pcap`
  >
  > Il contient ensuite un certain nombre de valeurs en dur: 
  >
  > - `passPhrase`: Le mot de passe d'authentification à l'AP
  > - `A`: Une string utilisée pour la création de la PTK, cette string est définie dans la norme WPA.
  >   [Doc de hmac.new()](https://docs.python.org/3/library/hmac.html),
  >   [Explication de la norme](http://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Part+II+The+Design+of+Wi-Fi+Security/Chapter+10.+WPA+and+RSN+Key+Hierarchy/Computing+the+Temporal+Keys/)
  > - `ssid`: le nom du Wifi à attaquer
  > - `APmac`: L'adresse MAC de l'AP
  > - `Clientmac`: L'adresse MAC du client
  > - `ANonce`: Le nonce de l'AP envoyé au client (message 2 du 4-way handshake)
  > - `SNonce`: Le nonce du client envoyé à l'AP (message 3 du 4-way handshake)
  > - `mic_to_test`: Le MIC tiré du message 4 du 4-way handshake qui sera utilisé comme condition de réussite de notre bruteforce au point 2
  > - `B`: La concaténation des adresses MAC de l'AP et du Client (par ordre croissant), suivi des Nonces de l'AP et du client, par ordre croissant
  >   Voir [Explication]([Explication de la norme](http://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Part+II+The+Design+of+Wi-Fi+Security/Chapter+10.+WPA+and+RSN+Key+Hierarchy/Computing+the+Temporal+Keys/)).
  >- `data`: Le payload EAPOL, il contient le MIC à utiliser pour le bruteforce.
  > 
  >On encode ensuite la passphase et le ssid, qui sont utilisé pour construire la Pairewise Mater Key (PMK). La passphrase sert de clé pour la fonction PBKDF2-SHA1, les données hashées étant le SSID. 4096 rondes, 32 bytes de sortie
  > 
  >Grâce à la PMK, on peut ensuite calculer la PTK en passant
  > 
  >`customPRF512(key,A,B):` est la fonction utilisée pour passer de la Pairwise Master Key (PMK) à la Pairwise Transient Key (PTK). PMK est la clé, A et B les données qui seront utilisées pour rendre la PTK unique.
  > 
  >On calcule ensuit le MIC en prenant les 16 premiers octets de la PTK comme clé HMAC, et les `data`comme données.
  > 

- __Modifier le script__ pour qu’il récupère automatiquement, à partir de la capture, les valeurs qui se trouvent actuellement codées en dur (```ssid```, ```APmac```, ```Clientmac```, nonces…) 

  > Voir repo, script 1_wpa_key_derivation.py
  >
  > ![](img/1.3_script_output.png)


### 2. Scaircrack (aircrack basé sur Scapy)

Aircrack utilise le quatrième message du 4-way handshake pour tester les passphrases contenues dans un dictionnaire. Ce message ne contient pas de données chiffrées mais il est authentifié avec un MIC qui peut être exploité comme « oracle » pour tester des clés différentes obtenues des passphrases du dictionnaire.


Utilisant le script [wpa\_key\_derivation.py](files/wpa_key_derivation.py) comme guide, créer un nouveau script ```scaircrack.py``` qui doit être capable de :

- Lire une passphrase à partir d’un fichier (wordlist)
- Dériver les clés à partir de la passphrase que vous venez de lire et des autres éléments nécessaires contenus dans la capture (cf [exercice 1](#1-obtention-des-paramètres-pour-la-dérivation-des-clés-wpa))
- Récupérer le MIC du dernier message du 4-way handshake dans la capture
- Avec les clés dérivées à partir de la passphrase, nonces, etc., calculer le MIC du dernier message du 4-way handshake à l’aide de l’algorithme Michael (cf l’explication à la fin de ce document)
- Comparer les deux MIC
   - Identiques &rarr; La passphrase utilisée est correcte
   - Différents &rarr; Essayer avec une nouvelle passphrase

> Voir repo, script 2_scaircrack.py
>
> ![](img/2_script_output.png)

### 3. Attaque PMKID

#### 3.1. Obtention de la PMKID et des paramètres pour la dérivation de la PMK

Vous allez réutiliser le script de dérivation de clés de l'exercice 1 et le fichier de capture [PMKID_handshake.pcap](files/PMKID_handshake.pcap) contenant une tentative d’authentification WPA pas réussie réalisée par un attaquant.

La PMKID est contenue dans le premier message du 4-way handshake de certains AP. Les AP de l'opérateur Sunrise en Suisse, par exemple, sont confirmés comme étant vulnérables. Il s'agit donc d'un AP de Sunrise qui a été utilisé pour faire [la capture](files/PMKID_handshake.pcap). 

Voici ce que vous devez faire pour cette partie :

- __Modifier votre script WPA__ pour qu’il récupère automatiquement, à partir de la capture, la valeur de la PMKID
- Vous aurez aussi besoin de récupérer les valeurs du ```ssid```, ```APmac``` et ```Clientmac``` (ceci est normalement déjà fait par votre script) 

> Voir repo, script 3_pmkid_attack.py


#### 3.2. Cracker la Passphrase utilisant l'attaque PMKID

L'attaque PMKID est une attaque par dictionnaire qui calcule systématiquement une PMK à partir de la passphrase. Cette PMK est utilisée comme clé pour SHA-1 calculé sur une concatenation du string "PMK Name" et les adresses MAC de l'AP et la STA. Les premiers 128 bits (6 octets) du résultat de ce calcul doivent correspondre à la valeur de la PMKID obtenue à partir du premier message du 4-way handshake.

Utilisant votre script précédent, le modifier pour réaliser les taches suivantes :

- Lire une passphrase à partir d’un fichier (wordlist) &rarr; __La passphrase utilisée dans la capture est ```admin123```__
- Dériver la PMK à partir de la passphrase que vous venez de lire et des autres éléments nécessaires contenus dans la capture (cf [exercice 1](#1-obtention-de-la-pmkid-et-des-paramètres-pour-la-dérivation-de-la-pmk))
- Calculer la PMKID (cf [vidéo YouTube](http://www.youtube.com/watch?v=APkk9C2sydM))
- Comparer la PMKID calculée avec celle récupérée de la capture :
   - Identiques &rarr; La passphrase utilisée est correcte
   - Différents &rarr; Essayer avec une nouvelle passphrase

> ![](img/3.2_script_output.png)


#### 3.3. Attaque hashcat

A manière de comparaison, réaliser l'attaque sur le [fichier de capture](files/PMKID_handshake.pcap) utilisant la méthode décrite [ici](https://hashcat.net/forum/thread-7717.html).

> Vu que nous n'avons pas d'AP qui envoie un PMKID, nous ne pouvons pas faire l'étape 1.
>
> Étape 2: On utilise `hcxpcaptool` pour scanner le `.pcap` pour des PMKID, et transformer ceux-cis en un hash utilisable par hashcat.
> ![](img/3.3_hcxcaptool_output.png)
>
> Étape 3: On craque les hashes avec hashcat avec notre dicitonnaire
> ![](img/3.3_hashcat_output.png)
>
> _NB_: The plugin 16800 is deprecated and was replaced with plugin 22000. For more details, please read: https://hashcat.net/forum/thread-10253.html


### 4. Scairodump (Challenge optionnel pour un bonus)

**Note : cet exercice nécessite une interface WiFi en mode monitor. Si vous n'arrivez pas à passer votre interface interne en mode monitor et que vous voulez tenter de le faire, vous pouvez en emprunter une. Il faudra m'avertir pour se mettre d'accord et se retrouver à l'école.**

Modifier votre script de cracking pour qu’il soit capable de faire les mêmes opérations que le script précédant mais sans utiliser une capture Wireshark. Pour cela, il faudra donc sniffer un 4-way handshake utilisant Scapy et refaire toutes les opérations de la partie 2 pour obtenir la passphrase. Le script doit implémenter la possibilité de déauthentifier un client pour stimuler le 4-way handshake. Cette déauthentification doit aussi être implémentée avec Scapy.

## Quelques éléments à considérer :

__Vous aurez peut-être besoin de lire ceci plus d'une fois pour comprendre...__

- Le dernier message du 4-way handshake contient un MIC dans sa payload. Pour calculer vous-même votre MIC, vous devez mettre les octets du MIC dans cette payload à ```\x00```
- Le calcul du MIC peut utiliser MD5 (WPA) ou SHA-1 (WPA2). Le 4-way handshake contient les informations nécessaires dans le champ Key Information

## Livrables

Un fork du repo original . Puis, un Pull Request contenant **vos noms** et :

- Script ```wpa_key_derivation.py``` **modifié pour** la récupération automatique des paramètres à partir de la capture. **Les modifications doivent être commentées/documentées**
- Script ```scaircrack.py``` **abondamment commenté/documenté** + fichier wordlist
   - Capture d’écran de votre script en action
- Script ```pmkid_attack.py``` **abondamment commenté/documenté** + fichier wordlist
   - Capture d’écran de votre script en action
   - Captures d'écran de l'attaque hashcat
-	**(Challenge optionnel)** Script ```scairodump.py``` **abondamment commenté/documenté** 
   - Capture d’écran de votre script en action
-	Envoyer le hash du commit et votre username GitHub et **les noms des participants** par email au professeur et à l'assistant


## Échéance

Le 4 mai 2023 à 23h59
