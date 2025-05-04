# Documentation Projet Fil Rouge 
# TODO : 

- GPO Redirection dossier
- GPO Firefox
- Résolution DNS LAMP1 depuis DC1

Table des matières
- [Introduction](#introduction)
- [Configuration initiale des VMs sur VirtualBox](#configuration-initiale-des-vms-sur-virtualbox)
- [Installation de Ubuntu Server, Windows Server 2022, Debian 12](#installation-de-ubuntu-server--windows-server-2022--debian-12)
- [Configuration des machines](#configuration-des-machines)
  * [R1](#r1)
  * [DC1](#dc1)
  * [DC2](#dc2)
  * [PC1](#pc1)
  * [R2](#r2)
  * [LAMP1](#lamp1)
- [Sécurité](#s-curit-)
  * [Mise en place d'un tunnel GRE](#mise-en-place-d-un-tunnel-gre)
  * [Proposition d'une solution plus sécurisée](#proposition-d-une-solution-plus-s-curis-e)

# Introduction

Ce projet consiste en une migration d'infrastructure pour l'entreprise Safeguard, exerçant dans le secteur de la cybersécurité. Il se déroule dans le cadre d'un projet fil rouge distribué par Dawan. 
L'entreprise ayant subit une expansion rapide, elle souhaite migrer son infrastructure dans de nouveaux locaux plus modernes et un datacenter spécialement conçu pour héberger ses applications web critiques.

Ce projet à pour objectif de nous donner le rôle d'un administrateur systèmes et réseaux. Il est donc important de veiller au bon déroulement de la migration et de faire les bons choix techniques pour assurer la fiabilité de l'infrastructure. Il faut respecter les choix du client tout en restant force de proposition. 

# Configuration initiale des VMs sur VirtualBox
* Infos VM **R1** - Ubuntu Server

| CPU           | RAM           | Stockage      | Firmware      |Interface 1           |Interface 2             |
| ------------- | ------------- | ------------- | ------------- |-------------         |-------------           |
| 1             | 512 MB        |32 GB          | BIOS          |Réseau NAT "Internet" |Réseau Interne "Campus" |

* Infos VM **DC1** - Windows Server 2022
 
| CPU           | RAM            | Stockage       | Firmware      |Interface 1             |
| ------------- | -------------  | -------------  | ------------- |-------------           |
| 2             | 4096 MB        |120 GB          | EFI           |Réseau Interne "Campus" |

* Infos VM **DC2** - Windows Server 2022

| CPU           | RAM            | Stockage       | Firmware      |Interface 1             |
| ------------- | -------------  | -------------  | ------------- |-------------           |
| 2             | 4096 MB        |120 GB          | EFI           |Réseau Interne "Campus" |

* Infos VM **R2** - Ubuntu Server

| CPU           | RAM           | Stockage      | Firmware      |Interface 1           |Interface 2                 |
| ------------- | ------------- | ------------- | ------------- |-------------         |-------------               |
| 1             | 512 MB        |32 GB          | BIOS          |Réseau NAT "Internet" |Réseau Interne "Datacenter" |

* Infos VM **LAMP1** - Debian 12

| CPU           | RAM            | Disque 1       | Disque 2      |Disque 3     |Firmware     |Interface 1                |
| ------------- | -------------  | -------------  | ------------- |-------------|-------------|-------------              |
| 2             | 4096 MB        |32 GB           | 50 GB         |50 GB        |EFI          |Réseau Interne "Datacenter"|


> Pour les machines qui bootent en EFI, lors de la configuration sur VirtualBox, il est important de cocher cette case : 
> ![](https://github.com/user-attachments/assets/44d599cf-f202-44f5-919b-41a956bfe66b)

# Installation de Ubuntu Server, Windows Server 2022, Debian 12
* **Ubuntu Server (R1 et R2)**

Pour l'installation des Ubuntu Server, il s'agit d'une installation classique sans particularité. Il faut surtout bien configurer les interfaces réseau comme suit : 

> R1 - La configuration de la seconde interface se fera en post-installation.
![config_reseau_r1](https://github.com/user-attachments/assets/6f08b0a8-b673-42fe-8f37-5e1a93d879f5)

> R2 - La configuration de la seconde interface se fera en post-installation.
![config_reseau_r2](https://github.com/user-attachments/assets/91afdf95-a7a5-4cd4-8bdb-dd63f3647268)

On a besoin d'un serveur SSH, il faut donc penser à l'installer : 
![installer_ssh_r1_r2](https://github.com/user-attachments/assets/7f065a41-36c8-4a29-8a48-0c367f0bd682)

Si l'installation s'est bien passée, on peut se connecter avec son login et mots de passe après le redémarrage.

> R1
![login_r1](https://github.com/user-attachments/assets/ec17b16a-cc08-4eee-a92f-06ca704fc32c)

> R2
![login_r2](https://github.com/user-attachments/assets/e36a0d83-482f-49ce-bc75-05b7b18ed779)

Par la suite, on va pouvoir se connecter en **SSH** pour plus de praticité.

* **Windows Server 2022 (DC1 et DC2)**

> Il faut faire attention à choisir l'expérience de bureau lors de l'installation.
![install_wserv_1](https://github.com/user-attachments/assets/c11819a3-6d31-4886-9ea1-1ba9a62b2076)

> et un type d'installation personnalisé puisque la première option, dans ce cas, est inutile.
![install_wserv2](https://github.com/user-attachments/assets/289b7fdb-062d-43b6-84eb-f02310dc5600)

* **Debian 12**

Ici la partie importante durant l'installation est la partie stockage. Sur ce serveur il faut une installation standard avec LVM pour mettre en place un RAID1 par la suite : 

> C'est à partir de cette étape qu'on choisit de partitionner les disques avec LVM.
![config_lvm_LAMP1_1](https://github.com/user-attachments/assets/4fba4e6b-dfbe-45d7-bf89-9676d0094586)

> Il faut choisir le premier disque à 34 GB.
![config_lvm_LAMP1_2](https://github.com/user-attachments/assets/aaeaf4be-8f96-4872-a3da-4c1ee71b029a)

>Comme il s'agit d'une installation classique avec LVM on choisit de tout mettre dans une seule partition.
![config_lvm_LAMP1_3](https://github.com/user-attachments/assets/03e78973-1945-45bb-8d4b-fc5103ea5b2b)

# Configuration des machines

## R1

--> Connexion à R1 en SSH

Le **SSH** est une connexion **sécurisée** qui fonctionne par paire de clés **rsa** ou **ed25519** (qui sont des algorithmes de chiffrement). .

La première étape est de configurer une redirection de port sur Virtualbox puisqu'on se situe sur un réseau **NAT** et qu'on veut faire communiquer la machine hôte et la machine virtuelle.

> On se rend sur VirtualBox dans les Outils puis Réseau.
![redirection_port_ssh_1](https://github.com/user-attachments/assets/f849969b-f1b6-4cff-920b-908621005231)

> Puisque la redirection de port se fait par rapport au NAT, on se rend dans l'onglet NAT Networks.
![redirection_port_ssh_2](https://github.com/user-attachments/assets/548a1f19-0573-484e-b5a4-2a539abfacb8)

> Puis Redirection de ports, on ajoute une nouvelle règle.
![redirection_port_ssh_3](https://github.com/user-attachments/assets/7ff3eea6-b79c-48cd-8c04-22c0eb824aab)

> Elle doit être configurée comme suit : 
![redirection_port_ssh_4](https://github.com/user-attachments/assets/243f8f1e-3aa1-4ebb-9fc3-24d88019f58c)

**2222** : C'est le port qu'on ouvre sur l'hôte pour laisser passer la connexion vers la machine virtuelles
**22** : C'est le port par défaut pour une connexion SSH, ici celle entrante sur la machine virtuelle

A partir d'ici il est déja possible de se connecter en SSH via une invite de commande sur la machine hôte en entrant la commande : 

``` console
ssh -p 2222 r1@127.0.0.1
```

A ce stade, l'inconvénient est qu'il faudra toujours entrer un mot de passe pour s'y connecter.

On peut y remédier en utilisant la clé publique de la machine hôte pour l'enregistrer sur la machine invitée. 

**Lire la clé publique de la machine hôte :**

* Pour Windows (depuis le répertoire personnel dans une invite de commande)
``` console
cd .ssh
type id_ed25519.pub
```

ou 

``` console
type id_rsa.pub
```

si la clé est en rsa et pas en ed25519.

**Ajouter la clé sur la machine invitée :**

Il faut d'abord créer un dossier .ssh depuis le répertoire personnel et lui donner les droits de lecture, modification et exécution : 

``` console
mkdir -p ~/.ssh
chmod 700 ~/.ssh
```

Puis il faut ajouter un fichier "authorized_keys" contenant la clé dans le dossier .ssh qu'on vient de créer : 

``` console
echo "clé_publique_ssh" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Si tout s'est bien déroulé, on devrait pouvoir se connecter à R1 depuis une invite de commande de la machine hôte en entrant la même commande que cité ci-avant. Cette fois aucun mot de passe ne sera demandé.

* Configuration du réseau
**a. Installation et configuration du DHCP**


**DHCP** (Dynamic Host Configuration Protocol) est un protocole qui assure une configuration d'IP automatique. Il peut attribuer une adresse IP, un masque de sous réseau, peut configurer l'adresse passerelle par défaut et des serveurs de noms.
On en a besoin pour que notre routeur puisse attribuer une configuration aux nouvelles machines ajoutées sur le réseau, notamment les machines clientes.


Pour installer le serveur DHCP :

``` console
sudo apt update
sudo apt install isc-dhcp-serve
```

Il faut ensuite éditer le fichier de configuration : 

``` console
sudo nano /etc/dhcp/dhcpd.conf
```

**Modifier** les lignes suivantes : 

``` console
option domain-name "safeguard.lan";
default-lease-time 86400;
max-lease-time 86400;
min-lease-time 86400;
```

**Ajouter** les lignes suivantes : 

``` console
subnet 192.168.100.0 netmask 255.255.255.0 {
    range 192.168.100.10 192.168.100.200;
    option routers 192.168.100.1;
    option broadcast-address 192.168.100.255; 
    option domain-name "safeguard.lan";
}
```

> Voici comment devrait être le contenu final.
![config_dhcp_r1](https://github.com/user-attachments/assets/3f76702e-2e4c-4ea2-95cb-c7917409faeb)

Il est important de vérifier si la syntaxe est correcte avec la commande : 

```
sudo dhcpd -t
```

**b. Configurer la deuxième interface réseau avec Netplan**

Pour configurer une interface virtuelle, il faut passer par le fichier *50-cloud-init.yaml*. Pour y accéder : 

```
sudo nano /etc/netplan/50-cloud-init.yaml
```

On va y ajouter la passerelle qui sort sur le réseau NAT et aussi l'adresse de la deuxième interface réseau : 
> Il ne faut pas mettre les <...>, c'est juste pour indiquer les parties ajoutées

``` console
network:
    version: 2
    ethernets:
        enp0s3:
            addresses:
            - 10.72.56.10/24
            nameservers:
                addresses: []
                search: []
         < routes:
            -   to: default
                via: 10.72.56.1 >
      < enp0s8:
            addresses:
            - 192.168.100.254/24 >
```

Pour que la configuration soit prise en compte il faut l'appliquer : 

```
sudo netplan apply
```
Il reste encore à vérifier notre configuration et à activer la seconde interface : 

``` console
ip addr show enp0s3
```
> On peut voir la configuration de l'interface enp0s3.
![ip_addr_show_enp0s3_r1](https://github.com/user-attachments/assets/16fee8c0-25fb-4859-87e6-8c1c026b242f)

``` console
sudo ip link set enp0s8 up
ip addr show enp0s8
```
> On peut voir la configuration de l'interface enp0s8
![ip_addr_show_enp0s8_r1](https://github.com/user-attachments/assets/1585ff04-9f99-4277-870b-7f53cf14b211)

## DC1
* Renommage de la machine et configuration de l'ip

> On peut voir sur l'interface du gestionnaire de serveur que le nom de l'ordinateur est à rallonge et qu'il serait plus simple de le renommer
> Il suffit de cliquer sur "WIN-KVMFUR312LR".
![renommage_DC1_1](https://github.com/user-attachments/assets/a8570128-b6d3-4c79-a976-ddfaa7aed5b1)

> Cette fenêtre s'ouvre, on accède à l'étape suivante en passant par le bouton "Modifier".
![renommage_DC1_2](https://github.com/user-attachments/assets/6c9eb006-8ea6-4428-85c7-4dc1088ddebf)

> On choisit de l'appeler DC1, les modifications seront appliquées au démarrage.
![renommage_DC1_3](https://github.com/user-attachments/assets/4a790ce9-cc54-49fe-ac65-3f54d84a9e19)

> On peut constater que le renommage à bien fonctionné.
![renommage_DC1_4](https://github.com/user-attachments/assets/eb84fd4c-42b2-4af0-afac-49e349ef3075)


Nous pouvons maintenant passer à l'étape de configuration de l'IP. Il est important de toujours attribuer une IP statique à un serveur car on doit toujours pouvoir y accéder par son IP. On ne souhaite donc pas qu'elle change.


La première chose à faire est de voir la configuration ip avec la commande : 
``` console
ipconfig
```
Et lister les cartes réseau avec : 
``` console
Get-NetIPConfiguration
```
![config_ip_DC1_1](https://github.com/user-attachments/assets/9dec297b-f3b6-444b-9c6b-bd0989c60e66)

On définit l'IP statique qui est *192.168.100.250* ainsi que la passerelle par défaut *192.168.100.254* : 

``` console
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.100.250 -PrefixLenght 24 -DefaultGateway 192.168.100.254
```

On peut vérifier de nouveau la configuration avec *ipconfig*.


On peut aussi désactiver l'IPV6, dans notre cas nous n'utiliserons que de l'IPV4 : 

``` console
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6
```

* Mise en place de l'AD

 Ici nous allons voir comment mettre en place l'ADDS (Active Directory Domain Services). Active Directory est un annuaire permettant de répertorier tous les utilisateurs présents sur un domaine, les différentes machines et périphériques ainsi que de les organiser dans des OU (Organisational Units), comme nous allons le voir ci-après.
 
Lorsque Windows Server à redémarré, on peut se connecter avec le compte administrateur définit durant l'installation et accéder au gestionnaire de serveur.

> Aller dans "Ajouter des rôles et fonctionnalités" puis suivre le reste des étapes.
![accéder_a_install_roles_et_fonctionnalites](https://github.com/user-attachments/assets/64cfbe05-bbaa-4003-b58f-03c16c032f04)

![install_ADDS_DC1_1](https://github.com/user-attachments/assets/9f7a93a5-851e-4132-8791-327b23e6de51)

![install_ADDS_DC1_2](https://github.com/user-attachments/assets/0dea544e-14cf-43d9-83ba-e049fbc78144)

> Il ne reste plus qu'à installer l'ADDS.
> Si l'on veut que la machine redémarre automatiquement ci-besoin on peut cocher la case correspondante.
![install_ADDS_DC1_3](https://github.com/user-attachments/assets/ae482eb2-686d-4b38-8a29-1455f699eaa4)


Après l'installation on constate qu'il y a encore une action à faire. En effet, un serveur ne peut pas avoir un Active Directory installé sans être un contrôleur de domaine. L'action demandée par le gestionnaire de serveur est donc de promouvoir DC1 en tant que Contrôleur de domaine. Mais avant, on doit encore installer le rôle de serveur **DNS**.



Le **DNS** (Domain Name System) est un système qui permet de traduire les noms de domaine (exemple : google.com) en adresses IPs lisibles par les machines. Il existe aussi le DNS inversé qui traduit les IPs en noms de domaines. On en a besoin puisque notre serveur se trouve sur un domaine qui possède donc un nom de domaine qu'il faut pouvoir interpréter.

Comme précédemment on ajoute une nouvelle fonctionnalité, on suit l'assistant et on trouve le rôle DNS.

Une fois le rôle installé, on va pouvoir promouvoir DC1 sans problème.

> Passer par "Promouvoir ce serveur en contrôleur de domaine"
![promouvoir_controleur_de_domaine](https://github.com/user-attachments/assets/ecdffdc1-35c0-496f-9717-3af6e4a64269)
> 
![promouvoir_controleur_domaine_DC1_1](https://github.com/user-attachments/assets/ae728c42-d80a-4b8b-a7db-43160bda7a45)

![promouvoir_controleur_domaine_DC1_2](https://github.com/user-attachments/assets/111a1f61-a993-43e6-a9b0-e13531bc590e)

![promouvoir_controleur_domaine_DC1_3](https://github.com/user-attachments/assets/75cb685a-26c6-4ac8-815e-b37bd17ba291)

![promouvoir_controleur_domaine_DC1_4](https://github.com/user-attachments/assets/83f4a51d-d6ed-48ab-8102-fbf1222ec2f7)

A partir d'ici il suffit de passer aux étapes suivantes et de finir l'installation.

* Ajout des OU et des utilisateurs dans l'AD

Pour créer les OU et ajouter les utilisateur, on va passer par une invite de commande et exécuter les commandes suivantes : 

``` console
New-ADOrganizationalUnit -Name "SAFEGUARD" -Path "DC=safeguard,DC=lan"
New-ADOrganizationalUnit -Name "Computers" -Path "OU=SAFEGUARD,DC=safeguard,DC=lan"
New-ADOrganizationalUnit -Name "Clients" -Path "OU=Computers,OU=SAFEGUARD,DC=safeguard,DC=lan"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Computers,OU=SAFEGUARD,DC=safeguard,DC=lan"
New-ADOrganizationalUnit -Name "Users" -Path "OU=SAFEGUARD,DC=safeguard,DC=lan"
```


A l'aide de ces commandes, nous avons crée les OU : **Safeguard, Computers, Clients, Servers et Users**.


Pour ajouter les utilisateurs c'est le même principe. On leur donne un nom de compte, un mail, un nom, un prénom et le chemin vers l'OU "Users" où ils doivent être répertoriés : 

``` console
New-ADUser -SamAccountName "Igauthier" -UserPrincipalName "Igauthier@safeguard.lan" -Name "Isabelle Gauthier" -GivenName "Isabelle" -Surname "Gauthier" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
New-ADUser -SamAccountName "Lmercier" -UserPrincipalName "Lmercier@safeguard.lan" -Name "Laurent Mercier" -GivenName "Laurent" -Surname "Mercier" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
New-ADUser -SamAccountName "Cmartin" -UserPrincipalName "Cmartin@safeguard.lan" -Name "Claire Martin" -GivenName "Claire" -Surname "Martin" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
New-ADUser -SamAccountName "Nbernard" -UserPrincipalName "Nbernard@safeguard.lan" -Name "Nicolas Bernard" -GivenName "Nicolas" -Surname "Bernard" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
New-ADUser -SamAccountName "Slefebvre" -UserPrincipalName "Slefebvre@safeguard.lan" -Name "Sophie Lefebvre" -GivenName "Sophie" -Surname "Lefebvre" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
New-ADUser -SamAccountName "Pmoreau" -UserPrincipalName "Pmoreau@safeguard.lan" -Name "Pierre Moreau" -GivenName "Pierre" -Surname "Moreau" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
New-ADUser -SamAccountName "Pdubois" -UserPrincipalName "Pdubois@safeguard.lan" -Name "Philippe Dubois" -GivenName "Philippe" -Surname "Dubois" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
New-ADUser -SamAccountName "JSimon" -UserPrincipalName "JSimon@safeguard.lan" -Name "Julie Simon" -GivenName "Julie" -Surname "Simon" -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
```

Comme spécifié par le client, les utilisateurs doivent faire partie de différents groupes globaux. Maintenant que nous avons l'OU et les utilisateurs concernés, on peut exécuter : 

``` console
New-ADGroup -Name "GG_Direction" -GroupScope Global -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -Description "Groupe Direction"
New-ADGroup -Name "GG_Compta" -GroupScope Global -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -Description "Groupe Comptabilité"
New-ADGroup -Name "GG_IT" -GroupScope Global -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan" -Description "Groupe IT"
```


Nous venons donc de créer les groupes globaux : **Direction, Compta et IT**.


Maintenant que les groupes sont crées il reste encore à placer les utilisateurs à l'intérieur : 

``` console
Add-ADGroupMember -Identity "GG_Direction" -Members "Igauthier", "Lmercier", "Cmartin"
Add-ADGroupMember -Identity "GG_Compta" -Members "Nbernard", "Slefebvre", "Pmoreau"
Add-ADGroupMember -Identity "GG_IT" -Members "Pdubois", "JSimon"
```

**Il faut également créer des groupes locaux.**


Avant de créer les groupes locaux, il est important de dire que nous sommes en train d'appliquer la méthode **AGDLP** (Account, Global, Domain Local, Permission). Cette méthode repose sur l'imbrication de groupes de sécurité. Le principe est de ne pas avoir de permissions reliées directement à un objet utilisateur au niveau des partages.


> *source : it-connect.fr*
![Methode-AGDLP-Exemple](https://github.com/user-attachments/assets/9722d291-0e21-4d92-b728-9edbd21c1d80)


Les **permissions** sont accordées aux **groupes locaux**. Les **groupes globaux**, créés précédemment, **feront partis** des groupes locaux. Les **utilisateurs** faisant partis des groupes globaux, par conséquent, **hériteront** des permissions des groupes locaux.


Pour créer les groupes locaux : 

``` console
New-ADGroup -Name "GL_Direction_RW" -GroupScope DomainLocal -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan"
New-ADGroup -Name "GL_Compta_RW" -GroupScope DomainLocal -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan"
New-ADGroup -Name "GL_Compta_RO" -GroupScope DomainLocal -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan"
```

Nous nous occuperons du côté partage sur DC2.

## DC2

Comme pour DC1, il faut renommer la machine et aussi configurer son ip.

Le but du serveur DC2 est d'être un réplicat de DC1. Par conséquent, il faut l'ajouter au domaine : 

```console
Add-Computer -DomainName "safeguard.lan" -Credential "SAFEGUARD\Administrateur" -Restart
```

Exactement comme pour DC1 il faut installer l'**ADDS** et le **DNS**. 

* Ajout en tant que contrôleur de domaine

Cette fois on peut le promouvoir en contrôleur de domaine via l'invite de commande : 

```console
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

```console
Import-Module ADDSDeployment
Install-ADDSDomainController `
-NoGlobalCatalog:$false `
-CreateDnsDelegation:$false `
-Credential (Get-Credential) `
-CriticalReplicationOnly:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainName "safeguard.lan" `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SiteName "Default-First-Site-Name" `
-SysvolPath "C:\Windows\SYSVOL" `
-InstallDns:$true
```

On peut vérifier la promotion avec cette commande : 

``` console
Get-ADDomainController -Filter * | Select-Object Name, Domain, Site
```

Avant de passer à la suite, on peut ajouter DC2 en tant que DNS auxiliaire de DC1 (en passant par DC1) : 

``` console
Add-DnsServerForwarder -IPAddress 192.168.100.251
```


On ajoute DC2 comme DNS auxiliaire de DC1 pour créer plus de fiabilité. Si DC1 venait à avoir un souci de DNS alors DC2 pourrait prendre le relais. Cet incident serait non bloquant.


* Services SMB et d'impression
    * SMB


**SMB** (Server Message Block) est un protocole qui permet de partager des ressources dans un réseau local avec des machines sous Windows. Ce protocole va donc nous permettre de mettre en place un partage de fichier destinés aux différents utilisateurs du domaine. Ces partages seront soumis à différentes autorisations s'appliquant selon le rôle des différents utilisateurs (**Administrateur, Utilisateurs du domaine,** etc...) ou de leur groupe.


Il y a plusieurs dossier qui seront partagés à créer : 
- DATA
- Direction
- Compta
- Public
- Logiciels

**DATA** sera le répertoire principal contenant tous les autres dossiers. Voici la commande pour le créer : 

``` console
New-Item -Path "C:\" -Name "DATA" -ItemType "Directory"
```
Maintenant il faut créer les sous répertoires : 

``` console
New-Item -Path "C:\DATA" -Name "Direction" -ItemType "Directory"
New-Item -Path "C:\DATA" -Name "Compta" -ItemType "Directory"
New-Item -Path "C:\DATA" -Name "Public" -ItemType "Directory"
New-Item -Path "C:\DATA" -Name "Logiciels" -ItemType "Directory"
```

Pour suivre la méthode **AGDLP**, il faut ajouter les groupes globaux aux groupes locaux : 

``` console
Add-ADGroupMember -Identity "GL_Direction_RW" -Members "GG_Direction"
Add-ADGroupMember -Identity "GL_Compta_RW" -Members "GG_Compta"
Add-ADGroupMember -Identity "GL_Compta_RO" -Members "GG_Compta"
```

Maintenant il faut s'occuper de partager les dossiers en appliquant les permissions NTFS et le partage avec le protocole SMB.


**NTFS** (New Technology File System) est un **système de fichier** standard sous Windows. Sur un volume NTFS chaque dossier et fichier a **ses propres permissions**. Ces permissions consiste à définir **l'accès aux données** en lecture, écriture, modification, etc... 


**Application des permissions NTFS et du partage sur Direction :** 

> NTFS
```console
$acl = Get-Acl "C:\DATA\Direction"
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("GL_Direction_RW", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Admins du domaine", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule1)
$acl.AddAccessRule($rule2)
Set-Acl "C:\DATA\Direction" $acl
```
> SMB
```console
New-SmbShare -Name "Direction" -Path "C:\DATA\Direction" -FullAccess "Admins du domaine" -ChangeAccess "GL_Direction_RW" -ReadAccess "Utilisateurs authentifiés"
```

**Application des permissions NTFS et du partage sur Compta :**

```console
$acl = Get-Acl "C:\DATA\Compta"
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("GL_Compta_RW", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Admins du domaine", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$rule3 = New-Object System.Security.AccessControl.FileSystemAccessRule("GL_Compta_RO", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule1)
$acl.AddAccessRule($rule2)
$acl.AddAccessRule($rule3)
Set-Acl "C:\DATA\Compta" $acl
```

```console
New-SmbShare -Name "Compta" -Path "C:\DATA\Compta" -FullAccess "Admins du domaine" -ChangeAccess "GL_Compta_RW" -ReadAccess "GL_Compta_RO"
```

**Application des permissions NTFS et du partage sur Public :**

```console
$acl = Get-Acl "C:\DATA\Public"
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("Tout le monde", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule1)
Set-Acl "C:\DATA\Public" $acl
```

```console
New-SmbShare -Name "Public" -Path "C:\DATA\Public" -FullAccess "Tout le monde"
```

**Application des permissions NTFS et du partage sur Logiciels :**

```console
$acl = Get-Acl "C:\DATA\Logiciels"
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("Admins du domaine", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("Utilisateurs du domaine", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule1)
$acl.AddAccessRule($rule2)
Set-Acl "C:\DATA\Logiciels" $acl
```

```console
New-SmbShare -Name "Logiciels" -Path "C:\DATA\Logiciels" -FullAccess "Admins du domaine" -ReadAccess "Utilisateurs du domaine"
```

* Création et déploiement des GPOs


**GPO** (Group Policy Object), également appelées *Stratégies de groupes*. Les GPOs sont un ensemble de règle qui permettent de mettre en place des stratégies de sécurité. Ces stratégies sont paramétrées par **l'administrateur système** et sont appliquées ensuite à des postes de travail, des serveurs ou des utilisateurs.
Les stratégies créées une **homogénéité** entre les machines mais aussi dans l'environnement des utilisateurs. On peut **appliquer** et **déployer** des **paramètres Windows**, par exemple, sur **toutes les sessions** des utilisateurs du domaine ou sur **un utilisateur en particulier** directement.
Le point important est que les GPOs permettent aux administrateurs systèmes de gérer les règles de sécurités (pour les utilisateurs ou les ordinateurs) de façon **centralisée**.


* Attribution d'un fond d'écran à tous les utilisateurs du domaine

Le but de cette GPO est de généraliser le fond d'écran des utilisateurs. Ce qui veut dire qu'à chaque ouverture de session tous les utilisateurs du domaines auront le même fond d'écran.

Voici le fond d'écran à utiliser : 

![Wallpaper_Users](https://github.com/user-attachments/assets/76b5aa72-425f-4792-b5eb-bae48f12bca0)

Il est nécessaire de créer la GPO via l'outil de gestion des stratégie de groupe : 

![acceder_outil_strategie_de_groupe](https://github.com/user-attachments/assets/19f09b52-2cdc-44f6-99f3-e5f854b762ef)

> Outil de stratégies de groupe
![gestionnaire_strategie_de_groupe](https://github.com/user-attachments/assets/ac491bbd-0cc3-4e5c-8c81-f4dfbe2a78ed)

> Créer la GPO dans le domaine Safeguard
![creation_gpo_wallpaper_1](https://github.com/user-attachments/assets/3bafdc61-e5b6-4359-9a34-86c9d1854e57)

> Donner un nom à la GPO
![creation_gpo_wallpaper_2](https://github.com/user-attachments/assets/2511b28f-a662-43fd-9e8f-638451f53d0a)

> La GPO est créée
![gpo_wallpaper_creee](https://github.com/user-attachments/assets/dbddbd5c-120d-4a45-940c-7b9453e78b2b)

> Mettre en place la GPO en passant par *Modifier*
![modification_gpo_wallpaper](https://github.com/user-attachments/assets/ddbd2bbd-54d6-4783-9f8e-6ee5f99d0ad7)

> Double-cliquer sur "Papier peint du bureau"
![activer_gpo_papier_peint_bureau](https://github.com/user-attachments/assets/1dd10756-7edc-45bb-94d3-be36bbbf5012)

> Configurer le papier peint de bureau
![gpo_configurer_papier_peint_bureau](https://github.com/user-attachments/assets/6e43df0e-d6d1-4bea-8635-07efff4d8987)

Il faut maintenant utiliser le dossier *DATA* précédemment créé et partagé. Nous allons créer un dossier, ici appelé *User* dans *DATA* (on peut le voir dans le chemin réseau attribué lors de la configuration du papier peint de bureau). Il faut ensuite paramétrer les permissions NTFS sur ce dossier : 

![permissions_ntfs_dossier_user](https://github.com/user-attachments/assets/585035a1-ba01-4b44-9aae-926fb88f8925)

Puis se rendre dans *Autorisation > Ajouter* : 

![ajout_autorisations_dossier_user](https://github.com/user-attachments/assets/a48ecbb2-d5f0-43ed-ae5b-4fa73c6ed666)

Voici ce qui devrait apparaître :

![ajout_image_finale_dossier_user](https://github.com/user-attachments/assets/ec7dadbd-5862-4df7-aae5-04c5c23559f0)

Il ne reste plus qu'à ajouter le fond d'écran dans le dossier *User* :

![ajout_fond_ecran_dossier_user](https://github.com/user-attachments/assets/3be48030-b9d2-4344-8d05-e2f5d972a436)

* Publication de Firefox
* Verouillage de compte utilisateurs

L'utilité de créer une GPO de verrouillage de compte est d'empêcher un utilisateur mal intentionné de forcer l'ouverture d'une session en bloquant le compte au bout d'un certains nombre d'essaie de connexion.

Comme précédemment il faut se rendre dans l'outil de gestion des stratégies de groupe et créer la GPO.
Il faut la configurer comme suit : 

![gpo_verrouillage_de_compte](https://github.com/user-attachments/assets/b81b2174-14c1-4314-9d88-96d151bfcaf9)

* Montage d'un lecteur réseau

![gpo_lecteur_p_1](https://github.com/user-attachments/assets/f0d49b5f-0552-4613-ae8c-e3740e026280)

![gpo_lecteur_p_2](https://github.com/user-attachments/assets/6caed7c7-6b72-4ae8-b752-8c43bc607875)

![gpo_lecteur_p_3](https://github.com/user-attachments/assets/069987f7-096a-4180-bca0-70b602009254)

![gpo_lecteur_p_4](https://github.com/user-attachments/assets/f6eddb35-2d2b-46a4-b266-7ef7bf40f782)

* Déploiement d'une imprimante TCP/IP

On souhaite déployer une imprimante TCP/IP, mais notre serveur n'a pas le rôle de serveur d'impression. Il faut donc l'installer, tout comme les rôles et fonctionnalités précédemment ajoutés.

> Un redémarrage sera nécessaire.
![ajout_role_impression](https://github.com/user-attachments/assets/075c1bab-14ae-4589-a48a-e72533bbebd0)

Après l'installation et le redémarrage, on doit ajouter un pilote pour l'imprimante pour pouvoir s'en servir. On se rend dans l'outil de Gestion de l'impression : 

![outils_gestion_impression](https://github.com/user-attachments/assets/a79ed4e8-07bf-424e-95c4-ab3649be8c41)

Il suffit de suivre les étapes suivante :

![ajout_pilote_gestion_impression](https://github.com/user-attachments/assets/08437008-6cbc-4b06-8c7e-80b4f5f96c76)

![selection_processeur_imprimante](https://github.com/user-attachments/assets/e81f79df-ea7b-42c1-b43c-a2d49f460295)

![selection_pilote_imprimante](https://github.com/user-attachments/assets/954a67af-95d0-4206-9780-d30256aa32d1)

Désormais, il est nécessaire d'ouvrir un port dédié à l'imprimante, en suivant les étape ci-après :

![ajout_port_gestion_impression](https://github.com/user-attachments/assets/b72e63a6-38c5-4aed-b70c-c89a734bed5c)

![selection_type_port_imprimante](https://github.com/user-attachments/assets/ca08cd56-6028-42e1-b70a-d6b1031c2024)

![ajout_ip_port_impression](https://github.com/user-attachments/assets/855e47e4-4111-4a0c-8875-e337d2db2287)

![selection_type_peripherique_imprimante](https://github.com/user-attachments/assets/1607b66d-58bd-4242-995e-1be25c35ad92)

Maintenant, il reste à ajouter l'imprimante en la reliant à son port et à son pilote dédié : 

![ajout_imprimante_gestion_impression](https://github.com/user-attachments/assets/cc4b451c-0d70-484a-a4d8-e7dade4631cc)

> Lier le port
![ajout_imprimante_via_port_cree](https://github.com/user-attachments/assets/4ea6f27d-bfb6-4857-b762-a49b286869f3)

> Lier le pilote
![ajout_imprimante_via_pilote_cree](https://github.com/user-attachments/assets/9443c2ed-640a-4873-a884-48833e1381c6)

> Nommer l'imprimante et la partager
![nommage_imprimante](https://github.com/user-attachments/assets/437fe0cb-4cbe-45c6-b8c6-5271b64432b8)

> Il est possible de vérifier en imprimant une page de test.

> On doit pouvoir retrouver l'imprimante dans le gestionnaire d'impression
![ajout_imprimante_image_finale](https://github.com/user-attachments/assets/b9292a48-9d60-4f2f-a92d-af882ac118aa)

La dernière étape est de lister l'imprimante dans l'annuaire pour y avoir accès.

> Lister l'imprimante dans l'annuaire
![lister_imprimante_dans_annuaire_gestion_impression](https://github.com/user-attachments/assets/5352fc23-76e4-4e99-ba9d-3c27857edab6)

> Cocher la case *Lister dans l'annuaire*
![cocher_case_lister_annuaire_gestion_impression](https://github.com/user-attachments/assets/acc155a6-21b5-4e2c-b1b4-c3414f7f62bf)

> *Supprimer de l'annuaire* à dû s'ajouté dans la liste d'options
![supprimer_de_lannuaire_sest_ajoute_gestion_impression](https://github.com/user-attachments/assets/dfcf040f-248f-4ef4-b972-67916954f02b)

* Redirection du dossier Documents
* Activation du RDP

Créer la GPO en l'appelant Desktop_Remote.

> Configurer l'autorisation pour l'ouverture de sessions à distance
![gpo_activer_rdp_1](https://github.com/user-attachments/assets/03ee6cd7-d8cb-4583-b923-b368b6a62a2e)

> Cocher la case *Définir ces paramètres de stratégie* pour *Ajouter un utilisateur ou un groupe*
![gpo_activer_rdp_2](https://github.com/user-attachments/assets/7f234ce9-0f7c-4007-a9cf-c2eb1ccb0450)

> Taper *Admins du domaine*
![gpo_activer_rdp_3](https://github.com/user-attachments/assets/389d9402-527e-44f0-980c-297d9c7188db)

> *Appliquer* la configuration
![gpo_activer_rdp_4](https://github.com/user-attachments/assets/f33e0c55-9f34-4851-96b0-23e81caccea0)

L'ouverture de sessions à distance est désormais activée.

## PC1
* Connexion avec un utilisateur du domaine
* Vérification du fonctionnement des GPOs

## R2
* Configuration réseau

## LAMP1
* Se connecter en SSH

Après l'installation de LAMP1 on peut remarquer que *sudo* n'est pas installé mais on va avoir besoin du rôle de super utilisateur pour faire certaines actions. 

La première étape est de passer en mode administrateur : 

``` sh
su -
```

Puis installer *sudo* : 

``` sh
apt update
apt install sudo
```

Il reste à ajouter l'utilisateur au groupe *sudoers* pour qu'il soit autorisé à utiliser la commande *sudo*. Pour ça, on peut passer par plusieurs méthodes : 

> Méthode 1
``` sh
usermod -aG sudo lamp1 # Utilise usermod pour ajouter l'utilisateur au groupe sudo
```

> Méthode 2
``` sh
echo ' lamp1 ALL=(ALL)   ALL' >> /etc/sudoers # Ajoute la ligne ' lamp1 ALL=(ALL)   ALL' au fichier sudoers se situant dans /etc
```
On peut maintenant utiliser la commande *sudo*.

 info
Nous pouvons nous connecter à LAMP1 en SSH comme pour R1 et R2 pour plus de simplicité et de lisibilité. Pour cela, il faudra d'abord se connecter à R2 en SSH, puis depuis R2, se connecter à LAMP1.


Le service SSH n'étant pas installer il faut l'installer : 

``` sh
sudo apt update
sudo apt install openssh-server # Installe openssh
```

> Vérifier que le service SSH est bien actif
``` sh
sudo systemctl status ssh
```

> S'assurer que le service se lancera à chaque démarrage
``` sh
sudo systemctl enable ssh
sudo systemctl start ssh
```

Il faut encore ouvrir le port nécessaire pour pouvoir se connecter. Le port SSH par défaut est le port 22. On va utiliser l'outil *iptables*.

 warning
**iptables** est un outil en ligne de commande utilisé pour configurer le pare-feu du noyau. Il permet de **contrôler le trafic réseau entrant, sortant ou traversant une machine**.


``` sh
sudo iptables -t nat -A PREROUTING -p tcp --dport 2224 -j DNAT --to-destination 192.168.200.11:22 # On définit le type de réseau, le protocole et la destination
sudo iptables -A FORWARD -p tcp -d 192.168.200.11 --dport 22 -j ACCEPT # Autorise le paquet à passer par le port 22
```

> Sauvegarder les règles *iptables*
``` sh
sudo sh -c 'iptables-save > /etc/iptables/rules.v4' # Exporte les règles au format lisible par la machine vers le fichier rules.v4
sudo iptables-restore < /etc/iptables/rules.v4 # Recharge les règles iptables à partir du fichier rules.v4
```

On peut désormais se connecter depuis R2 : 

``` sh
ssh lamp1@192.168.200.11
```

Comme pour R1 et R2, on peut faire en sorte de plus entrer de mot de passe à la connexion. 
Cette fois il faudra générer une clé sur R2 : 

``` sh
ssh-keygen -t ed25519 -C "your_email@example.com"
```

Puis comme vu précédemment la copier, cette fois vers LAMP1.

* Mise en place d'un RAID1


Le **RAID** est un ensemble de technique de virtualisation de stockage qui permet de **répartir les données sur plusieurs disques** pour améliorer la fiabilité, la disponibilité, les performances et capacités de stockage.
Il existe plusieurs types de RAID, ici nous allons mettre en place un **RAID1**.


> Ce schéma montre qu'il faut un minimum de **deux disques** pour mettre en place un RAID1. Les données sont écrites sur **chacun des diques**. On peut perdre un maximum d'**un seul disque**. Les deux disques doivent avoir la **même capacités de stockage**.
![schema_raid1](https://github.com/user-attachments/assets/039c6a04-8f6c-431b-951c-a59655684a97)

Sur Debian, il existe un outil qui permet de créer des RAIDs qui s'appelle **mdadm**. C'est un package à installer : 

``` console
sudo apt install mdadm
```

Avant de commencer à utiliser **mdadm** il faut revoir la configuration des disques avec la commande : 

``` console
lsblk
```

Il faut créer le RAID1 à partir des deux disques de 50 GB créé dans la configuration initiale : 

``` console
sudo mdadm --create /dev/md0 --assume-clean --level=1 --raid-devices=2 /dev/sdb /dev/sdc
```

Ici les partitions se nomment *sdb* et *sdc*, mais il est possible que le système ait donné des intitulés différents.

On peut vérifier la nouvelle configuration des disques : 

> Sur cette capture, la configuration à été appliquée
![configuration_raid1_1](https://github.com/user-attachments/assets/8593a51e-6851-4607-acbd-7c6c042ee787)

Le format de fichier demandé par le client est l'**ext4**.


**ext4** est un **système de fichier** principalement destiné aux distributions **GNU/Linux**. Il est le successeur de l'**ext3**.


Il est possible de formatter les disques du RAID avec la commande **mkfs** :

``` console
sudo mkfs.ext4 /dev/md0
```

> Résultat de la commande **mkfs**
![resultat_commande_mkfs_raid1](https://github.com/user-attachments/assets/79726f28-a416-4cd0-a0de-8943e400ef64)

Maintenant, il faut *monter* les disques et configurer le montage automatique pour qu'ils soient "accessibles" à chaque démarrage : 

``` console
sudo mkdir /mnt/local1
sudo mount /dev/md0 /mnt/local1 # Monter les disques
echo '/dev/md0 /mnt/local1 ext4 defaults 0 2' | sudo tee -a /etc/fstab # Configurer le montage automatique
```
> Résultat des commandes précédentes
![resultat_commandes_montage_raid1](https://github.com/user-attachments/assets/5c072f6c-f464-424a-98a0-fd96b6ac65f5)

* Création du répertoire *www*

On doit créer un répertoire nommé *www* (il se situera dans *local1*) qui accueillera la racine de chaque application web déployée sur le serveur.

Il suffit de se servir de la commande **mkdir** : 

``` console
sudo mkdir /mnt/local1/www
```

> On voit que le fichier à bien été créé
![lister_fichiers_local1_dossier_www](https://github.com/user-attachments/assets/1967156a-c7f9-472d-aab5-b6f483ef45ba)

* Installation de la stack **LAMP** (Apache2, MariaDB et PHP-FPM)

 warning
**LAMP** est l'acronyme de *Linux, Apache, MySQL/MariaDB et PHP*. C'est un **ensemble de technologies** permettant de créer des **applications web** performantes.


``` sh
sudo apt update
sudo apt install apache2 mariadb-server php-fpm # Installer la stack
sudo apt install ca-certificates lsb-release apt-transport-https # Ajoute des paquets pour l'ajout de dépôts, faire des connexions sécurisées et identifier la version du système
sudo curl -sSL https://packages.sury.org/php/README.txt | sudo bash - # Récupère le paquet PHP-FPM depuis l'archive d'Ondrej Sury
sudo apt install php8.3-fpm php8.3-mysql php8.3-cli php8.3-common php8.3-gd php8.3-xml php8.3-mbstring # Installe les dernières versions de PHP
```

* Déploiement de Wordpress

 warning
**WordPress** est un système de gestion de contenu (ou **CMS** pour Content Management System). C’est un outil qui permet de **créer** et de **gérer**** facilement un site web. Une partie est **l'interface qui permet de gérer le site**, une autre est **le serveur qui met à disposition le site** et aussi une partie **dédiée au stockage des données du site**.


Le but de déployer Wordpress est de le rendre disponible.
    
```sh
cd /mnt/local1/www # Se rendre dans le dossier www
sudo wget https://wordpress.org/latest.tar.gz # Récupérer la dernière version de Wordpress
sudo tar -xvzf latest.tar.gz # Extraire l'archive
sudo mv wordpress www.safeguard.lan # Bouger le dossier wordpress vers www.safeguard.lan
```

* Création de la base de données MariaDB

 warning
**MariaDB** est un **SGBD** ou Système de Gestion de Bases de Données Relationelles. Comme son nom l'indique c'est un **système** permettant de **créer, organiser et gérer les données**.


Pour stocker les données du site, Worpress va avoir besoin d'une base de données qui sera gérée via MariaDB.

Il faut d'abord créer la base à l'aide d'un script **SQL** : 

``` sql
CREATE DATABASE wwwsafeguardlan CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'wwwadmin'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON wwwsafeguardlan.* TO 'wwwadmin'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Puis la configurer en accédant à un fichier de config que l'on va renommer et modifier : 

``` sh
sudo cp /mnt/local1/www/www.safeguard.lan/wp-config-sample.php /mnt/local1/www/www.safeguard.lan/wp-config.php # Renommer le fichier 
sudo nano /mnt/local1/www/www.safeguard.lan/wp-config.php # Ouvrir le fichier avec un editeur (ici nano)
```

> Voici à quoi devra ressembler le fichier de configuration
![config_bdd_lamp1](https://github.com/user-attachments/assets/d3d7b60e-1122-4e5e-9dd5-e39af040ff08)

* Configuration Apache2

 warning
**Apache2** est un **serveur** permettant d'**héberger des applications web**, notamment avec **PHP**.


Pour configurer Apache2, il est nécessaire d'accéder au fichier de configuration : 

``` sh
sudo nano /etc/apache2/sites-available/www.safeguard.lan.conf
```

Il faut ajouter les lignes suivantes : 

``` sh
<VirtualHost *:80>
    DocumentRoot /mnt/local1/www/www.safeguard.lan # Fichier racine
    ServerName www.safeguard.lan # Nom du serveur

    <Directory /mnt/local1/www/www.safeguard.lan>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

Il ne reste plus qu'à activer le site : 

``` sh
sudo a2ensite www.safeguard.lan.conf
sudo a2enmod rewrite
sudo systemctl restart apache2
```

* Appliquer la résolution DNS depuis DC1 vers LAMP1

# Sécurité
## Mise en place d'un tunnel GRE


**GRE** (Generic Routing Encapsulation) est un **protocole** qui permet d'**encapsuler** tous les paquets dans leur **conception d'origine** dans la couche réseau.
Mettre en place un tunnel GRE est le **minimum** de sécurité à appliquer.


 info
Le but ici est de mettre en place un tunnel GRE entre R1 et R2 pour pouvoir faire communiquer les réseaux Datacenter et Campus.


> Il faut installer le paquet *net-tools* qui permet de pouvoir gérer le sous-système réseau
``` sh
sudo apt install net-tools
```

``` bash
sudo ip tunnel add gre1 mode gre local 10.72.56.10 remote 10.72.56.20 ttl 255 # On configure le tunnel en lui donnant un nom, le mode *gre* en précisant que le end-point local est le routeur R1 et celui qui est relié est R2
sudo ip addr add 10.0.0.1/30 dev gre1 # Attribue l'adresse 10.0.0.1 comme point d'extrémité sur R1
sudo ip link set gre1 up # Active l'interface du tunnel
```

``` sh
sudo ip tunnel add gre1 mode gre local 10.72.56.20 remote 10.72.56.10 ttl 255 # On configure le tunnel en lui donnant un nom, le mode *gre* en précisant que le end-point local est le routeur R2 et celui qui est relié est R1
sudo ip addr add 10.0.0.2/30 dev gre1 # Attribue l'adresse 10.0.0.2 comme point d'extrémité sur R2
sudo ip link set gre1 up # Active l'interface du tunnel
```

``` sh
sudo ip route add 192.168.200.0/24 via 10.0.0.2 dev gre1 # Etablit l'acheminement réseau vers Datacenter 
```

``` sh
sudo ip route add 192.168.100.0/24 via 10.0.0.1 dev gre1 # Etablit l'acheminement réseau vers Campus
```

Notre tunnel GRE est mis en place. Le souci est qu'il ne sera pas actif automatiquement à chaque démarrage. Il faut donc créer un script sur chacun des routeurs et créer un service qui se lancera automatiquement à chaque démarrage de la machine.

> Sur R1 et R2
``` sh
sudo nano /etc/network/if-up.d/gre-tunnel.sh # Création du fichier qui contiendra le script
```

> Script pour R1
``` sh
#!/bin/bash

# Vérifie si le tunnel gre1 existe déjà
if ip link show gre1 > /dev/null 2>&1; then
    echo "Tunnel GRE déjà existant."
    exit 0
fi

# Crée l'interface GRE
ip tunnel add gre1 mode gre local 10.72.56.10 remote 10.72.56.20 ttl 255
ip addr add 10.0.0.1/30 dev gre1
ip link set gre1 up

# Route vers le réseau de R2
ip route add 192.168.200.0/24 via 10.0.0.2 dev gre1
```

> Script pour R2
``` sh
#!/bin/bash

if ip link show gre1 > /dev/null 2>&1; then
    echo "Tunnel GRE déjà existant."
    exit 0
fi

ip tunnel add gre1 mode gre local 10.72.56.20 remote 10.72.56.10 ttl 255
ip addr add 10.0.0.2/30 dev gre1
ip link set gre1 up

ip route add 192.168.100.0/24 via 10.0.0.1 dev gre1
```

> Sur R1 et R2
``` sh
sudo chmod +x /etc/network/if-up.d/gre-tunnel.sh # Rends le script exécutable
```

On va désormais passer à la création du service sur les deux machines.

``` sh
sudo nano /etc/rc.local # Création du fichier qui contiendra le script permettant de lancer le tunnel
```

> Contenu de *rc.local*
``` sh
#!/bin/bash
bash /etc/network/if-up.d/gre-tunnel.sh & # Lance le tunnel GRE
exit 0
```

``` sh
sudo chmod +x /etc/rc.local # Rends le script exécutable
```

``` sh
sudo nano /etc/systemd/system/rc-local.service # Créer le fichier de service systemd
```

> Contenu du fichier
``` sh
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
```

``` sh
sudo systemctl daemon-reload # Recharge les processus
sudo systemctl enable rc-local # Rends actif rc-local 
sudo systemctl start rc-local # Démarre rc-local
sudo systemctl status rc-local # Vérifie son status
```
 Voilà, le servie est mis en place et devrait permettre de lancer le tunnel GRE automatiquement. Il est possible de vérifier après un redémarrage. 
Sur R1 on peut essayer de joindre le serveur LAMP1 et sur R2 le serveur DC1 par exemple : 

> Sur R1
``` bash
ping 192.168.200.11 # ip de LAMP1
```

> Sur R2
``` bash
ping 192.168.100.250 # ip de DC1
```

S'il a réponse des deux serveurs respectif alors le tunnel à bien démarré automatiquement.

## Proposition d'une solution plus sécurisée
* Mise en place d'un VPN IPsec

**IPsec** (Internet Protocol Security) est une **suite de protocoles** qui permet de **sécuriser** les communications entre **deux points sur un réseau**. IPsec **chiffre** et **authentifie** les données qui passent entre deux machines, créant ainsi un tunnel sécurisé. Cela empêche les pirates de lire ou modifier les données pendant leur transit.

Un **VPN IPsec** permet donc de créer un tunnel sécurisé pour que deux réseaux ou ordinateurs puissent communiquer en toute sécurité, comme s’ils étaient sur le **même réseau local**.


On va d'abord intaller *strongswan*.

 info
strongSwan est un **logiciel VPN**.


``` sh
sudo apt install strongswan # Installe strongswan
```

``` sh
sudo nano /etc/ipsec.conf # Accède au ficher de configuration ipsec
```

> Sur R1, le contenu doit être celui-ci
``` sh
config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids = yes

conn gre-ipsec
    auto=start
    left=10.72.56.10          
    right=10.72.56.20          
    type=transport
    keyexchange=ikev2
    authby=secret
    esp=aes256-sha256-modp2048
    ike=aes256-sha256-modp2048
```

> Sur R2, le contenu doit être celui-ci
``` sh
config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids = yes

conn gre-ipsec
    auto=start
    left=10.72.56.20          
    right=10.72.56.10          
    type=transport
    keyexchange=ikev2
    authby=secret
    esp=aes256-sha256-modp2048
    ike=aes256-sha256-modp2048
```

``` sh
sudo nano /etc/ipsec.secrets # Accède au fichier pour la configuration de l'authentification
```

``` sh
10.72.56.10 10.72.56.20 : PSK "P@ssw0rd" # R1
10.72.56.20 10.72.56.10 : PSK "P@ssw0rd" # R2
```

``` sh
sudo systemctl restart strongswan-starter.service # Recharge le service de strongswan
```

``` sh
sudo ipsec statusall # Vérifier le status du VPN IPsec
```

Notre tunnel VPN IPsec est mis en place, nos données vont pouvoir circuler en toute sécurité entre nos réseaux Datacenter et Campus.
