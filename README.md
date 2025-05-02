# Documentation Projet Fil Rouge

> [name=Noémie Vasseur]
> [time=06 Mai 2025][color=purple]

## Table des matières

[TOC]

## Introduction

Ce projet consiste en une migration d'infrastructure pour l'entreprise Safeguard, exerçant dans le secteur de la cybersécurité. Il se déroule dans le cadre d'un projet fil rouge distribué par Dawan. 
L'entreprise ayant subit une expansion rapide, elle souhaite migrer son infrastructure dans de nouveaux locaux plus modernes et un datacenter spécialement conçu pour héberger ses applications web critiques.

Ce projet à pour objectif de nous donner le rôle d'un administrateur systèmes et réseaux. Il est donc important de veiller au bon déroulement de la migration et de faire les bons choix techniques pour assurer la fiabilité de l'infrastructure. Il faut respecter les choix du client tout en restant force de proposition. 

## Configuration initiale des VMs sur VirtualBox
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
> ![](https://s3.hedgedoc.org/hd1-demo/uploads/d47f6f6c-b2bd-42af-b2c2-0c81e3f78a4e.png)
[color=#6c3483]



## Installation de Ubuntu Server, Windows Server 2022, Debian 12
* **Ubuntu Server (R1 et R2)**

Pour l'installation des Ubuntu Server, il s'agit d'une installation classique sans particularité. Il faut surtout bien configurer les interfaces réseau comme suit : 

> R1 - La configuration de la seconde interface se fera en post-installation.
![](https://s3.hedgedoc.org/hd1-demo/uploads/7329feb1-41c1-4e1a-bf73-443db74cb6e3.png)
[color=#6c3483]

> R2 - La configuration de la seconde interface se fera en post-installation.
![](https://s3.hedgedoc.org/hd1-demo/uploads/27b429ae-b9fc-4748-88b9-47c7d293ca0d.png)
[color=#6c3483]

On a besoin d'un serveur SSH, il faut donc penser à l'installer : 

![](https://s3.hedgedoc.org/hd1-demo/uploads/776fdff9-a0c9-488d-bad6-dfc5818537db.png)

Si l'installation s'est bien passée, on peut se connecter avec son login et mots de passe après le redémarrage.

> R1
![](https://s3.hedgedoc.org/hd1-demo/uploads/1faf7403-3ad5-492a-80b7-f89679868ba6.png)
[color=#6c3483]

> R2
![](https://s3.hedgedoc.org/hd1-demo/uploads/2081663d-f6f0-4897-9d3d-a30b672a7a85.png)
[color=#6c3483]

Par la suite, on va pouvoir se connecter en **SSH** pour plus de praticité.

* **Windows Server 2022 (DC1 et DC2)**

> Il faut faire attention à choisir l'expérience de bureau lors de l'installation.
![](https://s3.hedgedoc.org/hd1-demo/uploads/ecd32cc2-8d5e-446c-b394-b94b9323cb78.png)
[color=#6c3483]

> et un type d'installation personnalisé puisque la première option, dans ce cas, est inutile.
![](https://s3.hedgedoc.org/hd1-demo/uploads/c15d078a-bb8b-4751-9d0f-2abe486dcd52.png)
[color=#6c3483]

* **Debian 12**

Ici la partie importante durant l'installation est la partie stockage. Sur ce serveur il faut une installation standard avec LVM pour mettre en place un RAID1 par la suite : 

> C'est à partir de cette étape qu'on choisit de partitionner les disques avec LVM.
![](https://s3.hedgedoc.org/hd1-demo/uploads/76b692a8-2e1c-4cc7-ad2a-0da7fd809874.png)
[color=#6c3483]

> Il faut choisir le premier disque à 34 GB.
![](https://s3.hedgedoc.org/hd1-demo/uploads/4e159e29-5e3f-437d-b330-8d267a61a59a.png)
[color=#6c3483]

>Comme il s'agit d'une installation classique avec LVM on choisit de tout mettre dans une seule partition.
![](https://s3.hedgedoc.org/hd1-demo/uploads/f5c5c1cb-7d8d-4ffc-95ad-4fd63991836d.png)
[color=#6c3483]

## Configuration des machines

### R1

--> Connexion à R1 en SSH

Le **SSH** est une connexion **sécurisée** qui fonctionne par paire de clés **rsa** ou **ed25519** (qui sont des algorithmes de chiffrement). .

La première étape est de configurer une redirection de port sur Virtualbox puisqu'on se situe sur un réseau **NAT** et qu'on veut faire communiquer la machine hôte et la machine virtuelle.

> On se rend sur VirtualBox dans les Outils puis Réseau.
![](https://s3.hedgedoc.org/hd1-demo/uploads/662f7266-b976-4f79-970c-3b8dfd7eff15.png)
[color=#6c3483]

> Puisque la redirection de port se fait par rapport au NAT, on se rend dans l'onglet NAT Networks.
![](https://s3.hedgedoc.org/hd1-demo/uploads/e75d95f4-733f-4e18-8f4a-f73b01a91e03.png)
[color=#6c3483]

> Puis Redirection de ports, on ajoute une nouvelle règle.
![](https://s3.hedgedoc.org/hd1-demo/uploads/a7842b8d-2273-45de-a892-4b8a72759f3f.png)
[color=#6c3483]

> Elle doit être configurée comme suit : 
![](https://s3.hedgedoc.org/hd1-demo/uploads/9914d658-0357-46a6-a035-501a77da8741.png)
[color=#6c3483]

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

:::info
**DHCP** (Dynamic Host Configuration Protocol) est un protocole qui assure une configuration d'IP automatique. Il peut attribuer une adresse IP, un masque de sous réseau, peut configurer l'adresse passerelle par défaut et des serveurs de noms.
On en a besoin pour que notre routeur puisse attribuer une configuration aux nouvelles machines ajoutées sur le réseau, notamment les machines clientes.
:::

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
![](https://s3.hedgedoc.org/hd1-demo/uploads/6f88c906-d4ca-498d-bb62-96f375eeda8d.png)
[color=#6c3483]

Il est important de vérifier si la syntaxe est correcte avec la commande : 

```
sudo dhcpd -t
```

> Résultat de la commande si tout est correct.
![](https://s3.hedgedoc.org/hd1-demo/uploads/b6bcf1e1-6818-416d-a924-bd61ad636070.png)
[color=#6c3483]

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
![](https://s3.hedgedoc.org/hd1-demo/uploads/ad0990c3-cf68-438c-86d7-10622e2b30b5.png)
[color=#6c3483]

``` console
sudo ip link set enp0s8 up
ip addr show enp0s8
```
> On peut voir la configuration de l'interface enp0s8
![](https://s3.hedgedoc.org/hd1-demo/uploads/4b6393c2-94a3-4e33-824e-02665a8f438a.png)
[color=#6c3483]

### DC1
* Renommage de la machine et configuration de l'ip

> On peut voir sur l'interface du gestionnaire de serveur que le nom de l'ordinateur est à rallonge et qu'il serait plus simple de le renommer
> Il suffit de cliquer sur "WIN-KVMFUR312LR".
![](https://s3.hedgedoc.org/hd1-demo/uploads/ff08a2f3-470a-4b16-a1dc-c3ec3651d1b6.png)
[color=#6c3483]

> Cette fenêtre s'ouvre, on accède à l'étape suivante en passant par le bouton "Modifier".
![](https://s3.hedgedoc.org/hd1-demo/uploads/6f24eed3-f7b7-43a6-8ead-7ed006b41b8d.png)
[color=#6c3483]

> On choisit de l'appeler DC1, les modifications seront appliquées au démarrage.
![](https://s3.hedgedoc.org/hd1-demo/uploads/ef1afbc0-2857-41ce-8173-4ac20992b9f7.png)
[color=#6c3483]

> On peut constater que le renommage à bien fonctionné.
![](https://s3.hedgedoc.org/hd1-demo/uploads/643012ff-864f-489a-b8f0-4e3bbb8f527b.png)
[color=#6c3483]

:::info
Nous pouvons maintenant passer à l'étape de configuration de l'IP. Il est important de toujours attribuer une IP statique à un serveur car on doit toujours pouvoir y accéder par son IP. On ne souhaite donc pas qu'elle change.
:::

La première chose à faire est de voir la configuration ip avec la commande : 
``` console
ipconfig
```
Et lister les cartes réseau avec : 
``` console
Get-NetIPConfiguration
```

![](https://s3.hedgedoc.org/hd1-demo/uploads/9170a1c2-2862-4e0c-8017-8f28294d375f.png)

On définit l'IP statique qui est *192.168.100.250* ainsi que la passerelle par défaut *192.168.100.254* : 

``` console
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.100.250 -PrefixLenght 24 -DefaultGateway 192.168.100.254
```
> On peut vérifier de nouveau la configuration avec *ipconfig*.
![](https://s3.hedgedoc.org/hd1-demo/uploads/4e76c894-c5a1-458b-be4c-e3abe4af23a7.png)
[color=#6c3483]

On peut aussi désactiver l'IPV6, dans notre cas nous n'utiliserons que de l'IPV4 : 

``` console
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6
```

* Mise en place de l'AD

 Ici nous allons voir comment mettre en place l'ADDS (Active Directory Domain Services). Active Directory est un annuaire permettant de répertorier tous les utilisateurs présents sur un domaine, les différentes machines et périphériques ainsi que de les organiser dans des OU (Organisational Units), comme nous allons le voir ci-après.
 
Lorsque Windows Server à redémarré, on peut se connecter avec le compte administrateur définit durant l'installation et accéder au gestionnaire de serveur.

> Aller dans "Ajouter des rôles et fonctionnalités" puis suivre le reste des étapes.
![](https://s3.hedgedoc.org/hd1-demo/uploads/da653a61-2813-4dcb-943f-7d6cfd8b6cfe.png)
[color=#6c3483]

![](https://s3.hedgedoc.org/hd1-demo/uploads/cb036de6-8641-4896-9ef5-029b2c1e8b95.png)

![](https://s3.hedgedoc.org/hd1-demo/uploads/0fc8fd45-d456-431b-854f-f09e7c8d33ff.png)

> Il ne reste plus qu'à installer l'ADDS.
> Si l'on veut que la machine redémarre automatiquement ci-besoin on peut cocher la case correspondante.
![](https://s3.hedgedoc.org/hd1-demo/uploads/9dfd928e-491c-4132-93a3-9fe36300d582.png)
[color=#6c3483]

:::warning
Après l'installation on constate qu'il y a encore une action à faire. En effet, un serveur ne peut pas avoir un Active Directory installé sans être un contrôleur de domaine. L'action demandée par le gestionnaire de serveur est donc de promouvoir DC1 en tant que Contrôleur de domaine. Mais avant, on doit encore installer le rôle de serveur DNS.
:::

:::info
Le **DNS** (Domain Name System) est un système qui permet de traduire les noms de domaine (exemple : google.com) en adresses IPs lisibles par les machines. Il existe aussi le DNS inversé qui traduit les IPs en noms de domaines. On en a besoin puisque notre serveur se trouve sur un domaine qui possède donc un nom de domaine qu'il faut pouvoir interpréter.
:::
Comme précédemment on ajoute une nouvelle fonctionnalité, on suit l'assistant et on trouve le rôle DNS : 

![](https://s3.hedgedoc.org/hd1-demo/uploads/2594a76e-0e65-42d5-b3d1-e2ebc8b44df8.png)

Une fois le rôle installé, on va pouvoir promouvoir DC1 sans problème.

> Passer par "Promouvoir ce serveur en contrôleur de domaine"
![](https://s3.hedgedoc.org/hd1-demo/uploads/9b649dbc-6ed0-4b15-8c99-f56aba4560ab.png)
[color=#6c3483]

![](https://s3.hedgedoc.org/hd1-demo/uploads/aed00193-ea03-4a03-b7fd-bc6bef541c42.png)

![](https://s3.hedgedoc.org/hd1-demo/uploads/253736b3-cc1c-4f14-b3b0-7ed93a75e942.png)

![](https://s3.hedgedoc.org/hd1-demo/uploads/4f3f4455-78c7-4142-99d0-f433e555b252.png)

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

:::info
A l'aide de ces commandes, nous avons crée les OU : **Safeguard, Computers, Clients, Servers et Users**.
:::

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

:::info
Nous venons donc de créer les groupes globaux : **Direction, Compta et IT**.
:::

Maintenant que les groupes sont crées il reste encore à placer les utilisateurs à l'intérieur : 

``` console
Add-ADGroupMember -Identity "GG_Direction" -Members "Igauthier", "Lmercier", "Cmartin"
Add-ADGroupMember -Identity "GG_Compta" -Members "Nbernard", "Slefebvre", "Pmoreau"
Add-ADGroupMember -Identity "GG_IT" -Members "Pdubois", "JSimon"
```

**Il faut également créer des groupes locaux.**

:::warning
Avant de créer les groupes locaux, il est important de dire que nous sommes en train d'appliquer la méthode **AGDLP** (Account, Global, Domain Local, Permission). Cette méthode repose sur l'imbrication de groupes de sécurité. Le principe est de ne pas avoir de permissions reliées directement à un objet utilisateur au niveau des partages.
:::

> *source : it-connect.fr*
![](https://s3.hedgedoc.org/hd1-demo/uploads/29a1ff69-b843-4c61-932f-9b2bb4507262.png)
[color=#6c3483]

:::warning
Les **permissions** sont accordées aux **groupes locaux**. Les **groupes globaux**, créés précédemment, **feront partis** des groupes locaux. Les **utilisateurs** faisant partis des groupes globaux, par conséquent, **hériteront** des permissions des groupes locaux.
:::

Pour créer les groupes locaux : 

``` console
New-ADGroup -Name "GL_Direction_RW" -GroupScope DomainLocal -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan"
New-ADGroup -Name "GL_Compta_RW" -GroupScope DomainLocal -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan"
New-ADGroup -Name "GL_Compta_RO" -GroupScope DomainLocal -Path "OU=Users,OU=SAFEGUARD,DC=safeguard,DC=lan"
```

Nous nous occuperons du côté partage sur DC2.

### DC2

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

:::info
On ajoute DC2 comme DNS auxiliaire de DC1 pour créer plus de fiabilité. Si DC1 venait à avoir un souci de DNS alors DC2 pourrait prendre le relais. Cet incident serait non bloquant.
:::

* Services SMB et d'impression
    * SMB

:::warning
**SMB** (Server Message Block) est un protocole qui permet de partager des ressources dans un réseau local avec des machines sous Windows. Ce protocole va donc nous permettre de mettre en place un partage de fichier destinés aux différents utilisateurs du domaine. Ces partages seront soumis à différentes autorisations s'appliquant selon le rôle des différents utilisateurs (**Administrateur, Utilisateurs du domaine,** etc...) ou de leur groupe.
:::

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

Pour suivre la méthode AGDLP, il faut ajouter les groupes globaux aux groupes locaux : 

``` console
Add-ADGroupMember -Identity "GL_Direction_RW" -Members "GG_Direction"
Add-ADGroupMember -Identity "GL_Compta_RW" -Members "GG_Compta"
Add-ADGroupMember -Identity "GL_Compta_RO" -Members "GG_Compta"
```

* Création et déploiement des GPOs
    * Attribution un fond d'écran à tous les utilisateurs du domaine
    * Publication de Firefox
    * Verouillage de compte utilisateurs
    * Montage un lecteur réseau
    * Déploiement d'une imprimante TCP/IP
    * Redirection du dossier Documents
    * Activation du RDP

### PC1
* Connexion avec un utilisateur du domaine
* Vérification du fonctionnement des GPOs

### R2
* Configuration réseau

### LAMP1
* Mise en place d'un RAID1
* Création du répertoire *www*
* Installation de la stack Apache2, MariaDB et PHP-FPM
    --> Configuration Apache2
    --> Configuration MariaDB
    --> Configuration PHP-FPM
