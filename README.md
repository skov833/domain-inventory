# Inventaire passif de domaines — Python

English documentation: [README.en.md](README.en.md). English script:
[`domain_inventory_en.py`](domain_inventory_en.py).

Le script `domain_inventory.py` collecte des informations publiques et peut,
sur demande explicite, lancer un scan Nmap TCP limité. Sa configuration peut
être externalisée dans un fichier YAML.

## Prérequis

- Python 3.10 ou plus récent
- PyYAML 6.x
- accès HTTPS sortant vers `rdap.org`, `crt.sh` et `ipwho.is`
- accès HTTPS sortant vers `dns.google` pour les requêtes DNS-over-HTTPS
- accès DNS sortant

Nmap est facultatif. Il n'est requis que si l'option `--nmap` est utilisée.

### Installation sous Windows

Dans PowerShell, créez de préférence un environnement virtuel :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
```

Installez Nmap pour Windows uniquement si vous utiliserez `--nmap`, puis
vérifiez que `nmap.exe` est dans le `PATH` ou fournissez `--nmap-path`.

### Installation sous Linux/Debian

Les paquets Debian permettent d'utiliser les dépendances du système sans
installation globale avec `pip` :

```bash
sudo apt update
sudo apt install python3 python3-yaml ca-certificates
```

Ajoutez Nmap uniquement si vous utiliserez `--nmap` :

```bash
sudo apt install nmap
```

Autre possibilité, avec un environnement virtuel isolé :

```bash
sudo apt install python3 python3-venv ca-certificates
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

N'utilisez pas `sudo pip install`. Les versions récentes de Debian protègent
l'environnement Python du système ; utilisez le paquet `python3-yaml` ou un
environnement virtuel.

Références Debian : paquets officiels
[`python3-yaml`](https://packages.debian.org/stable/python/python3-yaml) et
[`nmap`](https://packages.debian.org/stable/nmap), ainsi que les
[notes de publication Debian sur les environnements Python gérés](https://www.debian.org/releases/stable/release-notes/).

Les enrichissements DNSDumpster et who.is sont optionnels et nécessitent chacun
une clé API personnelle. Le script n'effectue aucun scraping de leurs pages web.

## Utilisation

Placez un domaine par ligne dans `domaines.txt`, puis lancez :

```powershell
python .\domain_inventory.py --input .\domaines.txt --output .\resultats
```

Sous Linux/Debian :

```bash
python3 ./domain_inventory.py --input ./domaines.txt --output ./resultats
```

Le fichier possède un shebang Python 3. Si vous souhaitez l'appeler directement
sous Linux, rendez votre copie exécutable avec `chmod u+x domain_inventory.py`,
puis utilisez `./domain_inventory.py`. L'appel explicite avec `python3` fonctionne
sans modifier ses permissions.

### Configuration YAML

Copiez le modèle fourni, puis modifiez la copie locale :

```powershell
Copy-Item .\config.example.yaml .\config.yaml
python .\domain_inventory.py --config .\config.yaml --input .\domaines.txt
```

Sous Linux/Debian :

```bash
cp ./config.example.yaml ./config.yaml
chmod 600 ./config.yaml
python3 ./domain_inventory.py --config ./config.yaml --input ./domaines.txt
```

Le chemin par défaut est `config.yaml` dans le dossier courant. Ce fichier est
facultatif : si aucune copie n'existe, les valeurs intégrées au script restent
actives. Un autre chemin peut être indiqué avec `--config`.

Le YAML permet de configurer :

- le `User-Agent` HTTP ;
- l'expression régulière de validation des domaines ;
- l'expression de reconnaissance des CDN et reverse proxies ;
- les préfixes de sous-domaines classiques ;
- les sélecteurs DKIM testés par défaut ;
- les ports Nmap par défaut ;
- les clés API DNSDumpster et who.is.

Extrait minimal pour les clés :

```yaml
api_keys:
  dnsdumpster: "votre_cle_dnsdumpster"
  whois: "wis_live_votre_cle_whois"
```

`config.yaml` et `config.local.yaml` sont ignorés par Git. Ne placez jamais de
vraie clé dans `config.example.yaml`, qui est versionné. Sous Linux, appliquez
`chmod 600 config.yaml` afin que seul son propriétaire puisse lire et modifier
les clés. Sous Windows, conservez le fichier dans un profil utilisateur dont les
droits NTFS ne sont pas partagés avec d'autres comptes.

Ordre de priorité :

1. argument de ligne de commande, lorsqu'une option correspondante existe ;
2. variable d'environnement pour les clés API ;
3. valeur du fichier YAML ;
4. valeur intégrée au script.

### Activer DNSDumpster et who.is

Créez les clés dans les tableaux de bord des services, puis placez-les dans des
variables d'environnement, ou utilisez la section `api_keys` du YAML. Elles ne
seront ni enregistrées dans les CSV ni affichées par le script. Les variables
d'environnement remplacent les valeurs du YAML :

```powershell
$env:DNSDUMPSTER_API_KEY = "votre_cle_dnsdumpster"
$env:WHOIS_API_KEY = "wis_live_votre_cle_whois"
python .\domain_inventory.py --input .\domaines.txt --output .\resultats
```

Pour supprimer les clés de la session PowerShell après l'exécution :

```powershell
Remove-Item Env:DNSDUMPSTER_API_KEY
Remove-Item Env:WHOIS_API_KEY
```

Sous Bash/Linux, utilisez des variables exportées, puis supprimez-les de la
session après l'exécution :

```bash
export DNSDUMPSTER_API_KEY="votre_cle_dnsdumpster"
export WHOIS_API_KEY="wis_live_votre_cle_whois"
python3 ./domain_inventory.py --input ./domaines.txt --output ./resultats
unset DNSDUMPSTER_API_KEY WHOIS_API_KEY
```

DNSDumpster impose officiellement une requête au maximum toutes les deux
secondes. Le script applique automatiquement cette temporisation. Les quotas
quotidiens et le nombre maximal de résultats dépendent du compte. who.is applique
également les quotas et conditions du plan associé à la clé ; vérifiez que le
volume traité est compatible avec votre abonnement et ses conditions d'usage.

### Gestion du quota DNSDumpster Free User

La configuration par défaut correspond au compte communiqué :

- compte : `Free User` ;
- compteur initial du jour : `0` ;
- quota quotidien : `50` ;
- cadence maximale : une requête toutes les deux secondes.

Le script conserve le compteur dans un dossier d'état stable, indépendant du
script et des résultats :

- Windows : `%LOCALAPPDATA%\DomainInventory\dnsdumpster-usage.json` ;
- Linux/Debian : `~/.domain-inventory/dnsdumpster-usage.json`.

Ce fichier ne contient ni clé API ni domaine. Le compteur est réinitialisé automatiquement au changement
de date. Lorsqu'il atteint 50, la collecte continue
avec les autres sources, mais DNSDumpster est ignoré pour les domaines restants.
Les reprises HTTP automatiques sont désactivées pour DNSDumpster afin qu'une
erreur ne déclenche pas plusieurs requêtes susceptibles de consommer le quota.

Si des requêtes ont déjà été effectuées depuis le site ou un autre outil, indiquez
le compteur affiché dans votre compte :

```powershell
python .\domain_inventory.py `
  --input .\domaines.txt `
  --output .\resultats `
  --dnsdumpster-today-count 17
```

Sous Linux/Debian :

```bash
python3 ./domain_inventory.py --input ./domaines.txt --output ./resultats --dnsdumpster-today-count 17
```

Le script retient toujours la valeur la plus élevée entre ce paramètre et son
compteur local. Les paramètres `--dnsdumpster-daily-quota` et
`--dnsdumpster-state-file` permettent d'adapter ultérieurement le plan ou
l'emplacement du fichier d'état.

### Gestion du quota who.is Free

Le plan gratuit who.is est géré selon ses limites officielles actuelles :

- compte : `Free` ;
- 500 crédits par mois civil UTC ;
- une consultation WHOIS standard coûte un crédit ;
- cadence maximale : une requête par seconde ;
- aucun rafraîchissement `live=true`, réservé aux crédits payants.

Le compteur est conservé dans :

- Windows : `%LOCALAPPDATA%\DomainInventory\whois-usage.json` ;
- Linux/Debian : `~/.domain-inventory/whois-usage.json`.

Il se réinitialise automatiquement au changement de mois UTC. Ce fichier ne contient
ni clé API ni domaine. Une fois les 500 crédits comptabilisés, who.is est ignoré
pour les domaines restants et toutes les autres sources continuent normalement.

Les reprises HTTP automatiques sont désactivées pour who.is afin d'éviter la
consommation accidentelle de plusieurs crédits. Le suivi local est volontairement
conservateur : une tentative est comptée avant l'appel. who.is indique que les
réponses `not_found` sont remboursées, mais le script ne retranche pas ce crédit
localement et ne risque donc pas de dépasser le plafond.

Si le tableau de bord indique, par exemple, 125 crédits déjà utilisés ce mois :

```powershell
python .\domain_inventory.py `
  --input .\domaines.txt `
  --output .\resultats `
  --whois-month-count 125
```

Sous Linux/Debian :

```bash
python3 ./domain_inventory.py --input ./domaines.txt --output ./resultats --whois-month-count 125
```

Le script retient la valeur la plus élevée entre le compteur déclaré et son état
local. Les options `--whois-monthly-quota` et `--whois-state-file` permettent
d'adapter ultérieurement le plan ou l'emplacement du fichier d'état.

Après chaque réponse who.is, le script lit `X-RateLimit-Limit`,
`X-RateLimit-Remaining` et `X-Credits-Charged`, puis remplace son estimation par
le compteur réel communiqué par l'API. DNSDumpster ne documente actuellement ni
endpoint de consultation du compteur ni en-têtes de quota ; le script exploite
les en-têtes standards s'ils sont présents, sinon son fichier d'état persistant
reste la référence. Aucun scraping du tableau de bord n'est effectué.

Si le dossier d'état système est inaccessible, le script se replie sur
`.domain-inventory-state` dans le dossier courant et affiche un avertissement,
au lieu d'interrompre le traitement.

Avec 400 domaines et aucun crédit déjà consommé, les consultations WHOIS du lot
utilisent au maximum 400 des 500 crédits mensuels du plan Free.

### Choix de la source who.is

L'option `--whois-source` contrôle l'endpoint who.is utilisé :

- `whois` — valeur par défaut : `/v1/whois/{domain}`, un crédit par domaine ;
- `rdap` — `/v1/rdap/{domain}`, un crédit par domaine ;
- `both` — appelle WHOIS puis RDAP, deux crédits par domaine si le quota le permet.

Exemples :

```powershell
# Contacts WHOIS normalisés, adapté à 400 domaines sur le plan Free
python .\domain_inventory.py --input .\domaines.txt --whois-source whois

# Entités RDAP normalisées, y compris les child_entities
python .\domain_inventory.py --input .\domaines.txt --whois-source rdap

# Les deux sources, à réserver à un lot compatible avec le solde disponible
python .\domain_inventory.py --input .\domaines.txt --whois-source both
```

Sous Linux/Debian, remplacez `python .\domain_inventory.py` par
`python3 ./domain_inventory.py` ; les options sont identiques.

En mode `both`, le script vérifie le solde avant chaque endpoint : il peut donc
exécuter le WHOIS et ignorer le RDAP du même domaine si le dernier crédit
disponible a été consommé entre les deux. Le fichier `contacts-whois.csv`
distingue les lignes avec la colonne `SourceType` (`WHOIS` ou `RDAP`). Les
colonnes `Handle`, `IdentifiantPublicType` et `IdentifiantPublic` sont alimentées
par les entités RDAP who.is lorsqu'elles sont publiées.

Pour un seul domaine :

```powershell
python .\domain_inventory.py --domain acteaumeilleurprix.com --output .\resultats-test
```

```bash
python3 ./domain_inventory.py --domain acteaumeilleurprix.com --output ./resultats-test
```

Pour plusieurs domaines sans fichier, répétez l'option :

```powershell
python .\domain_inventory.py -d exemple.fr -d exemple.com -o .\resultats
```

```bash
python3 ./domain_inventory.py -d exemple.fr -d exemple.com -o ./resultats
```

Options utiles : `--workers 12`, `--delay 0.35` et `--retries 3`. Pour 400 domaines, conservez une temporisation afin de respecter les services publics.

### Remplacement ou fusion des résultats

Le comportement par défaut reste le remplacement complet des huit CSV :

```powershell
python .\domain_inventory.py --input .\domaines.txt --output .\resultats --output-mode overwrite
```

Pour conserver l'historique dans le même dossier, activez la fusion :

```powershell
python .\domain_inventory.py --input .\domaines.txt --output .\resultats --output-mode merge
```

Sous Linux/Debian, la syntaxe est identique avec
`python3 ./domain_inventory.py`.

Le mode `merge` :

- charge les CSV existants ;
- déduplique chaque type de donnée avec une clé métier stable ;
- conserve les anciennes lignes qui ne sont pas observées pendant la nouvelle
  exécution ;
- actualise les champs non vides avec la nouvelle observation ;
- ne remplace pas une ancienne valeur renseignée par une nouvelle valeur vide ;
- ne compte qu'une observation par clé et par exécution, même si la collecte
  courante contient plusieurs doublons ;
- écrit les CSV et `resume.json` par remplacement atomique.

Trois colonnes sont ajoutées à chacun des huit CSV, dans les deux modes :

- `PremiereObservation` : date UTC de la première observation ;
- `DerniereObservation` : date UTC de la dernière exécution ayant retrouvé
  l'élément ;
- `NombreObservations` : nombre d'exécutions dans lesquelles l'élément a été
  observé.

Lors de la première fusion d'un ancien CSV qui ne possède pas ces colonnes, la
date de modification du fichier est utilisée comme date historique initiale.
Cette date est donc une approximation de migration, pas une preuve de la date
réelle de première découverte.

`resume.json` représente l'état cumulé des CSV après la fusion et contient aussi
le champ `output_mode`. Il est remplacé, jamais concaténé.

### Contrôles DNS et messagerie

Pour chaque domaine, le script interroge Google Public DNS en DNS-over-HTTPS et
enregistre les résultats dans `enregistrements-dns.csv` :

- `MX` ;
- `TXT`, avec identification des politiques SPF commençant par `v=spf1` ;
- `CNAME` (le type DNS s'écrit CNAME, parfois abrégé par erreur en « CNAM ») ;
- `AAAA` ;
- DMARC sur `_dmarc.<domaine>` ;
- DKIM sur plusieurs sélecteurs courants.

Comme un sélecteur DKIM ne peut pas être découvert automatiquement par DNS, les
sélecteurs testés par défaut sont `default`, `selector1`, `selector2`, `google`,
`k1`, `s1` et `s2`. Ils peuvent être remplacés en répétant l'option :

```powershell
python .\domain_inventory.py `
  --input .\domaines.txt `
  --dkim-selector selector1 `
  --dkim-selector selector2 `
  --dkim-selector mon-selecteur `
  --output .\resultats
```

Sous Linux/Debian :

```bash
python3 ./domain_inventory.py --input ./domaines.txt --dkim-selector selector1 --dkim-selector selector2 --dkim-selector mon-selecteur --output ./resultats
```

Le script ajoute aussi systématiquement les noms suivants à la résolution DNS :
`ftp`, `mail`, `www`, `webmail`, `ns1` et `ns2`. Leur origine est marquée
`test de sous-domaine classique` dans `sous-domaines-dns.csv`.

Pour éviter les faux positifs, un nom aléatoire inexistant est aussi résolu pour
chaque domaine. S'il renvoie la même IP qu'un nom classique, la colonne
`WildcardDNSProbable` vaut `True` et le service doit être considéré comme non
confirmé tant qu'un contrôle applicatif autorisé n'a pas été effectué.

### Analyse Nmap optionnelle

Nmap est totalement désactivé par défaut. Activez-le uniquement pour des IP que
vous possédez ou que vous êtes explicitement autorisé à auditer :

```powershell
python .\domain_inventory.py `
  --input .\domaines.txt `
  --output .\resultats `
  --nmap
```

Sous Linux/Debian :

```bash
python3 ./domain_inventory.py --input ./domaines.txt --output ./resultats --nmap
```

Le profil est volontairement borné :

- scan TCP connect (`-sT`) uniquement ;
- 18 ports TCP courants : `21,22,25,53,80,110,143,443,465,587,993,995,1433,3306,3389,5432,8080,8443` ;
- cadence normale `-T3` et délai minimal de 50 ms entre sondes ;
- une seule retransmission au maximum ;
- délai maximal de 30 secondes par IP ;
- aucune détection de version (`-sV`) ;
- aucune détection d'OS (`-O`) ;
- aucun script NSE (`--script`) ;
- aucun scan UDP ;
- IP publiques uniquement par défaut ;
- 256 IP maximum par exécution.

Un scan TCP connect établit une connexion TCP normale puis la ferme sans envoyer
de requête applicative. Il reste susceptible d'être journalisé par la cible :
« non invasif » signifie ici faible périmètre et absence de techniques avancées,
pas invisibilité.

Options disponibles :

```powershell
# Liste personnalisée, toujours limitée à 100 ports explicites
--nmap --nmap-ports 22,25,80,443

# Chemin Nmap si l'exécutable n'est pas dans le PATH
--nmap --nmap-path "C:\Program Files (x86)\Nmap\nmap.exe"

# Limiter davantage le nombre de cibles
--nmap --nmap-max-ips 50

# Inclure le réseau privé uniquement si vous êtes autorisé à l'auditer
--nmap --nmap-include-private
```

Sous Linux/Debian, Nmap installé par APT est normalement trouvé automatiquement
dans `/usr/bin/nmap`. Si nécessaire :

```bash
python3 ./domain_inventory.py --input ./domaines.txt --nmap --nmap-path /usr/bin/nmap
```

Le profil `-sT` utilisé par le script repose sur les connexions TCP du système
et ne nécessite normalement pas les privilèges `root`. N'exécutez pas tout le
script avec `sudo` : cela créerait les résultats et les compteurs avec un autre
propriétaire et exposerait inutilement les clés au processus privilégié.

## Fichiers produits

- `domaines.csv` : registrar, dates, statuts, serveurs DNS, synthèse du contact administratif et du contact de facturation.
- `contacts-rdap.csv` : détail des entités RDAP publiques, y compris les rôles `administrative`, `billing`, `technical`, `registrant`, `abuse`, `registrar` ou `reseller` lorsqu'ils sont publiés. Les entités imbriquées sont également parcourues.
- `contacts-whois.csv` : contacts WHOIS normalisés renvoyés par l'API who.is, lorsque cette source est activée.
- `dnsdumpster.csv` : hôtes, IP, PTR, ASN, propriétaire réseau et pays renvoyés par DNSDumpster. Les hôtes trouvés sont fusionnés avec ceux de `crt.sh` avant résolution DNS.
- `enregistrements-dns.csv` : résultats consolidés de Google Public DNS et
  DNSDumpster pour MX, TXT/SPF, NS, CNAME, AAAA, DMARC et DKIM. Une même valeur
  vue par les deux sources n'apparaît qu'une fois et la colonne `Source` mentionne
  les deux fournisseurs.
- `nmap.csv` : état des ports TCP testés lorsque `--nmap` est activé. Le fichier
  contient uniquement l'état, la raison et un nom de service indicatif issu de la
  table Nmap ; aucune détection de version n'est effectuée.
- `sous-domaines-dns.csv` : noms vus dans les journaux de certificats, enregistrements A/AAAA et statut de résolution.
- `adresses-ip.csv` : ASN, opérateur réseau, organisation, pays, attribution probable et indicateur de CDN/proxy.
- `resume.json` : volume traité, date d'exécution et limites méthodologiques.

Les CSV sont encodés en UTF-8 avec BOM et utilisent le point-virgule, pour une ouverture simple dans Excel en environnement français.

## Générer un rapport HTML complet

Le script annexe `generate_report.py` transforme un dossier de résultats
existant en un rapport HTML autonome. Il n'effectue aucun appel réseau et ne
modifie pas les CSV ou le JSON source.

Sous Windows :

```powershell
python .\generate_report.py `
  --input-dir .\resultats `
  --output .\resultats\rapport.html `
  --language fr
```

Sous Linux/Debian :

```bash
python3 ./generate_report.py \
  --input-dir ./resultats \
  --output ./resultats/rapport.html \
  --language fr
```

Si `--output` est omis, le fichier est créé sous
`<input-dir>/report.html`. Les langues disponibles sont `fr` et `en`.

Le rapport contient :

- une synthèse chiffrée de l'exécution ;
- l'état de présence de chaque fichier attendu ;
- tous les champs de `resume.json` ;
- l'intégralité des lignes de chacun des huit CSV ;
- le nombre de ports Nmap ouverts observés ;
- les limites méthodologiques et les avertissements d'attribution.

Le HTML contient son propre style, fonctionne hors ligne et propose une mise en
page d'impression. Les valeurs des CSV et du JSON sont échappées avant leur
insertion dans le document. Un fichier absent est signalé dans le rapport sans
empêcher la génération des autres sections.

## Confidentialité et limites

La liste des domaines et les noms découverts sont transmis aux services activés.
Sans clés optionnelles, il s'agit de `rdap.org`, `crt.sh`, `dns.google` et
`ipwho.is`. Avec les
enrichissements, les domaines sont aussi transmis à DNSDumpster et/ou who.is.
Pour une confidentialité totale, il faut remplacer ces sources par des services
internes ou des miroirs maîtrisés.

Les contacts RDAP peuvent être masqués en raison du RGPD ou de la politique du registre. Dans ce cas, les colonnes de synthèse indiquent `Non publié par le service RDAP` : le script ne tente pas de contourner cette restriction. Les journaux de transparence des certificats ne donnent pas un inventaire exhaustif. Une IP peut appartenir à un CDN, un reverse proxy ou une plateforme cloud : `HebergeurProbable` décrit donc l'opérateur apparent de l'IP, pas nécessairement l'infrastructure d'origine.
