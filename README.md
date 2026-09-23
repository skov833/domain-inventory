# Inventaire passif de domaines — Python

Le script `domain_inventory.py` utilise uniquement la bibliothèque standard de Python. Il collecte des informations publiques sans scan de ports, brute force DNS ni connexion aux services découverts.

## Prérequis

- Python 3.10 ou plus récent
- accès HTTPS sortant vers `rdap.org`, `crt.sh` et `ipwho.is`
- accès DNS sortant

Les enrichissements DNSDumpster et who.is sont optionnels et nécessitent chacun
une clé API personnelle. Le script n'effectue aucun scraping de leurs pages web.

## Utilisation

Placez un domaine par ligne dans `domaines.txt`, puis lancez :

```powershell
python .\domain_inventory.py --input .\domaines.txt --output .\resultats
```

### Activer DNSDumpster et who.is

Créez les clés dans les tableaux de bord des services, puis placez-les dans des
variables d'environnement. Elles ne seront ni enregistrées dans les CSV ni
affichées par le script :

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

Le script conserve le compteur dans `.dnsdumpster-usage.json`, à côté du script.
Ce fichier ne contient ni clé API ni domaine. Le compteur est réinitialisé
automatiquement au changement de date. Lorsqu'il atteint 50, la collecte continue
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

Le compteur est conservé dans `.whois-usage.json`, à côté du script, et se
réinitialise automatiquement au changement de mois UTC. Ce fichier ne contient
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

Le script retient la valeur la plus élevée entre le compteur déclaré et son état
local. Les options `--whois-monthly-quota` et `--whois-state-file` permettent
d'adapter ultérieurement le plan ou l'emplacement du fichier d'état.

Avec 400 domaines et aucun crédit déjà consommé, les consultations WHOIS du lot
utilisent au maximum 400 des 500 crédits mensuels du plan Free.

Pour un seul domaine :

```powershell
python .\domain_inventory.py --domain acteaumeilleurprix.com --output .\resultats-test
```

Pour plusieurs domaines sans fichier, répétez l'option :

```powershell
python .\domain_inventory.py -d exemple.fr -d exemple.com -o .\resultats
```

Options utiles : `--workers 12`, `--delay 0.35` et `--retries 3`. Pour 400 domaines, conservez une temporisation afin de respecter les services publics.

## Fichiers produits

- `domaines.csv` : registrar, dates, statuts, serveurs DNS, synthèse du contact administratif et du contact de facturation.
- `contacts-rdap.csv` : détail des entités RDAP publiques, y compris les rôles `administrative`, `billing`, `technical`, `registrant`, `abuse`, `registrar` ou `reseller` lorsqu'ils sont publiés. Les entités imbriquées sont également parcourues.
- `contacts-whois.csv` : contacts WHOIS normalisés renvoyés par l'API who.is, lorsque cette source est activée.
- `dnsdumpster.csv` : hôtes, IP, PTR, ASN, propriétaire réseau et pays renvoyés par DNSDumpster. Les hôtes trouvés sont fusionnés avec ceux de `crt.sh` avant résolution DNS.
- `sous-domaines-dns.csv` : noms vus dans les journaux de certificats, enregistrements A/AAAA et statut de résolution.
- `adresses-ip.csv` : ASN, opérateur réseau, organisation, pays, attribution probable et indicateur de CDN/proxy.
- `resume.json` : volume traité, date d'exécution et limites méthodologiques.

Les CSV sont encodés en UTF-8 avec BOM et utilisent le point-virgule, pour une ouverture simple dans Excel en environnement français.

## Confidentialité et limites

La liste des domaines et les noms découverts sont transmis aux services activés.
Sans clés optionnelles, il s'agit de `rdap.org`, `crt.sh` et `ipwho.is`. Avec les
enrichissements, les domaines sont aussi transmis à DNSDumpster et/ou who.is.
Pour une confidentialité totale, il faut remplacer ces sources par des services
internes ou des miroirs maîtrisés.

Les contacts RDAP peuvent être masqués en raison du RGPD ou de la politique du registre. Dans ce cas, les colonnes de synthèse indiquent `Non publié par le service RDAP` : le script ne tente pas de contourner cette restriction. Les journaux de transparence des certificats ne donnent pas un inventaire exhaustif. Une IP peut appartenir à un CDN, un reverse proxy ou une plateforme cloud : `HebergeurProbable` décrit donc l'opérateur apparent de l'IP, pas nécessairement l'infrastructure d'origine.
