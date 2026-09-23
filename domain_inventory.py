#!/usr/bin/env python3
"""Inventaire passif de domaines à partir de sources publiques.

Le programme prend un ou plusieurs domaines en entrée et exécute quatre étapes :

1. interrogation RDAP du domaine (registrar, dates, statuts et contacts publics) ;
2. recherche de noms dans les journaux Certificate Transparency de ``crt.sh`` ;
3. résolution DNS A/AAAA des noms trouvés ;
4. attribution des IP à un ASN et à un opérateur apparent.

Les résultats sont écrits dans huit CSV et un résumé JSON. Le script utilise
PyYAML pour sa configuration. Il n'effectue aucun brute force DNS. Un scan Nmap
TCP borné peut être activé explicitement avec ``--nmap`` ; il reste désactivé
par défaut.

Attention : les requêtes transmettent les domaines recherchés à ``rdap.org`` et
``crt.sh``, et les IP à ``rdap.org`` et ``ipwho.is``. Les contacts absents d'une
réponse RDAP ne peuvent pas être reconstitués par ce programme.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # Le message explicite est produit seulement si un YAML est utilisé.
    yaml = None


USER_AGENT = "DomainInventory/1.0 (passive asset inventory)"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$"
)
CDN_RE = re.compile(
    r"cloudflare|akamai|fastly|cloudfront|amazon.*front|imperva|sucuri|"
    r"bunny|stackpath|edgecast|cdn77",
    re.IGNORECASE,
)
COMMON_SUBDOMAIN_PREFIXES = ("ftp", "mail", "www", "webmail", "ns1", "ns2")
DEFAULT_DKIM_SELECTORS = ("default", "selector1", "selector2", "google", "k1", "s1", "s2")
DEFAULT_NMAP_PORTS = (
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 3306, 3389, 5432, 8080, 8443,
)


def default_state_directory() -> Path:
    """Retourne un dossier d'état stable, indépendant du chemin du script."""
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "DomainInventory"
    return Path.home() / ".domain-inventory"


def prepare_state_file(preferred: Path, fallback_name: str) -> Path:
    """Valide le dossier d'état ou choisit un repli local accessible.

    Le chemin de repli est ``.domain-inventory-state`` dans le dossier courant.
    Il est utilisé uniquement lorsque le dossier préféré ne peut pas être créé.
    """
    try:
        preferred.parent.mkdir(parents=True, exist_ok=True)
        return preferred
    except OSError as exc:
        fallback = Path.cwd() / ".domain-inventory-state" / fallback_name
        fallback.parent.mkdir(parents=True, exist_ok=True)
        print(
            f"AVERTISSEMENT: dossier d'état principal inaccessible ({exc}); "
            f"repli vers {fallback}",
            file=sys.stderr,
        )
        return fallback


def normalize_domain(value: str) -> str | None:
    """Nettoie et valide un nom de domaine.

    Accepte également une URL simple ou un nom générique de certificat tel que
    ``*.example.com``. Les noms internationalisés sont convertis en IDNA.

    Args:
        value: Valeur brute provenant de la ligne de commande, d'un fichier ou
            d'un journal de certificats.

    Returns:
        Le domaine ASCII normalisé, ou ``None`` si la valeur est invalide.
    """
    candidate = value.strip().lower()
    candidate = re.sub(r"^https?://", "", candidate)
    candidate = candidate.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return candidate if DOMAIN_RE.fullmatch(candidate) else None


def http_json_response(
    url: str,
    retries: int,
    delay: float,
    service: str,
    extra_headers: dict[str, str] | None = None,
) -> tuple[Any | None, dict[str, str], int | None]:
    """Télécharge du JSON et conserve les en-têtes utiles au suivi de quota.

    Les erreurs réseau sont non bloquantes : après la dernière tentative, la
    fonction écrit un avertissement et renvoie ``None``. Cela permet à un lot de
    400 domaines de continuer même si une source publique échoue ponctuellement.

    Args:
        url: URL HTTPS à interroger.
        retries: Nombre maximal de tentatives.
        delay: Temporisation de base en secondes entre les tentatives.
        service: Nom lisible de la source, utilisé dans les avertissements.
        extra_headers: En-têtes supplémentaires, notamment pour l'authentification
            des API optionnelles. Ils ne sont jamais écrits dans les résultats.

    Returns:
        ``(document JSON, en-têtes en minuscules, statut HTTP)``. Le document
        vaut ``None`` après un échec définitif.
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    headers.update(extra_headers or {})
    request = urllib.request.Request(
        url, headers=headers
    )
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                return json.load(response), response_headers, response.status
        except urllib.error.HTTPError as exc:
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
            if attempt == retries:
                print(f"AVERTISSEMENT: {service} inaccessible: {exc}", file=sys.stderr)
                return None, response_headers, exc.code
            time.sleep(max(0.5, delay * attempt))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == retries:
                print(f"AVERTISSEMENT: {service} inaccessible: {exc}", file=sys.stderr)
                return None, {}, None
            time.sleep(max(0.5, delay * attempt))
    return None, {}, None


def http_json(
    url: str,
    retries: int,
    delay: float,
    service: str,
    extra_headers: dict[str, str] | None = None,
) -> Any | None:
    """Version simplifiée de :func:`http_json_response` ne renvoyant que le JSON."""
    data, _, _ = http_json_response(
        url, retries, delay, service, extra_headers
    )
    return data


def rate_limit_from_headers(headers: dict[str, str]) -> dict[str, int]:
    """Extrait les compteurs normalisés des en-têtes de limitation courants."""
    result: dict[str, int] = {}
    mapping = {
        "x-ratelimit-limit": "limit",
        "x-ratelimit-remaining": "remaining",
        "x-credits-charged": "charged",
    }
    for header, field in mapping.items():
        try:
            result[field] = int(headers[header])
        except (KeyError, TypeError, ValueError):
            pass
    return result


def vcard_values(entity: dict[str, Any], prop: str) -> list[str]:
    """Extrait toutes les valeurs d'une propriété jCard d'une entité RDAP.

    RDAP représente les coordonnées au format jCard dans ``vcardArray``. Cette
    fonction gère les valeurs simples et les listes, puis déduplique le résultat.
    """
    vcard = entity.get("vcardArray") or []
    if len(vcard) < 2 or not isinstance(vcard[1], list):
        return []
    values: list[str] = []
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == prop:
            value = item[3]
            if isinstance(value, list):
                values.extend(str(part) for part in value if part)
            elif value:
                values.append(str(value))
    return sorted(set(values))


def walk_rdap_entities(entities: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """Parcourt récursivement les entités RDAP et leurs sous-entités.

    Certains registres placent par exemple le contact ``abuse`` sous l'entité du
    registrar. Un parcours limité au premier niveau perdrait ces informations.
    """
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        yield entity
        yield from walk_rdap_entities(entity.get("entities") or [])


def vcard_address(entity: dict[str, Any]) -> str:
    """Formate les adresses postales jCard publiques d'une entité RDAP."""
    vcard = entity.get("vcardArray") or []
    if len(vcard) < 2 or not isinstance(vcard[1], list):
        return ""
    addresses: list[str] = []
    for item in vcard[1]:
        if not (isinstance(item, list) and len(item) >= 4 and item[0] == "adr"):
            continue
        value = item[3]
        if isinstance(value, list):
            formatted = ", ".join(str(part).strip() for part in value if str(part).strip())
        else:
            formatted = str(value).strip()
        if formatted:
            addresses.append(formatted)
    return " | ".join(dict.fromkeys(addresses))


def rdap_entity_row(domain: str, entity: dict[str, Any]) -> dict[str, Any]:
    """Convertit une entité RDAP en ligne prête pour ``contacts-rdap.csv``."""
    roles = sorted(set(str(role).lower() for role in (entity.get("roles") or [])))
    return {
        "Domaine": domain,
        "Roles": ", ".join(roles) or "non précisé",
        "Handle": entity.get("handle") or "",
        "Nom": ", ".join(vcard_values(entity, "fn")),
        "Organisation": ", ".join(vcard_values(entity, "org")),
        "Emails": ", ".join(vcard_values(entity, "email")),
        "Telephones": ", ".join(vcard_values(entity, "tel")),
        "Adresse": vcard_address(entity),
        "Statuts": ", ".join(sorted(entity.get("status") or [])),
        "Port43": entity.get("port43") or "",
        "LienRdap": next(
            (
                link.get("href", "")
                for link in (entity.get("links") or [])
                if isinstance(link, dict) and link.get("href")
            ),
            "",
        ),
    }


def rdap_role_summary(rdap: dict[str, Any] | None, role: str) -> str:
    """Construit une synthèse lisible des entités portant un rôle donné.

    Args:
        rdap: Réponse RDAP complète du domaine, ou ``None`` en cas d'échec.
        role: Rôle RDAP recherché, par exemple ``administrative`` ou ``billing``.

    Returns:
        Les coordonnées publiques concaténées, une indication de masquage, ou
        une indication d'indisponibilité de la source RDAP.
    """
    if not rdap:
        return "RDAP indisponible"
    matches: list[str] = []
    for entity in walk_rdap_entities(rdap.get("entities") or []):
        roles = {str(item).lower() for item in (entity.get("roles") or [])}
        if role.lower() not in roles:
            continue
        row = rdap_entity_row("", entity)
        details = [
            row["Nom"], row["Organisation"], row["Emails"], row["Telephones"],
            row["Adresse"], f"handle={row['Handle']}" if row["Handle"] else "",
        ]
        published = [str(value) for value in details if value]
        matches.append(" | ".join(published) if published else "Rôle présent, détails masqués")
    return " ; ".join(dict.fromkeys(matches)) if matches else "Non publié par le service RDAP"


def rdap_contacts(rdap: dict[str, Any] | None) -> str:
    """Produit une synthèse de tous les contacts RDAP publiquement visibles."""
    if not rdap:
        return ""
    contacts: list[str] = []
    for entity in walk_rdap_entities(rdap.get("entities") or []):
        roles = ",".join(entity.get("roles") or []) or "non précisé"
        details: list[str] = []
        for field in ("fn", "org", "email", "tel"):
            details.extend(vcard_values(entity, field))
        if details:
            contacts.append(f"{roles}: {' | '.join(dict.fromkeys(details))}")
        elif entity.get("handle"):
            contacts.append(f"{roles}: handle={entity['handle']}")
    return " ; ".join(dict.fromkeys(contacts))


def rdap_event(rdap: dict[str, Any] | None, actions: Iterable[str]) -> str:
    """Renvoie la date du premier événement correspondant aux actions fournies."""
    if not rdap:
        return ""
    events = rdap.get("events") or []
    for action in actions:
        for event in events:
            if event.get("eventAction") == action:
                return str(event.get("eventDate") or "")
    return ""


def registrar_name(rdap: dict[str, Any] | None) -> str:
    """Extrait le nom public du registrar, avec repli sur son handle RDAP."""
    if not rdap:
        return ""
    for entity in rdap.get("entities") or []:
        if "registrar" in (entity.get("roles") or []):
            names = vcard_values(entity, "fn") or vcard_values(entity, "org")
            return names[0] if names else str(entity.get("handle") or "")
    return ""


def certificate_names(domain: str, retries: int, delay: float) -> list[str]:
    """Recherche les noms d'un domaine dans les journaux de certificats.

    Le domaine racine est toujours présent dans le résultat, même si ``crt.sh``
    est indisponible. Les jokers sont retirés et seuls les descendants réels du
    domaine demandé sont conservés.
    """
    query = urllib.parse.quote(f"%.{domain}")
    records = http_json(
        f"https://crt.sh/?q={query}&output=json", retries, delay, "crt.sh"
    )
    names = {domain}
    for record in records or []:
        for raw_name in str(record.get("name_value") or "").splitlines():
            name = normalize_domain(raw_name)
            if name and (name == domain or name.endswith(f".{domain}")):
                names.add(name)
    return sorted(names)


def dns_over_https(
    name: str, record_type: str, retries: int, delay: float
) -> tuple[int | None, list[dict[str, Any]]]:
    """Interroge Google Public DNS via son API JSON DNS-over-HTTPS.

    Args:
        name: Nom DNS à interroger, déjà normalisé.
        record_type: Type canonique tel que ``MX``, ``TXT``, ``CNAME`` ou ``AAAA``.
        retries: Nombre de tentatives HTTP.
        delay: Temporisation de base entre les tentatives.

    Returns:
        Un couple ``(code DNS, réponses)``. Le code ``0`` signifie NOERROR,
        ``3`` NXDOMAIN et ``None`` une indisponibilité HTTP/JSON.
    """
    query = urllib.parse.urlencode(
        {
            "name": name,
            "type": record_type,
            # Empêche l'envoi d'une partie de l'IP cliente aux serveurs faisant
            # autorité par le mécanisme EDNS Client Subnet.
            "edns_client_subnet": "0.0.0.0/0",
        }
    )
    data = http_json(
        f"https://dns.google/resolve?{query}", retries, delay, "Google Public DNS"
    )
    if not isinstance(data, dict):
        return None, []
    answers = [item for item in (data.get("Answer") or []) if isinstance(item, dict)]
    return data.get("Status"), answers


def collect_domain_dns_records(
    domain: str,
    dkim_selectors: Iterable[str],
    retries: int,
    delay: float,
    workers: int,
) -> list[dict[str, Any]]:
    """Collecte les enregistrements DNS et contrôles de messagerie d'un domaine.

    Les sélecteurs DKIM ne peuvent pas être découverts de façon générique par
    DNS. Le script teste donc une liste configurable de sélecteurs fréquents.
    Chaque interrogation, y compris une absence de réponse, produit au moins une
    ligne afin que le contrôle soit auditable.
    """
    checks: list[tuple[str, str, str]] = [
        (domain, "MX", "MX"),
        (domain, "TXT", "TXT/SPF"),
        (domain, "CNAME", "CNAME"),
        (domain, "AAAA", "AAAA"),
        (f"_dmarc.{domain}", "TXT", "DMARC"),
    ]
    checks.extend(
        (f"{selector}._domainkey.{domain}", "TXT", "DKIM")
        for selector in dkim_selectors
    )

    results: list[dict[str, Any]] = []

    def run_check(check: tuple[str, str, str]) -> list[dict[str, Any]]:
        query_name, record_type, category = check
        status, answers = dns_over_https(query_name, record_type, retries, delay)
        rows: list[dict[str, Any]] = []
        matching_answers = [
            answer for answer in answers if int(answer.get("type", -1)) in {
                "MX": 15, "TXT": 16, "CNAME": 5, "AAAA": 28
            }.values()
        ]
        for answer in matching_answers:
            value = str(answer.get("data") or "")
            logical_category = category
            if category == "TXT/SPF":
                logical_category = "SPF" if value.strip('"').lower().startswith("v=spf1") else "TXT"
            elif category == "DMARC" and not value.strip('"').lower().startswith("v=dmarc1"):
                logical_category = "TXT (_dmarc, non DMARC)"
            elif category == "DKIM" and "v=dkim1" not in value.lower():
                logical_category = "TXT (_domainkey, non DKIM)"
            rows.append(
                {
                    "Domaine": domain,
                    "NomInterroge": query_name,
                    "TypeDNS": record_type,
                    "Categorie": logical_category,
                    "Valeur": value,
                    "TTL": answer.get("TTL") or "",
                    "CodeDNS": status if status is not None else "",
                    "Statut": "Présent",
                    "Source": "Google Public DNS over HTTPS",
                }
            )
        if not rows:
            rows.append(
                {
                    "Domaine": domain,
                    "NomInterroge": query_name,
                    "TypeDNS": record_type,
                    "Categorie": category,
                    "Valeur": "",
                    "TTL": "",
                    "CodeDNS": status if status is not None else "",
                    "Statut": "Absent" if status is not None else "Indisponible",
                    "Source": "Google Public DNS over HTTPS",
                }
            )
        return rows

    with ThreadPoolExecutor(max_workers=min(max(1, workers), len(checks), 8)) as pool:
        futures = [pool.submit(run_check, check) for check in checks]
        for future in as_completed(futures):
            results.extend(future.result())
    return sorted(results, key=lambda row: (row["NomInterroge"], row["TypeDNS"], row["Valeur"]))


def whois_contact_summary(contact: Any) -> str:
    """Formate un contact issu de l'API who.is sans supposer tous les champs.

    L'API renvoie des contacts déjà normalisés, mais le nombre de champs varie
    selon le registre et le niveau de masquage. Les dictionnaires et listes
    imbriqués sont donc aplatis prudemment.
    """
    if not isinstance(contact, dict) or not contact:
        return "Non publié par who.is"
    preferred = (
        "name", "organization", "email", "phone", "fax", "street",
        "city", "state_province", "postal_code", "country",
    )
    values: list[str] = []
    for key in preferred:
        value = contact.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value if item)
        elif value:
            values.append(str(value))
    return " | ".join(dict.fromkeys(values)) or "Détails masqués par who.is"


def get_whois_enrichment(
    domain: str, api_key: str, retries: int, delay: float
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Interroge l'API WHOIS officielle de who.is.

    Returns:
        Un couple contenant la réponse brute normalisée et les lignes de
        contacts destinées à ``contacts-whois.csv``.
    """
    url = f"https://api.who.is/v1/whois/{urllib.parse.quote(domain)}"
    data, headers, _ = http_json_response(
        url,
        retries,
        delay,
        "who.is",
        {"Authorization": f"Bearer {api_key}"},
    )
    data = data or {}
    rows: list[dict[str, Any]] = []
    contacts = data.get("contacts") or {}
    if isinstance(contacts, dict):
        for role, contact_or_contacts in contacts.items():
            items = contact_or_contacts if isinstance(contact_or_contacts, list) else [contact_or_contacts]
            for contact in items:
                contact = contact if isinstance(contact, dict) else {}
                rows.append(
                    {
                        "Domaine": domain,
                        "SourceType": "WHOIS",
                        "Role": role,
                        "Nom": contact.get("name") or "",
                        "Organisation": contact.get("organization") or "",
                        "Email": contact.get("email") or "",
                        "Telephone": contact.get("phone") or "",
                        "Fax": contact.get("fax") or "",
                        "Rue": " | ".join(contact.get("street") or [])
                        if isinstance(contact.get("street"), list)
                        else contact.get("street") or "",
                        "Ville": contact.get("city") or "",
                        "Region": contact.get("state_province") or "",
                        "CodePostal": contact.get("postal_code") or "",
                        "Pays": contact.get("country") or "",
                        "Source": url,
                    }
                )
    return data, rows, rate_limit_from_headers(headers)


def walk_whois_rdap_entities(
    entities: Iterable[dict[str, Any]],
) -> Iterable[dict[str, Any]]:
    """Parcourt les entités RDAP normalisées de who.is et leurs enfants."""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        yield entity
        yield from walk_whois_rdap_entities(entity.get("child_entities") or [])


def whois_rdap_entity_summary(entity: dict[str, Any]) -> str:
    """Formate les coordonnées publiques d'une entité RDAP normalisée who.is."""
    values = [
        entity.get("fn"),
        entity.get("org"),
        entity.get("email"),
        entity.get("tel"),
        entity.get("country_code"),
        f"handle={entity['handle']}" if entity.get("handle") else "",
    ]
    return " | ".join(dict.fromkeys(str(value) for value in values if value))


def whois_rdap_role_summary(
    data: dict[str, Any], aliases: Iterable[str]
) -> str:
    """Synthétise les entités RDAP who.is correspondant à un rôle."""
    expected = {alias.lower() for alias in aliases}
    summaries: list[str] = []
    for entity in walk_whois_rdap_entities(data.get("entities") or []):
        roles = {str(role).lower() for role in (entity.get("roles") or [])}
        if roles.intersection(expected):
            summaries.append(
                whois_rdap_entity_summary(entity) or "Rôle présent, détails masqués"
            )
    return " ; ".join(dict.fromkeys(summaries)) if summaries else "Non publié par who.is RDAP"


def get_whois_rdap_enrichment(
    domain: str, api_key: str, retries: int, delay: float
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Interroge l'endpoint RDAP normalisé de who.is et extrait ses entités."""
    url = f"https://api.who.is/v1/rdap/{urllib.parse.quote(domain)}"
    data, headers, _ = http_json_response(
        url,
        retries,
        delay,
        "who.is RDAP",
        {"Authorization": f"Bearer {api_key}"},
    )
    data = data or {}
    rows: list[dict[str, Any]] = []
    for entity in walk_whois_rdap_entities(data.get("entities") or []):
        roles = ", ".join(sorted(entity.get("roles") or [])) or "non précisé"
        rows.append(
            {
                "Domaine": domain,
                "SourceType": "RDAP",
                "Role": roles,
                "Nom": entity.get("fn") or "",
                "Organisation": entity.get("org") or "",
                "Email": entity.get("email") or "",
                "Telephone": entity.get("tel") or "",
                "Fax": "",
                "Rue": entity.get("address") or "",
                "Ville": "",
                "Region": "",
                "CodePostal": "",
                "Pays": entity.get("country_code") or "",
                "Handle": entity.get("handle") or "",
                "IdentifiantPublicType": entity.get("public_id_type") or "",
                "IdentifiantPublic": entity.get("public_id") or "",
                "Source": url,
            }
        )
    return data, rows, rate_limit_from_headers(headers)


def whois_role_summary(data: dict[str, Any], aliases: Iterable[str]) -> str:
    """Retourne la synthèse du premier rôle who.is correspondant aux alias.

    Les fournisseurs emploient notamment ``admin`` ou ``administrative`` pour
    le même rôle. Cette fonction rend le rapprochement explicite.
    """
    contacts = data.get("contacts") or {}
    if not isinstance(contacts, dict):
        return "Non publié par who.is"
    lowered = {str(key).lower(): value for key, value in contacts.items()}
    for alias in aliases:
        value = lowered.get(alias.lower())
        if isinstance(value, list):
            summaries = [whois_contact_summary(item) for item in value]
            return " ; ".join(dict.fromkeys(summaries))
        if value:
            return whois_contact_summary(value)
    return "Non publié par who.is"


def get_dnsdumpster_enrichment(
    domain: str, api_key: str, retries: int, delay: float
) -> tuple[
    set[str], list[dict[str, Any]], list[dict[str, Any]], dict[str, int]
]:
    """Interroge l'API officielle DNSDumpster et normalise ses enregistrements.

    Les catégories de réponse connues (A, MX, NS) contiennent des hôtes et des
    listes d'IP déjà enrichies avec ASN, propriétaire réseau et pays. Le parseur
    accepte aussi de futures catégories ayant la même structure.
    """
    url = f"https://api.dnsdumpster.com/domain/{urllib.parse.quote(domain)}"
    data, headers, _ = http_json_response(
        url,
        retries,
        max(delay, 2.0),
        "DNSDumpster",
        {"X-API-Key": api_key},
    )
    data = data or {}
    names: set[str] = set()
    rows: list[dict[str, Any]] = []
    dns_rows: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return names, rows, dns_rows, rate_limit_from_headers(headers)
    for record_type, records in data.items():
        if not isinstance(records, list):
            continue
        for record in records:
            # TXT/SPF sont généralement des chaînes simples dans la réponse.
            if isinstance(record, str):
                value = record.strip()
                category = (
                    "SPF" if value.strip('"').lower().startswith("v=spf1")
                    else str(record_type).upper()
                )
                rows.append(
                    {
                        "DomaineRacine": domain,
                        "Type": str(record_type).upper(),
                        "Hote": domain,
                        "IP": "",
                        "PTR": "",
                        "ASN": "",
                        "ProprietaireASN": "",
                        "PlageASN": "",
                        "Pays": "",
                        "CodePays": "",
                        "Source": url,
                    }
                )
                dns_rows.append(
                    {
                        "Domaine": domain,
                        "NomInterroge": domain,
                        "TypeDNS": "TXT" if category in {"TXT", "SPF"} else category,
                        "Categorie": category,
                        "Valeur": value,
                        "TTL": "",
                        "CodeDNS": "",
                        "Statut": "Présent",
                        "Source": "DNSDumpster",
                    }
                )
                continue
            if not isinstance(record, dict):
                continue
            host = normalize_domain(str(record.get("host") or ""))
            if host and (host == domain or host.endswith(f".{domain}")):
                names.add(host)
            normalized_type = str(record_type).upper()
            if normalized_type in {"MX", "NS", "CNAME"}:
                dns_rows.append(
                    {
                        "Domaine": domain,
                        "NomInterroge": domain,
                        "TypeDNS": normalized_type,
                        "Categorie": normalized_type,
                        "Valeur": str(record.get("host") or ""),
                        "TTL": "",
                        "CodeDNS": "",
                        "Statut": "Présent",
                        "Source": "DNSDumpster",
                    }
                )
            ips = record.get("ips") or []
            if not isinstance(ips, list) or not ips:
                ips = [{}]
            for ip_info in ips:
                ip_info = ip_info if isinstance(ip_info, dict) else {}
                rows.append(
                    {
                        "DomaineRacine": domain,
                        "Type": str(record_type).upper(),
                        "Hote": host or record.get("host") or "",
                        "IP": ip_info.get("ip") or record.get("ip") or "",
                        "PTR": ip_info.get("ptr") or "",
                        "ASN": ip_info.get("asn") or "",
                        "ProprietaireASN": ip_info.get("asn_name") or "",
                        "PlageASN": ip_info.get("asn_range") or "",
                        "Pays": ip_info.get("country") or "",
                        "CodePays": ip_info.get("country_code") or "",
                        "Source": url,
                    }
                )
    return names, rows, dns_rows, rate_limit_from_headers(headers)


def consolidate_dns_records(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fusionne les observations DNS identiques provenant de plusieurs sources.

    Les lignes présentes priment sur les lignes ``Absent`` pour un même contrôle.
    Lorsqu'une même valeur est vue par Google et DNSDumpster, leurs noms sont
    réunis dans la colonne ``Source``.
    """
    present_checks = {
        (row["Domaine"], row["NomInterroge"], row["TypeDNS"], row["Categorie"])
        for row in rows
        if row.get("Statut") == "Présent"
    }
    merged: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        check_key = (
            row["Domaine"], row["NomInterroge"], row["TypeDNS"], row["Categorie"]
        )
        if row.get("Statut") != "Présent" and check_key in present_checks:
            continue
        normalized_value = str(row.get("Valeur") or "").strip().strip('"').rstrip(".").lower()
        key = (*check_key, normalized_value)
        if key not in merged:
            merged[key] = dict(row)
            continue
        sources = set(str(merged[key].get("Source") or "").split(" + "))
        sources.update(str(row.get("Source") or "").split(" + "))
        merged[key]["Source"] = " + ".join(sorted(source for source in sources if source))
        if not merged[key].get("TTL") and row.get("TTL"):
            merged[key]["TTL"] = row["TTL"]
    return sorted(
        merged.values(),
        key=lambda row: (
            row["Domaine"], row["NomInterroge"], row["TypeDNS"],
            row["Categorie"], row["Valeur"],
        ),
    )


def parse_port_list(value: str) -> list[int]:
    """Valide une liste de ports TCP séparés par des virgules.

    Les plages et expressions Nmap ne sont volontairement pas acceptées afin de
    maintenir un périmètre explicite et borné.
    """
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item.isdigit():
            raise argparse.ArgumentTypeError(
                "les ports Nmap doivent être des entiers séparés par des virgules"
            )
        port = int(item)
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port hors limites: {port}")
        ports.add(port)
    if not ports:
        raise argparse.ArgumentTypeError("au moins un port Nmap est requis")
    if len(ports) > 100:
        raise argparse.ArgumentTypeError("100 ports maximum pour le mode non invasif")
    return sorted(ports)


def parse_nmap_xml(ip: str, xml_text: str) -> list[dict[str, Any]]:
    """Transforme la sortie XML Nmap en lignes CSV sans conserver le XML brut."""
    root = ET.fromstring(xml_text)
    rows: list[dict[str, Any]] = []
    for host in root.findall("host"):
        host_status = host.find("status")
        host_state = host_status.get("state", "") if host_status is not None else ""
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port in ports_node.findall("port"):
            state = port.find("state")
            service = port.find("service")
            rows.append(
                {
                    "IP": ip,
                    "HoteEtat": host_state,
                    "Protocole": port.get("protocol", "tcp"),
                    "Port": port.get("portid", ""),
                    "Etat": state.get("state", "") if state is not None else "",
                    "Raison": state.get("reason", "") if state is not None else "",
                    "ServiceIndicatif": service.get("name", "") if service is not None else "",
                    "Analyse": "TCP connect limité; aucune détection de version",
                }
            )
    return rows


def run_safe_nmap(
    ips: Iterable[str],
    ports: list[int],
    nmap_path: str | None,
    include_private: bool,
    max_ips: int,
) -> list[dict[str, Any]]:
    """Exécute un scan Nmap TCP connect borné et sans techniques intrusives.

    Le profil interdit implicitement les scripts NSE, la détection de versions,
    la détection d'OS et l'UDP. Les IP sont traitées séquentiellement.
    """
    executable = nmap_path or shutil.which("nmap")
    if not executable:
        raise RuntimeError(
            "Nmap est introuvable. Installez-le ou utilisez --nmap-path."
        )
    selected_ips = sorted(
        set(ips), key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value))
    )
    rows: list[dict[str, Any]] = []
    for index, ip in enumerate(selected_ips):
        if index >= max_ips:
            rows.append(
                {
                    "IP": ip, "HoteEtat": "ignoré", "Protocole": "tcp",
                    "Port": "", "Etat": "non analysé", "Raison": "limite --nmap-max-ips atteinte",
                    "ServiceIndicatif": "", "Analyse": "Aucun paquet envoyé",
                }
            )
            continue
        address = ipaddress.ip_address(ip)
        if not include_private and not address.is_global:
            rows.append(
                {
                    "IP": ip, "HoteEtat": "ignoré", "Protocole": "tcp",
                    "Port": "", "Etat": "non analysé", "Raison": "IP non publique",
                    "ServiceIndicatif": "", "Analyse": "Aucun paquet envoyé",
                }
            )
            continue
        command = [
            executable,
            "-sT", "-Pn", "-n", "-T3",
            "--max-retries", "1",
            "--host-timeout", "30s",
            "--scan-delay", "50ms",
            "-p", ",".join(str(port) for port in ports),
            "-oX", "-",
        ]
        if address.version == 6:
            command.append("-6")
        command.append(ip)
        print(f"Nmap limité {index + 1}/{min(len(selected_ips), max_ips)}: {ip}", flush=True)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=45,
                check=False,
                shell=False,
            )
            parsed = parse_nmap_xml(ip, completed.stdout) if completed.stdout.strip() else []
            if parsed:
                rows.extend(parsed)
            else:
                rows.append(
                    {
                        "IP": ip, "HoteEtat": "inconnu", "Protocole": "tcp",
                        "Port": "", "Etat": "erreur", "Raison": completed.stderr.strip()[:500],
                        "ServiceIndicatif": "", "Analyse": "Nmap sans résultat XML exploitable",
                    }
                )
        except (subprocess.TimeoutExpired, ET.ParseError, OSError) as exc:
            rows.append(
                {
                    "IP": ip, "HoteEtat": "inconnu", "Protocole": "tcp",
                    "Port": "", "Etat": "erreur", "Raison": str(exc)[:500],
                    "ServiceIndicatif": "", "Analyse": "Analyse interrompue sans nouvelle tentative",
                }
            )
    return rows


def resolve_name(name: str) -> dict[str, Any]:
    """Résout un nom en IPv4/IPv6 par le résolveur DNS configuré localement.

    ``socket.getaddrinfo`` suit les éventuels CNAME et retourne les adresses
    finales. Une erreur DNS est renvoyée comme donnée afin d'être inscrite dans
    le CSV plutôt que d'interrompre le lot.
    """
    addresses: set[tuple[str, str]] = set()
    error = ""
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(
            name, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        ):
            ip = sockaddr[0]
            record_type = "A" if family == socket.AF_INET else "AAAA"
            addresses.add((record_type, ip))
    except socket.gaierror as exc:
        error = str(exc)
    return {"name": name, "addresses": sorted(addresses), "error": error}


def ip_attribution(ip: str, retries: int, delay: float) -> dict[str, Any]:
    """Enrichit une IP avec son ASN, son opérateur et son réseau RDAP.

    ``ipwho.is`` fournit principalement ASN/ISP/organisation. RDAP fournit le
    titulaire du bloc réseau. ``HebergeurProbable`` est donc une attribution de
    l'opérateur apparent, qui peut être un CDN ou un reverse proxy.
    """
    encoded = urllib.parse.quote(ip, safe="")
    geo = http_json(f"https://ipwho.is/{encoded}", retries, delay, "ipwho.is") or {}
    rdap = http_json(f"https://rdap.org/ip/{encoded}", retries, delay, "RDAP IP") or {}

    connection = geo.get("connection") or {}
    asn = connection.get("asn") or ""
    isp = connection.get("isp") or ""
    organisation = connection.get("org") or ""
    country = geo.get("country_code") or rdap.get("country") or ""
    network = rdap.get("name") or rdap.get("handle") or ""

    if not organisation:
        for entity in rdap.get("entities") or []:
            names = vcard_values(entity, "fn") or vcard_values(entity, "org")
            if names:
                organisation = names[0]
                break

    provider = organisation or isp or network
    evidence = " ".join(str(x) for x in (organisation, isp, network) if x)
    return {
        "IP": ip,
        "ASN": asn,
        "ISP": isp,
        "Organisation": organisation,
        "ReseauRdap": network,
        "Pays": country,
        "HebergeurProbable": provider,
        "CdnOuProxyProbable": bool(CDN_RE.search(evidence)),
        "SourceAttribution": "ipwho.is + RDAP",
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    """Écrit un CSV Excel-friendly : UTF-8 avec BOM et séparateur point-virgule."""
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def load_dnsdumpster_usage(state_file: Path, reported_today_count: int) -> int:
    """Charge le compteur DNSDumpster du jour.

    Le compteur fourni par l'utilisateur et le compteur local sont comparés et
    la valeur la plus élevée est retenue. Ce choix conservateur évite de dépasser
    le quota lorsqu'une partie des requêtes a été faite hors de ce script.
    """
    today = date.today().isoformat()
    local_count = 0
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if state.get("date") == today:
            local_count = max(0, int(state.get("requests_attempted", 0)))
    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return max(local_count, reported_today_count)


def save_dnsdumpster_usage(state_file: Path, count: int, daily_quota: int) -> None:
    """Enregistre atomiquement le nombre de requêtes DNSDumpster tentées.

    Aucune clé API ni aucun domaine n'est conservé dans ce fichier d'état.
    """
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_file.with_suffix(state_file.suffix + ".tmp")
    payload = {
        "date": date.today().isoformat(),
        "account": "Free User",
        "requests_attempted": count,
        "daily_quota": daily_quota,
    }
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(state_file)


def load_whois_usage(state_file: Path, reported_month_count: int) -> int:
    """Charge le nombre de crédits who.is comptabilisés pour le mois UTC.

    Le plan Free se renouvelle au début de chaque mois civil UTC. Comme pour
    DNSDumpster, la valeur la plus élevée entre le compteur local et la valeur
    déclarée par l'utilisateur est retenue.
    """
    current_period = datetime.now(timezone.utc).strftime("%Y-%m")
    local_count = 0
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if state.get("period_utc") == current_period:
            local_count = max(0, int(state.get("credits_attempted", 0)))
    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return max(local_count, reported_month_count)


def save_whois_usage(state_file: Path, count: int, monthly_quota: int) -> None:
    """Enregistre atomiquement le compteur mensuel who.is Free.

    Le fichier ne contient ni clé API ni domaine. Les recherches introuvables
    sont officiellement gratuites, mais elles sont comptées localement par
    prudence car le statut HTTP n'est pas exposé par la couche de collecte.
    """
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_file.with_suffix(state_file.suffix + ".tmp")
    payload = {
        "period_utc": datetime.now(timezone.utc).strftime("%Y-%m"),
        "account": "Free",
        "credits_attempted": count,
        "monthly_quota": monthly_quota,
    }
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(state_file)


def load_domains(args: argparse.Namespace) -> list[str]:
    """Charge, normalise et déduplique les domaines des arguments utilisateur."""
    raw: list[str] = list(args.domain or [])
    if args.input:
        raw.extend(Path(args.input).read_text(encoding="utf-8-sig").splitlines())
    domains: set[str] = set()
    invalid: list[str] = []
    for line in raw:
        token = re.split(r"[,;\s]", line.strip(), maxsplit=1)[0] if line.strip() else ""
        domain = normalize_domain(token)
        if domain:
            domains.add(domain)
        elif token:
            invalid.append(token)
    if invalid:
        print(f"AVERTISSEMENT: {len(invalid)} entrée(s) ignorée(s): {', '.join(invalid[:5])}", file=sys.stderr)
    return sorted(domains)


def load_yaml_config(path: Path, explicitly_requested: bool) -> dict[str, Any]:
    """Charge un fichier YAML sans jamais journaliser son contenu sensible.

    Le fichier ``config.yaml`` par défaut est facultatif. En revanche, un chemin
    fourni explicitement avec ``--config`` doit exister afin de détecter les
    erreurs de saisie plutôt que d'exécuter silencieusement une autre configuration.
    """
    if not path.exists():
        if explicitly_requested:
            raise ValueError(f"fichier de configuration introuvable: {path}")
        return {}
    if yaml is None:
        raise ValueError(
            "PyYAML est requis pour lire la configuration: "
            "python -m pip install -r requirements.txt"
        )
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"configuration YAML invalide ({path}): {exc}") from exc
    if document is None:
        return {}
    if not isinstance(document, dict):
        raise ValueError("la racine du fichier YAML doit être un objet")
    return document


def config_section(config: dict[str, Any], name: str) -> dict[str, Any]:
    """Retourne une section YAML et refuse les types ambigus."""
    value = config.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"la section YAML '{name}' doit être un objet")
    return value


def string_list(value: Any, field: str, pattern: str) -> tuple[str, ...]:
    """Valide une liste YAML de chaînes courtes et dédupliquées."""
    if not isinstance(value, list) or not value:
        raise ValueError(f"'{field}' doit être une liste YAML non vide")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not re.fullmatch(pattern, item.strip().lower()):
            raise ValueError(f"valeur invalide dans '{field}': {item!r}")
        normalized = item.strip().lower()
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def apply_yaml_config(config: dict[str, Any]) -> dict[str, str]:
    """Applique les constantes configurables et retourne les clés API du YAML."""
    global USER_AGENT, DOMAIN_RE, CDN_RE
    global COMMON_SUBDOMAIN_PREFIXES, DEFAULT_DKIM_SELECTORS, DEFAULT_NMAP_PORTS

    http = config_section(config, "http")
    validation = config_section(config, "validation")
    cdn = config_section(config, "cdn")
    dns = config_section(config, "dns")
    nmap = config_section(config, "nmap")
    api_keys = config_section(config, "api_keys")

    if "user_agent" in http:
        user_agent = http["user_agent"]
        if not isinstance(user_agent, str) or not user_agent.strip() or len(user_agent) > 256:
            raise ValueError("'http.user_agent' doit être une chaîne de 1 à 256 caractères")
        USER_AGENT = user_agent.strip()

    if "domain_regex" in validation:
        pattern = validation["domain_regex"]
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("'validation.domain_regex' doit être une chaîne non vide")
        try:
            DOMAIN_RE = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"'validation.domain_regex' est invalide: {exc}") from exc

    if "provider_regex" in cdn:
        pattern = cdn["provider_regex"]
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("'cdn.provider_regex' doit être une chaîne non vide")
        try:
            CDN_RE = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"'cdn.provider_regex' est invalide: {exc}") from exc

    if "common_subdomain_prefixes" in dns:
        COMMON_SUBDOMAIN_PREFIXES = string_list(
            dns["common_subdomain_prefixes"],
            "dns.common_subdomain_prefixes",
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        )
    if "dkim_selectors" in dns:
        DEFAULT_DKIM_SELECTORS = string_list(
            dns["dkim_selectors"], "dns.dkim_selectors", r"[a-z0-9_-]{1,63}"
        )
    if "ports" in nmap:
        ports = nmap["ports"]
        if not isinstance(ports, list):
            raise ValueError("'nmap.ports' doit être une liste YAML")
        DEFAULT_NMAP_PORTS = tuple(parse_port_list(",".join(str(port) for port in ports)))

    result: dict[str, str] = {}
    for field in ("dnsdumpster", "whois"):
        value = api_keys.get(field, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError(f"'api_keys.{field}' doit être une chaîne")
        result[field] = value.strip()
    return result


def main() -> int:
    """Analyse les options, orchestre la collecte et écrit les livrables."""
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", default="config.yaml")
    preliminary, _ = config_parser.parse_known_args()
    explicitly_requested = any(
        argument == "--config" or argument.startswith("--config=")
        for argument in sys.argv[1:]
    )
    config_path = Path(preliminary.config).expanduser().resolve()
    try:
        yaml_config = load_yaml_config(config_path, explicitly_requested)
        yaml_api_keys = apply_yaml_config(yaml_config)
    except ValueError as exc:
        config_parser.error(str(exc))

    parser = argparse.ArgumentParser(description="Inventaire passif de domaines")
    parser.add_argument(
        "--config",
        default=str(config_path),
        help="Fichier YAML de configuration (défaut: ./config.yaml s'il existe)",
    )
    parser.add_argument("--input", "-i", help="Fichier texte, un domaine par ligne")
    parser.add_argument("--domain", "-d", action="append", help="Domaine (option répétable)")
    parser.add_argument("--output", "-o", default=f"domain-inventory-{datetime.now():%Y%m%d-%H%M%S}")
    parser.add_argument("--workers", type=int, default=12, help="Résolutions DNS parallèles (défaut: 12)")
    parser.add_argument("--delay", type=float, default=0.35, help="Pause entre appels d'attribution IP")
    parser.add_argument("--retries", type=int, default=3, help="Tentatives HTTP (défaut: 3)")
    parser.add_argument(
        "--dkim-selector",
        action="append",
        dest="dkim_selectors",
        help=(
            "Sélecteur DKIM à tester (option répétable). Sans cette option, "
            "plusieurs sélecteurs courants sont testés."
        ),
    )
    parser.add_argument(
        "--dnsdumpster-daily-quota",
        type=int,
        default=50,
        help="Quota quotidien DNSDumpster du compte (défaut Free User: 50)",
    )
    parser.add_argument(
        "--dnsdumpster-today-count",
        type=int,
        default=0,
        help="Compteur DNSDumpster déjà consommé aujourd'hui (défaut: 0)",
    )
    parser.add_argument(
        "--dnsdumpster-state-file",
        default=str(default_state_directory() / "dnsdumpster-usage.json"),
        help="Fichier local persistant du compteur DNSDumpster",
    )
    parser.add_argument(
        "--whois-monthly-quota",
        type=int,
        default=500,
        help="Crédits mensuels who.is (défaut plan Free: 500)",
    )
    parser.add_argument(
        "--whois-month-count",
        type=int,
        default=0,
        help="Crédits who.is déjà consommés ce mois-ci (défaut: 0)",
    )
    parser.add_argument(
        "--whois-state-file",
        default=str(default_state_directory() / "whois-usage.json"),
        help="Fichier local persistant du compteur who.is",
    )
    parser.add_argument(
        "--whois-source",
        choices=("whois", "rdap", "both"),
        default="whois",
        help=(
            "Endpoint(s) who.is à utiliser: whois (1 crédit/domaine), "
            "rdap (1 crédit/domaine) ou both (2 crédits/domaine)"
        ),
    )
    parser.add_argument(
        "--nmap",
        action="store_true",
        help=(
            "Active le scan Nmap TCP connect limité. À utiliser uniquement sur "
            "des IP que vous êtes autorisé à auditer."
        ),
    )
    parser.add_argument(
        "--nmap-ports",
        type=parse_port_list,
        default=",".join(str(port) for port in DEFAULT_NMAP_PORTS),
        help="Ports TCP séparés par des virgules (100 maximum)",
    )
    parser.add_argument(
        "--nmap-path",
        help="Chemin explicite vers l'exécutable Nmap si absent du PATH",
    )
    parser.add_argument(
        "--nmap-max-ips",
        type=int,
        default=256,
        help="Nombre maximal d'IP analysées par exécution (défaut: 256)",
    )
    parser.add_argument(
        "--nmap-include-private",
        action="store_true",
        help="Autorise aussi les IP privées/non globales découvertes",
    )
    args = parser.parse_args()

    # Une variable d'environnement remplace la valeur YAML. Les clés ne sont
    # jamais inscrites dans les CSV, le résumé ou les journaux du programme.
    dnsdumpster_api_key = os.environ.get(
        "DNSDUMPSTER_API_KEY", yaml_api_keys["dnsdumpster"]
    ).strip()
    whois_api_key = os.environ.get("WHOIS_API_KEY", yaml_api_keys["whois"]).strip()

    if not args.input and not args.domain:
        parser.error("utilisez --input ou au moins un --domain")
    if (
        args.workers < 1
        or args.workers > 64
        or args.retries < 1
        or args.delay < 0
        or args.dnsdumpster_daily_quota < 1
        or args.dnsdumpster_today_count < 0
        or args.whois_monthly_quota < 1
        or args.whois_month_count < 0
        or args.nmap_max_ips < 1
        or args.nmap_max_ips > 4096
    ):
        parser.error("paramètres workers/retries/delay invalides")

    domains = load_domains(args)
    if not domains:
        parser.error("aucun domaine valide")

    # Toutes les sorties d'une exécution sont regroupées dans un répertoire.
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    domain_rows: list[dict[str, Any]] = []
    rdap_contact_rows: list[dict[str, Any]] = []
    whois_contact_rows: list[dict[str, Any]] = []
    dnsdumpster_rows: list[dict[str, Any]] = []
    domain_dns_rows: list[dict[str, Any]] = []
    discovered_by_root: dict[str, dict[str, set[str]]] = {}
    dnsdumpster_state_file = prepare_state_file(
        Path(args.dnsdumpster_state_file).expanduser().resolve(),
        "dnsdumpster-usage.json",
    )
    dnsdumpster_usage = load_dnsdumpster_usage(
        dnsdumpster_state_file, args.dnsdumpster_today_count
    )
    dnsdumpster_skipped_quota = 0
    whois_state_file = prepare_state_file(
        Path(args.whois_state_file).expanduser().resolve(),
        "whois-usage.json",
    )
    whois_usage = load_whois_usage(whois_state_file, args.whois_month_count)
    whois_skipped_quota = 0
    dkim_selectors = tuple(
        dict.fromkeys(
            selector.strip().lower()
            for selector in (args.dkim_selectors or DEFAULT_DKIM_SELECTORS)
            if re.fullmatch(r"[a-z0-9_-]{1,63}", selector.strip().lower())
        )
    )
    if not dkim_selectors:
        parser.error("aucun sélecteur DKIM valide")

    print(
        "Sources optionnelles: "
        f"DNSDumpster={'activé' if dnsdumpster_api_key else 'désactivé (clé absente)'}, "
        f"who.is={'activé' if whois_api_key else 'désactivé (clé absente)'}",
        flush=True,
    )
    if dnsdumpster_api_key:
        print(
            "DNSDumpster Free User: "
            f"{dnsdumpster_usage}/{args.dnsdumpster_daily_quota} requête(s) "
            "déjà comptabilisée(s) aujourd'hui.",
            flush=True,
        )
    if whois_api_key:
        print(
            "who.is Free: "
            f"{whois_usage}/{args.whois_monthly_quota} crédit(s) "
            "comptabilisé(s) pour le mois UTC.",
            flush=True,
        )

    # Étape 1 : métadonnées/contacts RDAP et découverte passive des noms.
    for root in domains:
        print(f"[{root}] RDAP et Certificate Transparency...", flush=True)
        rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(root)}"
        rdap = http_json(rdap_url, args.retries, args.delay, "RDAP domaine")
        whois_data: dict[str, Any] = {}
        whois_rdap_data: dict[str, Any] = {}
        whois_queried = False
        whois_rdap_queried = False
        requested_whois_sources = (
            ("whois", "rdap") if args.whois_source == "both"
            else (args.whois_source,)
        )
        if whois_api_key:
            for selected_source in requested_whois_sources:
                if whois_usage >= args.whois_monthly_quota:
                    whois_skipped_quota += 1
                    if whois_skipped_quota == 1:
                        print(
                            "AVERTISSEMENT: quota mensuel who.is atteint; les "
                            "appels who.is restants sont ignorés.",
                            file=sys.stderr,
                        )
                    continue

                # Chaque lookup WHOIS ou RDAP coûte un crédit. Le compteur est
                # persisté avant l'appel pour survivre à une interruption.
                whois_usage += 1
                save_whois_usage(
                    whois_state_file, whois_usage, args.whois_monthly_quota
                )
                if selected_source == "whois":
                    whois_data, contact_rows, whois_rate = get_whois_enrichment(
                        root, whois_api_key, 1, args.delay
                    )
                    whois_queried = True
                else:
                    (
                        whois_rdap_data,
                        contact_rows,
                        whois_rate,
                    ) = get_whois_rdap_enrichment(
                        root, whois_api_key, 1, args.delay
                    )
                    whois_rdap_queried = True
                whois_contact_rows.extend(contact_rows)

                # Les en-têtes officiels remplacent l'estimation locale.
                if "limit" in whois_rate and "remaining" in whois_rate:
                    args.whois_monthly_quota = whois_rate["limit"]
                    whois_usage = max(
                        0, whois_rate["limit"] - whois_rate["remaining"]
                    )
                    save_whois_usage(
                        whois_state_file,
                        whois_usage,
                        args.whois_monthly_quota,
                    )
                # Limite du plan Free : une requête par seconde.
                time.sleep(max(1.0, args.delay))
        nameservers = sorted(
            ns.get("ldhName", "") for ns in (rdap or {}).get("nameservers", []) if ns.get("ldhName")
        )
        domain_rows.append(
            {
                "Domaine": root,
                "Registrar": registrar_name(rdap),
                "Creation": rdap_event(rdap, ("registration",)),
                "Expiration": rdap_event(rdap, ("expiration",)),
                "DerniereModification": rdap_event(rdap, ("last changed", "last update of RDAP database")),
                "Statuts": ", ".join(sorted((rdap or {}).get("status") or [])),
                "ServeursDNS": ", ".join(nameservers),
                "ContactAdministratif": rdap_role_summary(rdap, "administrative"),
                "ContactFacturation": rdap_role_summary(rdap, "billing"),
                "ContactAdministratifWhois": whois_role_summary(
                    whois_data, ("administrative", "admin")
                ) if whois_queried else (
                    "Source who.is non interrogée (quota atteint)"
                    if whois_api_key else "Source who.is désactivée"
                ),
                "ContactFacturationWhois": whois_role_summary(
                    whois_data, ("billing", "bill")
                ) if whois_queried else (
                    "Source who.is non interrogée (quota atteint)"
                    if whois_api_key else "Source who.is désactivée"
                ),
                "ContactAdministratifWhoisRdap": whois_rdap_role_summary(
                    whois_rdap_data, ("administrative", "admin")
                ) if whois_rdap_queried else (
                    "Mode RDAP who.is non sélectionné"
                    if args.whois_source == "whois"
                    else (
                        "Source who.is RDAP non interrogée (quota atteint)"
                        if whois_api_key else "Source who.is désactivée"
                    )
                ),
                "ContactFacturationWhoisRdap": whois_rdap_role_summary(
                    whois_rdap_data, ("billing", "bill")
                ) if whois_rdap_queried else (
                    "Mode RDAP who.is non sélectionné"
                    if args.whois_source == "whois"
                    else (
                        "Source who.is RDAP non interrogée (quota atteint)"
                        if whois_api_key else "Source who.is désactivée"
                    )
                ),
                "ContactsPublics": rdap_contacts(rdap),
                "RegistrarWhois": whois_data.get("registrar") or "",
                "InstantaneWhois": whois_data.get("snapshot_time") or "",
                "RegistrarWhoisRdap": whois_rdap_role_summary(
                    whois_rdap_data, ("registrar",)
                ) if whois_rdap_queried else "",
                "InstantaneWhoisRdap": whois_rdap_data.get("snapshot_time") or "",
                "RessourceWhoisRdap": whois_rdap_data.get("resource_url") or "",
                "Source": rdap_url,
            }
        )
        for entity in walk_rdap_entities((rdap or {}).get("entities") or []):
            rdap_contact_rows.append(rdap_entity_row(root, entity))
        source_map: dict[str, set[str]] = {}
        for name in certificate_names(root, args.retries, args.delay):
            source_map.setdefault(name, set()).add(
                "domaine racine" if name == root else "crt.sh"
            )
        if dnsdumpster_api_key and dnsdumpster_usage < args.dnsdumpster_daily_quota:
            # Le compteur est incrémenté avant l'appel : même si le processus est
            # interrompu ou si l'API échoue, le suivi local reste conservateur.
            dnsdumpster_usage += 1
            save_dnsdumpster_usage(
                dnsdumpster_state_file,
                dnsdumpster_usage,
                args.dnsdumpster_daily_quota,
            )
            (
                dumpster_names,
                dumpster_records,
                dumpster_dns_records,
                dumpster_rate,
            ) = get_dnsdumpster_enrichment(
                # Pas de reprise automatique pour cette source : une nouvelle
                # tentative pourrait consommer une unité de quota supplémentaire.
                root, dnsdumpster_api_key, 1, args.delay
            )
            # DNSDumpster ne documente pas d'endpoint de compteur. Si l'API
            # fournit néanmoins des en-têtes standards, ils sont prioritaires.
            if "limit" in dumpster_rate and "remaining" in dumpster_rate:
                args.dnsdumpster_daily_quota = dumpster_rate["limit"]
                dnsdumpster_usage = max(
                    0, dumpster_rate["limit"] - dumpster_rate["remaining"]
                )
                save_dnsdumpster_usage(
                    dnsdumpster_state_file,
                    dnsdumpster_usage,
                    args.dnsdumpster_daily_quota,
                )
            for name in dumpster_names:
                source_map.setdefault(name, set()).add("DNSDumpster")
            dnsdumpster_rows.extend(dumpster_records)
            domain_dns_rows.extend(dumpster_dns_records)
            # Limite officielle : au plus une requête toutes les deux secondes.
            time.sleep(max(2.0, args.delay))
        elif dnsdumpster_api_key:
            dnsdumpster_skipped_quota += 1
            if dnsdumpster_skipped_quota == 1:
                print(
                    "AVERTISSEMENT: quota DNSDumpster quotidien atteint; "
                    "cette source est ignorée pour les domaines restants.",
                    file=sys.stderr,
                )
        # Ajout explicite des noms classiques demandés, même s'ils ne sont pas
        # présents dans les journaux de certificats ou chez DNSDumpster.
        for prefix in COMMON_SUBDOMAIN_PREFIXES:
            source_map.setdefault(f"{prefix}.{root}", set()).add(
                "test de sous-domaine classique"
            )
        discovered_by_root[root] = source_map

        print(f"[{root}] Contrôles DNS et messagerie...", flush=True)
        domain_dns_rows.extend(
            collect_domain_dns_records(
                root, dkim_selectors, args.retries, args.delay, args.workers
            )
        )
        time.sleep(args.delay)

    # Les observations Google et DNSDumpster sont regroupées dans une même table.
    domain_dns_rows = consolidate_dns_records(domain_dns_rows)

    # Un nom peut appartenir à plusieurs domaines demandés (cas de listes
    # redondantes). Cette table permet une seule résolution DNS par nom unique.
    owner_by_name: dict[str, set[str]] = {}
    for root, source_map in discovered_by_root.items():
        for name in source_map:
            owner_by_name.setdefault(name, set()).add(root)

    # Étape 2 : les résolutions DNS, indépendantes, sont parallélisées.
    print(f"Résolution DNS de {len(owner_by_name)} nom(s)...", flush=True)
    resolved: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(resolve_name, name): name for name in owner_by_name}
        for future in as_completed(futures):
            result = future.result()
            resolved[result["name"]] = result

    # Un nom aléatoire permet de détecter un éventuel DNS générique (wildcard).
    # Si ce nom inexistant se résout, les sous-domaines classiques qui renvoient
    # les mêmes IP doivent être interprétés avec prudence.
    wildcard_ips_by_root: dict[str, set[str]] = {}
    for root in domains:
        probe_name = f"codex-wildcard-check-{secrets.token_hex(6)}.{root}"
        probe = resolve_name(probe_name)
        wildcard_ips_by_root[root] = {
            ip for _, ip in probe["addresses"]
        }

    # Étape 3 : transformation des réponses DNS en lignes CSV et constitution
    # d'un ensemble d'IP, ce qui évite d'enrichir plusieurs fois la même adresse.
    dns_rows: list[dict[str, Any]] = []
    unique_ips: set[str] = set()
    for name in sorted(owner_by_name):
        result = resolved[name]
        for root in sorted(owner_by_name[name]):
            if not result["addresses"]:
                dns_rows.append(
                    {
                        "DomaineRacine": root,
                        "Nom": name,
                        "Type": "",
                        "IP": "",
                        "StatutDNS": "Non résolu",
                        "ErreurDNS": result["error"],
                        "WildcardDNSProbable": False,
                        "Commentaire": "",
                        "SourceSousDomaine": ", ".join(
                            sorted(discovered_by_root[root][name])
                        ),
                    }
                )
            for record_type, ip in result["addresses"]:
                unique_ips.add(ip)
                is_classic_test = (
                    "test de sous-domaine classique"
                    in discovered_by_root[root][name]
                )
                wildcard_probable = (
                    is_classic_test and ip in wildcard_ips_by_root.get(root, set())
                )
                dns_rows.append(
                    {
                        "DomaineRacine": root,
                        "Nom": name,
                        "Type": record_type,
                        "IP": ip,
                        "StatutDNS": "Résolu",
                        "ErreurDNS": "",
                        "WildcardDNSProbable": wildcard_probable,
                        "Commentaire": (
                            "Même IP qu'un nom aléatoire inexistant; service réel non confirmé"
                            if wildcard_probable else ""
                        ),
                        "SourceSousDomaine": ", ".join(
                            sorted(discovered_by_root[root][name])
                        ),
                    }
                )

    # Étape 4 : attribution séquentielle des IP. La temporisation réduit le
    # risque de limitation par les services publics.
    ip_rows: list[dict[str, Any]] = []
    for index, ip in enumerate(sorted(unique_ips, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))):
        print(f"Attribution IP {index + 1}/{len(unique_ips)}: {ip}", flush=True)
        ip_rows.append(ip_attribution(ip, args.retries, args.delay))
        if index + 1 < len(unique_ips):
            time.sleep(args.delay)

    # Étape optionnelle : aucun scan n'est effectué sans le drapeau --nmap.
    nmap_rows: list[dict[str, Any]] = []
    if args.nmap:
        print(
            "Nmap activé: TCP connect uniquement, ports bornés, sans scripts, "
            "sans détection de versions ni d'OS.",
            flush=True,
        )
        try:
            nmap_rows = run_safe_nmap(
                unique_ips,
                args.nmap_ports,
                args.nmap_path,
                args.nmap_include_private,
                args.nmap_max_ips,
            )
        except RuntimeError as exc:
            print(f"AVERTISSEMENT: {exc}", file=sys.stderr)
            nmap_rows = [
                {
                    "IP": "", "HoteEtat": "non exécuté", "Protocole": "tcp",
                    "Port": "", "Etat": "erreur", "Raison": str(exc),
                    "ServiceIndicatif": "", "Analyse": "Aucun paquet envoyé",
                }
            ]

    # Étape 5 : écriture des huit tables et du résumé de l'exécution.
    write_csv(output / "domaines.csv", domain_rows, [
        "Domaine", "Registrar", "Creation", "Expiration", "DerniereModification",
        "Statuts", "ServeursDNS", "ContactAdministratif", "ContactFacturation",
        "ContactAdministratifWhois", "ContactFacturationWhois",
        "ContactAdministratifWhoisRdap", "ContactFacturationWhoisRdap",
        "ContactsPublics", "RegistrarWhois", "InstantaneWhois",
        "RegistrarWhoisRdap", "InstantaneWhoisRdap", "RessourceWhoisRdap", "Source",
    ])
    write_csv(output / "contacts-rdap.csv", rdap_contact_rows, [
        "Domaine", "Roles", "Handle", "Nom", "Organisation", "Emails",
        "Telephones", "Adresse", "Statuts", "Port43", "LienRdap",
    ])
    write_csv(output / "contacts-whois.csv", whois_contact_rows, [
        "Domaine", "SourceType", "Role", "Nom", "Organisation", "Email",
        "Telephone", "Fax", "Rue", "Ville", "Region", "CodePostal", "Pays",
        "Handle", "IdentifiantPublicType", "IdentifiantPublic", "Source",
    ])
    write_csv(output / "dnsdumpster.csv", dnsdumpster_rows, [
        "DomaineRacine", "Type", "Hote", "IP", "PTR", "ASN", "ProprietaireASN",
        "PlageASN", "Pays", "CodePays", "Source",
    ])
    write_csv(output / "enregistrements-dns.csv", domain_dns_rows, [
        "Domaine", "NomInterroge", "TypeDNS", "Categorie", "Valeur", "TTL",
        "CodeDNS", "Statut", "Source",
    ])
    write_csv(output / "sous-domaines-dns.csv", dns_rows, [
        "DomaineRacine", "Nom", "Type", "IP", "StatutDNS", "ErreurDNS",
        "WildcardDNSProbable", "Commentaire", "SourceSousDomaine",
    ])
    write_csv(output / "adresses-ip.csv", ip_rows, [
        "IP", "ASN", "ISP", "Organisation", "ReseauRdap", "Pays",
        "HebergeurProbable", "CdnOuProxyProbable", "SourceAttribution",
    ])
    write_csv(output / "nmap.csv", nmap_rows, [
        "IP", "HoteEtat", "Protocole", "Port", "Etat", "Raison",
        "ServiceIndicatif", "Analyse",
    ])

    summary = {
        "execution_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "collecte passive et scan Nmap limité" if args.nmap else "collecte passive uniquement",
        "configuration_file": str(config_path) if config_path.exists() else None,
        "domaines_demandes": len(domains),
        "noms_decouverts": len(owner_by_name),
        "adresses_ip_uniques": len(unique_ips),
        "nmap_active": bool(args.nmap),
        "nmap_ports": args.nmap_ports if args.nmap else [],
        "nmap_max_ips": args.nmap_max_ips if args.nmap else 0,
        "nmap_include_private": bool(args.nmap_include_private) if args.nmap else False,
        "nmap_resultats": len(nmap_rows),
        "services_externes": ["rdap.org", "crt.sh", "ipwho.is", "dns.google"]
        + (["dnsdumpster.com"] if dnsdumpster_api_key else [])
        + (["who.is"] if whois_api_key else []),
        "dnsdumpster_active": bool(dnsdumpster_api_key),
        "dnsdumpster_account": "Free User" if dnsdumpster_api_key else None,
        "dnsdumpster_daily_quota": args.dnsdumpster_daily_quota,
        "dnsdumpster_today_count_final": dnsdumpster_usage,
        "dnsdumpster_remaining": max(
            0, args.dnsdumpster_daily_quota - dnsdumpster_usage
        ),
        "dnsdumpster_domains_skipped_quota": dnsdumpster_skipped_quota,
        "dnsdumpster_state_file": str(dnsdumpster_state_file),
        "who_is_active": bool(whois_api_key),
        "who_is_account": "Free" if whois_api_key else None,
        "who_is_mode": args.whois_source,
        "who_is_monthly_quota": args.whois_monthly_quota,
        "who_is_month_count_final": whois_usage,
        "who_is_remaining": max(0, args.whois_monthly_quota - whois_usage),
        "who_is_domains_skipped_quota": whois_skipped_quota,
        "who_is_state_file": str(whois_state_file),
        "contacts_rdap_publics": len(rdap_contact_rows),
        "contacts_whois_publics": len(whois_contact_rows),
        "enregistrements_dnsdumpster": len(dnsdumpster_rows),
        "controles_dns": len(domain_dns_rows),
        "sous_domaines_classiques_testes": list(COMMON_SUBDOMAIN_PREFIXES),
        "selecteurs_dkim_testes": list(dkim_selectors),
        "avertissement": (
            "Les contacts peuvent être masqués; les sous-domaines issus des journaux de "
            "certificats ne sont pas exhaustifs; l'hébergeur est une attribution probable "
            "de l'IP et peut être un CDN ou proxy."
        ),
    }
    (output / "resume.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Terminé. Résultats: {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
