#!/usr/bin/env python3
"""Passive domain inventory based on public sources.

The program accepts one or more domains and performs four main stages:

1. query domain RDAP data (registrar, dates, statuses, and public contacts);
2. discover names in the ``crt.sh`` Certificate Transparency logs;
3. resolve the discovered names to A and AAAA records;
4. attribute IP addresses to an ASN and an apparent network operator.

Results are written to eight CSV files and one JSON summary. PyYAML is used for
configuration. The script performs no DNS brute force. A bounded TCP Nmap scan
can be enabled explicitly with ``--nmap`` and is disabled by default.

Warning: queries send searched domains to ``rdap.org`` and ``crt.sh``, and IP
addresses to ``rdap.org`` and ``ipwho.is``. Contacts absent from an RDAP response
cannot be reconstructed by this program.
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
except ImportError:  # An explicit error is emitted only when a YAML file is used.
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
    """Return a stable state directory independent of the script location."""
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "DomainInventory"
    return Path.home() / ".domain-inventory"


def prepare_state_file(preferred: Path, fallback_name: str) -> Path:
    """Validate the state directory or select an accessible local fallback.

    The fallback is ``.domain-inventory-state`` in the current directory and is
    used only when the preferred directory cannot be created.
    """
    try:
        preferred.parent.mkdir(parents=True, exist_ok=True)
        return preferred
    except OSError as exc:
        fallback = Path.cwd() / ".domain-inventory-state" / fallback_name
        fallback.parent.mkdir(parents=True, exist_ok=True)
        print(
            f"WARNING: primary state directory is unavailable ({exc}); "
            f"falling back to {fallback}",
            file=sys.stderr,
        )
        return fallback


def normalize_domain(value: str) -> str | None:
    """Clean and validate a domain name.

    Also accepts a simple URL or wildcard certificate name such as
    ``*.example.com``. Internationalized names are converted to IDNA.

    Args:
        value: Raw value from the command line, an input file, or a certificate
            transparency log.

    Returns:
        The normalized ASCII domain, or ``None`` when the value is invalid.
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
    """Download JSON and retain headers useful for quota tracking.

    Network errors are non-fatal: after the last attempt, the function emits a
    warning and returns ``None``. This allows a 400-domain batch to continue
    when a public source fails temporarily.

    Args:
        url: HTTPS URL to query.
        retries: Maximum number of attempts.
        delay: Base delay in seconds between attempts.
        service: Human-readable source name used in warnings.
        extra_headers: Additional headers, notably for optional API
            authentication. They are never written to result files.

    Returns:
        ``(JSON document, lowercase headers, HTTP status)``. The document is
        ``None`` after a final failure.
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
                print(f"WARNING: {service} inaccessible: {exc}", file=sys.stderr)
                return None, response_headers, exc.code
            time.sleep(max(0.5, delay * attempt))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == retries:
                print(f"WARNING: {service} inaccessible: {exc}", file=sys.stderr)
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
    """Simplified :func:`http_json_response` variant returning JSON only."""
    data, _, _ = http_json_response(
        url, retries, delay, service, extra_headers
    )
    return data


def rate_limit_from_headers(headers: dict[str, str]) -> dict[str, int]:
    """Extract normalized counters from common rate-limit headers."""
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
    """Extract all values of a jCard property from an RDAP entity.

    RDAP represents contact details as jCard data in ``vcardArray``. This
    function handles scalar and list values, then deduplicates the result.
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
    """Recursively walk RDAP entities and their child entities.

    Some registries place the ``abuse`` contact below the registrar entity. A
    first-level-only traversal would lose this information.
    """
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        yield entity
        yield from walk_rdap_entities(entity.get("entities") or [])


def vcard_address(entity: dict[str, Any]) -> str:
    """Format the public jCard postal addresses of an RDAP entity."""
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
    """Convert an RDAP entity into a row for ``contacts-rdap.csv``."""
    roles = sorted(set(str(role).lower() for role in (entity.get("roles") or [])))
    return {
        "Domaine": domain,
        "Roles": ", ".join(roles) or "unspecified",
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
    """Build a readable summary of entities carrying a given role.

    Args:
        rdap: Complete domain RDAP response, or ``None`` on failure.
        role: Requested RDAP role, for example ``administrative`` or ``billing``.

    Returns:
        Concatenated public contact details, a redaction notice, or an RDAP
        source-unavailable notice.
    """
    if not rdap:
        return "RDAP unavailable"
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
        matches.append(" | ".join(published) if published else "Role present, details redacted")
    return " ; ".join(dict.fromkeys(matches)) if matches else "Not published by the RDAP service"


def rdap_contacts(rdap: dict[str, Any] | None) -> str:
    """Produce a summary of all publicly visible RDAP contacts."""
    if not rdap:
        return ""
    contacts: list[str] = []
    for entity in walk_rdap_entities(rdap.get("entities") or []):
        roles = ",".join(entity.get("roles") or []) or "unspecified"
        details: list[str] = []
        for field in ("fn", "org", "email", "tel"):
            details.extend(vcard_values(entity, field))
        if details:
            contacts.append(f"{roles}: {' | '.join(dict.fromkeys(details))}")
        elif entity.get("handle"):
            contacts.append(f"{roles}: handle={entity['handle']}")
    return " ; ".join(dict.fromkeys(contacts))


def rdap_event(rdap: dict[str, Any] | None, actions: Iterable[str]) -> str:
    """Return the date of the first event matching the supplied actions."""
    if not rdap:
        return ""
    events = rdap.get("events") or []
    for action in actions:
        for event in events:
            if event.get("eventAction") == action:
                return str(event.get("eventDate") or "")
    return ""


def registrar_name(rdap: dict[str, Any] | None) -> str:
    """Extract the public registrar name, falling back to its RDAP handle."""
    if not rdap:
        return ""
    for entity in rdap.get("entities") or []:
        if "registrar" in (entity.get("roles") or []):
            names = vcard_values(entity, "fn") or vcard_values(entity, "org")
            return names[0] if names else str(entity.get("handle") or "")
    return ""


def certificate_names(domain: str, retries: int, delay: float) -> list[str]:
    """Find domain names in Certificate Transparency logs.

    The root domain is always present, even when ``crt.sh`` is unavailable.
    Wildcards are removed and only actual descendants of the requested domain
    are retained.
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
    """Query Google Public DNS through its DNS-over-HTTPS JSON API.

    Args:
        name: Normalized DNS name to query.
        record_type: Canonical type such as ``MX``, ``TXT``, ``CNAME``, or ``AAAA``.
        retries: Number of HTTP attempts.
        delay: Base delay between attempts.

    Returns:
        A ``(DNS code, answers)`` pair. Code ``0`` means NOERROR, ``3`` means
        NXDOMAIN, and ``None`` means that HTTP/JSON was unavailable.
    """
    query = urllib.parse.urlencode(
        {
            "name": name,
            "type": record_type,
            # Prevent sending part of the client IP to authoritative servers
            # through EDNS Client Subnet.
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
    """Collect DNS records and email-security checks for a domain.

    DKIM selectors cannot be discovered generically through DNS, so the script
    tests a configurable list of common selectors. Every query, including an
    empty response, produces at least one row so the check remains auditable.
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
                logical_category = "TXT (_dmarc, not DMARC)"
            elif category == "DKIM" and "v=dkim1" not in value.lower():
                logical_category = "TXT (_domainkey, not DKIM)"
            rows.append(
                {
                    "Domaine": domain,
                    "NomInterroge": query_name,
                    "TypeDNS": record_type,
                    "Categorie": logical_category,
                    "Valeur": value,
                    "TTL": answer.get("TTL") or "",
                    "CodeDNS": status if status is not None else "",
                    "Statut": "Present",
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
                    "Statut": "Absent" if status is not None else "Unavailable",
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
    """Format a who.is API contact without assuming every field is present.

    The API returns normalized contacts, but fields vary by registry and privacy
    redaction. Nested dictionaries and lists are flattened conservatively.
    """
    if not isinstance(contact, dict) or not contact:
        return "Not published by who.is"
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
    return " | ".join(dict.fromkeys(values)) or "Details redacted by who.is"


def get_whois_enrichment(
    domain: str, api_key: str, retries: int, delay: float
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Query the official who.is WHOIS API.

    Returns:
        A pair containing the normalized raw response and contact rows intended
        for ``contacts-whois.csv``.
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
    """Walk normalized who.is RDAP entities and their children."""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        yield entity
        yield from walk_whois_rdap_entities(entity.get("child_entities") or [])


def whois_rdap_entity_summary(entity: dict[str, Any]) -> str:
    """Format public contact data from a normalized who.is RDAP entity."""
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
    """Summarize who.is RDAP entities matching a role."""
    expected = {alias.lower() for alias in aliases}
    summaries: list[str] = []
    for entity in walk_whois_rdap_entities(data.get("entities") or []):
        roles = {str(role).lower() for role in (entity.get("roles") or [])}
        if roles.intersection(expected):
            summaries.append(
                whois_rdap_entity_summary(entity) or "Role present, details redacted"
            )
    return " ; ".join(dict.fromkeys(summaries)) if summaries else "Not published by who.is RDAP"


def get_whois_rdap_enrichment(
    domain: str, api_key: str, retries: int, delay: float
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Query the normalized who.is RDAP endpoint and extract its entities."""
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
        roles = ", ".join(sorted(entity.get("roles") or [])) or "unspecified"
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
    """Return the first who.is role summary matching the supplied aliases.

    Providers may use ``admin`` or ``administrative`` for the same role. This
    function makes that mapping explicit.
    """
    contacts = data.get("contacts") or {}
    if not isinstance(contacts, dict):
        return "Not published by who.is"
    lowered = {str(key).lower(): value for key, value in contacts.items()}
    for alias in aliases:
        value = lowered.get(alias.lower())
        if isinstance(value, list):
            summaries = [whois_contact_summary(item) for item in value]
            return " ; ".join(dict.fromkeys(summaries))
        if value:
            return whois_contact_summary(value)
    return "Not published by who.is"


def get_dnsdumpster_enrichment(
    domain: str, api_key: str, retries: int, delay: float
) -> tuple[
    set[str], list[dict[str, Any]], list[dict[str, Any]], dict[str, int]
]:
    """Query the official DNSDumpster API and normalize its records.

    Known response categories (A, MX, NS) contain hosts and IP lists already
    enriched with ASN, network owner, and country. The parser also accepts
    future categories using the same structure.
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
            # TXT/SPF entries are usually simple strings in the response.
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
                        "Statut": "Present",
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
                        "Statut": "Present",
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
    """Merge identical DNS observations from multiple sources.

    Present rows take precedence over ``Absent`` rows for the same check. When
    Google and DNSDumpster report the same value, both names are combined in
    the ``Source`` column.
    """
    present_checks = {
        (row["Domaine"], row["NomInterroge"], row["TypeDNS"], row["Categorie"])
        for row in rows
        if row.get("Statut") == "Present"
    }
    merged: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        check_key = (
            row["Domaine"], row["NomInterroge"], row["TypeDNS"], row["Categorie"]
        )
        if row.get("Statut") != "Present" and check_key in present_checks:
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
    """Validate a comma-separated list of TCP ports.

    Nmap ranges and expressions are intentionally rejected to keep the scope
    explicit and bounded.
    """
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item.isdigit():
            raise argparse.ArgumentTypeError(
                "Nmap ports must be comma-separated integers"
            )
        port = int(item)
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port out of range: {port}")
        ports.add(port)
    if not ports:
        raise argparse.ArgumentTypeError("at least one Nmap port is required")
    if len(ports) > 100:
        raise argparse.ArgumentTypeError("the bounded mode accepts at most 100 ports")
    return sorted(ports)


def parse_nmap_xml(ip: str, xml_text: str) -> list[dict[str, Any]]:
    """Convert Nmap XML output into CSV rows without retaining raw XML."""
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
                    "Analyse": "Bounded TCP connect; no version detection",
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
    """Run a bounded Nmap TCP connect scan without intrusive techniques.

    The profile excludes NSE scripts, version detection, OS detection, and UDP.
    IP addresses are processed sequentially.
    """
    executable = nmap_path or shutil.which("nmap")
    if not executable:
        raise RuntimeError(
            "Nmap was not found. Install it or use --nmap-path."
        )
    selected_ips = sorted(
        set(ips), key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value))
    )
    rows: list[dict[str, Any]] = []
    for index, ip in enumerate(selected_ips):
        if index >= max_ips:
            rows.append(
                {
                    "IP": ip, "HoteEtat": "skipped", "Protocole": "tcp",
                    "Port": "", "Etat": "not scanned", "Raison": "--nmap-max-ips limit reached",
                    "ServiceIndicatif": "", "Analyse": "No packet sent",
                }
            )
            continue
        address = ipaddress.ip_address(ip)
        if not include_private and not address.is_global:
            rows.append(
                {
                    "IP": ip, "HoteEtat": "skipped", "Protocole": "tcp",
                    "Port": "", "Etat": "not scanned", "Raison": "non-public IP",
                    "ServiceIndicatif": "", "Analyse": "No packet sent",
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
        print(f"Bounded Nmap scan {index + 1}/{min(len(selected_ips), max_ips)}: {ip}", flush=True)
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
                        "IP": ip, "HoteEtat": "unknown", "Protocole": "tcp",
                        "Port": "", "Etat": "error", "Raison": completed.stderr.strip()[:500],
                        "ServiceIndicatif": "", "Analyse": "Nmap returned no usable XML result",
                    }
                )
        except (subprocess.TimeoutExpired, ET.ParseError, OSError) as exc:
            rows.append(
                {
                    "IP": ip, "HoteEtat": "unknown", "Protocole": "tcp",
                    "Port": "", "Etat": "error", "Raison": str(exc)[:500],
                    "ServiceIndicatif": "", "Analyse": "Scan interrupted without retry",
                }
            )
    return rows


def resolve_name(name: str) -> dict[str, Any]:
    """Resolve a name to IPv4/IPv6 using the locally configured DNS resolver.

    ``socket.getaddrinfo`` follows CNAME records and returns final addresses. A
    DNS error is returned as data for the CSV instead of aborting the batch.
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
    """Enrich an IP address with its ASN, operator, and RDAP network.

    ``ipwho.is`` mainly supplies ASN/ISP/organization data, while RDAP supplies
    the network block holder. ``HebergeurProbable`` therefore identifies the
    apparent operator, which may be a CDN or reverse proxy.
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
    """Write an Excel-friendly CSV using UTF-8 BOM and semicolon delimiters."""
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def load_dnsdumpster_usage(state_file: Path, reported_today_count: int) -> int:
    """Load today's DNSDumpster counter.

    The user-supplied and local counters are compared, and the highest value is
    retained. This conservative choice avoids exceeding the quota when some
    requests were made outside this script.
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
    """Atomically store the number of attempted DNSDumpster requests.

    No API key or domain is stored in this state file.
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
    """Load the who.is credits counted for the current UTC month.

    The Free plan renews at the beginning of each UTC calendar month. As with
    DNSDumpster, the higher of the local and user-supplied counters is retained.
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
    """Atomically store the monthly who.is Free counter.

    The file contains no API key or domain. Not-found lookups are officially
    free but are counted locally as a precaution because the collection layer
    does not expose the HTTP status here.
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
    """Load, normalize, and deduplicate domains from user arguments."""
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
        print(f"WARNING: {len(invalid)} invalid input(s) ignored: {', '.join(invalid[:5])}", file=sys.stderr)
    return sorted(domains)


def load_yaml_config(path: Path, explicitly_requested: bool) -> dict[str, Any]:
    """Load a YAML file without ever logging sensitive content.

    The default ``config.yaml`` file is optional. A path explicitly supplied
    with ``--config`` must exist, preventing a typo from silently running a
    different configuration.
    """
    if not path.exists():
        if explicitly_requested:
            raise ValueError(f"configuration file not found: {path}")
        return {}
    if yaml is None:
        raise ValueError(
            "PyYAML is required to read the configuration: "
            "python -m pip install -r requirements.txt"
        )
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"invalid YAML configuration ({path}): {exc}") from exc
    if document is None:
        return {}
    if not isinstance(document, dict):
        raise ValueError("the YAML document root must be a mapping")
    return document


def config_section(config: dict[str, Any], name: str) -> dict[str, Any]:
    """Return a YAML section and reject ambiguous types."""
    value = config.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"YAML section '{name}' must be a mapping")
    return value


def string_list(value: Any, field: str, pattern: str) -> tuple[str, ...]:
    """Validate a YAML list of short, deduplicated strings."""
    if not isinstance(value, list) or not value:
        raise ValueError(f"'{field}' must be a non-empty YAML list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not re.fullmatch(pattern, item.strip().lower()):
            raise ValueError(f"invalid value in '{field}': {item!r}")
        normalized = item.strip().lower()
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def apply_yaml_config(config: dict[str, Any]) -> dict[str, str]:
    """Apply configurable constants and return API keys from YAML."""
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
            raise ValueError("'http.user_agent' must contain 1 to 256 characters")
        USER_AGENT = user_agent.strip()

    if "domain_regex" in validation:
        pattern = validation["domain_regex"]
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("'validation.domain_regex' must be a non-empty string")
        try:
            DOMAIN_RE = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"'validation.domain_regex' is invalid: {exc}") from exc

    if "provider_regex" in cdn:
        pattern = cdn["provider_regex"]
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("'cdn.provider_regex' must be a non-empty string")
        try:
            CDN_RE = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"'cdn.provider_regex' is invalid: {exc}") from exc

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
            raise ValueError("'nmap.ports' must be a YAML list")
        DEFAULT_NMAP_PORTS = tuple(parse_port_list(",".join(str(port) for port in ports)))

    result: dict[str, str] = {}
    for field in ("dnsdumpster", "whois"):
        value = api_keys.get(field, "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError(f"'api_keys.{field}' must be a string")
        result[field] = value.strip()
    return result


def main() -> int:
    """Parse options, orchestrate collection, and write deliverables."""
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

    parser = argparse.ArgumentParser(description="Passive domain inventory")
    parser.add_argument(
        "--config",
        default=str(config_path),
        help="YAML configuration file (default: ./config.yaml when present)",
    )
    parser.add_argument("--input", "-i", help="Text file containing one domain per line")
    parser.add_argument("--domain", "-d", action="append", help="Domain (repeatable option)")
    parser.add_argument("--output", "-o", default=f"domain-inventory-{datetime.now():%Y%m%d-%H%M%S}")
    parser.add_argument("--workers", type=int, default=12, help="Parallel DNS resolutions (default: 12)")
    parser.add_argument("--delay", type=float, default=0.35, help="Delay between IP attribution calls")
    parser.add_argument("--retries", type=int, default=3, help="HTTP attempts (default: 3)")
    parser.add_argument(
        "--dkim-selector",
        action="append",
        dest="dkim_selectors",
        help=(
            "DKIM selector to test (repeatable option). Without it, "
            "several common selectors are tested."
        ),
    )
    parser.add_argument(
        "--dnsdumpster-daily-quota",
        type=int,
        default=50,
        help="DNSDumpster account daily quota (Free User default: 50)",
    )
    parser.add_argument(
        "--dnsdumpster-today-count",
        type=int,
        default=0,
        help="DNSDumpster requests already used today (default: 0)",
    )
    parser.add_argument(
        "--dnsdumpster-state-file",
        default=str(default_state_directory() / "dnsdumpster-usage.json"),
        help="Persistent local DNSDumpster counter file",
    )
    parser.add_argument(
        "--whois-monthly-quota",
        type=int,
        default=500,
        help="Monthly who.is credits (Free plan default: 500)",
    )
    parser.add_argument(
        "--whois-month-count",
        type=int,
        default=0,
        help="who.is credits already used this month (default: 0)",
    )
    parser.add_argument(
        "--whois-state-file",
        default=str(default_state_directory() / "whois-usage.json"),
        help="Persistent local who.is counter file",
    )
    parser.add_argument(
        "--whois-source",
        choices=("whois", "rdap", "both"),
        default="whois",
        help=(
            "who.is endpoint(s): whois (1 credit/domain), "
            "rdap (1 credit/domain), or both (2 credits/domain)"
        ),
    )
    parser.add_argument(
        "--nmap",
        action="store_true",
        help=(
            "Enable the bounded Nmap TCP connect scan. Use only on "
            "IP addresses you are authorized to audit."
        ),
    )
    parser.add_argument(
        "--nmap-ports",
        type=parse_port_list,
        default=",".join(str(port) for port in DEFAULT_NMAP_PORTS),
        help="Comma-separated TCP ports (100 maximum)",
    )
    parser.add_argument(
        "--nmap-path",
        help="Explicit Nmap executable path when absent from PATH",
    )
    parser.add_argument(
        "--nmap-max-ips",
        type=int,
        default=256,
        help="Maximum IP addresses scanned per run (default: 256)",
    )
    parser.add_argument(
        "--nmap-include-private",
        action="store_true",
        help="Also allow discovered private/non-global IP addresses",
    )
    args = parser.parse_args()

    # An environment variable overrides YAML. Keys are never written to CSV
    # files, the summary, or program logs.
    dnsdumpster_api_key = os.environ.get(
        "DNSDUMPSTER_API_KEY", yaml_api_keys["dnsdumpster"]
    ).strip()
    whois_api_key = os.environ.get("WHOIS_API_KEY", yaml_api_keys["whois"]).strip()

    if not args.input and not args.domain:
        parser.error("use --input or at least one --domain")
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
        parser.error("invalid workers/retries/delay parameters")

    domains = load_domains(args)
    if not domains:
        parser.error("no valid domain")

    # All outputs from one run are grouped in a single directory.
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
        parser.error("no valid DKIM selector")

    print(
        "Optional sources: "
        f"DNSDumpster={'enabled' if dnsdumpster_api_key else 'disabled (missing key)'}, "
        f"who.is={'enabled' if whois_api_key else 'disabled (missing key)'}",
        flush=True,
    )
    if dnsdumpster_api_key:
        print(
            "DNSDumpster Free User: "
            f"{dnsdumpster_usage}/{args.dnsdumpster_daily_quota} request(s) "
            "already counted today.",
            flush=True,
        )
    if whois_api_key:
        print(
            "who.is Free: "
            f"{whois_usage}/{args.whois_monthly_quota} credit(s) "
            "counted for the UTC month.",
            flush=True,
        )

    # Stage 1: RDAP metadata/contacts and passive name discovery.
    for root in domains:
        print(f"[{root}] RDAP et Certificate Transparency...", flush=True)
        rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(root)}"
        rdap = http_json(rdap_url, args.retries, args.delay, "domain RDAP")
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
                            "WARNING: monthly who.is quota reached; remaining "
                            "who.is calls are skipped.",
                            file=sys.stderr,
                        )
                    continue

                # Each WHOIS or RDAP lookup costs one credit. Persist the counter
                # before the call so it survives an interruption.
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

                # Official response headers replace the local estimate.
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
                # Free-plan limit: one request per second.
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
                    "who.is source not queried (quota reached)"
                    if whois_api_key else "who.is source disabled"
                ),
                "ContactFacturationWhois": whois_role_summary(
                    whois_data, ("billing", "bill")
                ) if whois_queried else (
                    "who.is source not queried (quota reached)"
                    if whois_api_key else "who.is source disabled"
                ),
                "ContactAdministratifWhoisRdap": whois_rdap_role_summary(
                    whois_rdap_data, ("administrative", "admin")
                ) if whois_rdap_queried else (
                    "who.is RDAP mode not selected"
                    if args.whois_source == "whois"
                    else (
                        "who.is RDAP source not queried (quota reached)"
                        if whois_api_key else "who.is source disabled"
                    )
                ),
                "ContactFacturationWhoisRdap": whois_rdap_role_summary(
                    whois_rdap_data, ("billing", "bill")
                ) if whois_rdap_queried else (
                    "who.is RDAP mode not selected"
                    if args.whois_source == "whois"
                    else (
                        "who.is RDAP source not queried (quota reached)"
                        if whois_api_key else "who.is source disabled"
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
                "root domain" if name == root else "crt.sh"
            )
        if dnsdumpster_api_key and dnsdumpster_usage < args.dnsdumpster_daily_quota:
            # Increment before the call so local tracking remains conservative
            # even if the process is interrupted or the API fails.
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
                # No automatic retry for this source: another
                # attempt could consume an additional quota unit.
                root, dnsdumpster_api_key, 1, args.delay
            )
            # DNSDumpster does not document a quota endpoint. If the API
            # Standard response headers take precedence when provided.
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
            # Official limit: no more than one request every two seconds.
            time.sleep(max(2.0, args.delay))
        elif dnsdumpster_api_key:
            dnsdumpster_skipped_quota += 1
            if dnsdumpster_skipped_quota == 1:
                print(
                    "WARNING: daily DNSDumpster quota reached; this source is "
                    "skipped for the remaining domains.",
                    file=sys.stderr,
                )
        # Explicitly add requested common names even when absent from
        # certificate logs and DNSDumpster.
        for prefix in COMMON_SUBDOMAIN_PREFIXES:
            source_map.setdefault(f"{prefix}.{root}", set()).add(
                "common subdomain test"
            )
        discovered_by_root[root] = source_map

        print(f"[{root}] DNS and email checks...", flush=True)
        domain_dns_rows.extend(
            collect_domain_dns_records(
                root, dkim_selectors, args.retries, args.delay, args.workers
            )
        )
        time.sleep(args.delay)

    # Combine Google and DNSDumpster observations in one table.
    domain_dns_rows = consolidate_dns_records(domain_dns_rows)

    # A name may belong to multiple requested domains in redundant lists. This
    # table ensures only one DNS resolution per unique name.
    owner_by_name: dict[str, set[str]] = {}
    for root, source_map in discovered_by_root.items():
        for name in source_map:
            owner_by_name.setdefault(name, set()).add(root)

    # Stage 2: independent DNS resolutions are parallelized.
    print(f"Resolving DNS for {len(owner_by_name)} name(s)...", flush=True)
    resolved: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(resolve_name, name): name for name in owner_by_name}
        for future in as_completed(futures):
            result = future.result()
            resolved[result["name"]] = result

    # A random name detects possible wildcard DNS. If this nonexistent name
    # resolves, common subdomains returning the same IPs require caution.
    wildcard_ips_by_root: dict[str, set[str]] = {}
    for root in domains:
        probe_name = f"codex-wildcard-check-{secrets.token_hex(6)}.{root}"
        probe = resolve_name(probe_name)
        wildcard_ips_by_root[root] = {
            ip for _, ip in probe["addresses"]
        }

    # Stage 3: convert DNS responses into CSV rows and build a unique IP set to
    # avoid enriching the same address more than once.
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
                        "StatutDNS": "Unresolved",
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
                    "common subdomain test"
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
                        "StatutDNS": "Resolved",
                        "ErreurDNS": "",
                        "WildcardDNSProbable": wildcard_probable,
                        "Commentaire": (
                            "Same IP as a random nonexistent name; actual service not confirmed"
                            if wildcard_probable else ""
                        ),
                        "SourceSousDomaine": ", ".join(
                            sorted(discovered_by_root[root][name])
                        ),
                    }
                )

    # Stage 4: sequential IP attribution. The delay reduces the risk of
    # rate limiting by public services.
    ip_rows: list[dict[str, Any]] = []
    for index, ip in enumerate(sorted(unique_ips, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))):
        print(f"Attribution IP {index + 1}/{len(unique_ips)}: {ip}", flush=True)
        ip_rows.append(ip_attribution(ip, args.retries, args.delay))
        if index + 1 < len(unique_ips):
            time.sleep(args.delay)

    # Optional stage: no scan is performed unless --nmap is supplied.
    nmap_rows: list[dict[str, Any]] = []
    if args.nmap:
        print(
            "Nmap enabled: TCP connect only, bounded ports, no scripts, "
            "no version or OS detection.",
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
            print(f"WARNING: {exc}", file=sys.stderr)
            nmap_rows = [
                {
                    "IP": "", "HoteEtat": "not executed", "Protocole": "tcp",
                    "Port": "", "Etat": "error", "Raison": str(exc),
                    "ServiceIndicatif": "", "Analyse": "No packet sent",
                }
            ]

    # Stage 5: write the eight tables and the execution summary.
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
        "mode": "passive collection and bounded Nmap scan" if args.nmap else "passive collection only",
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
            "Contacts may be redacted; subdomains found in certificate "
            "logs are not exhaustive; hosting is a probable attribution "
            "of the IP and may be a CDN or proxy."
        ),
    }
    (output / "resume.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Completed. Results: {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
