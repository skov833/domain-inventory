"""Build the denormalized global CSV from normalized inventory datasets."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable


GLOBAL_FIELDS = [
    "DomaineRacine",
    "Registrar",
    "ContactAdministratif",
    "SousDomaine",
    "Type",
    "Resolu",
    "SourceSousDomaine",
    "AdresseIP",
    "Organisation",
    "ISP",
    "HebergeurProbable",
    "CDNouProxy",
    "SourceAttribution",
    "HoteEtat",
    "Port",
    "Etat",
]


def _text(value: Any) -> str:
    """Normalize a cell value without changing its human-readable content."""
    return "" if value is None else str(value).strip()


def _admin_contacts(rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    """Aggregate administrative who.is contacts per root domain."""
    by_domain: dict[str, list[str]] = {}
    for row in rows:
        roles = {
            role.strip().casefold()
            for role in _text(row.get("Role")).replace(";", ",").split(",")
            if role.strip()
        }
        if not roles.intersection({"admin", "administrative"}):
            continue
        domain = _text(row.get("Domaine"))
        if not domain:
            continue
        parts = [
            _text(row.get("Nom")),
            _text(row.get("Organisation")),
            _text(row.get("Email")),
            _text(row.get("Telephone")),
        ]
        summary = " | ".join(part for part in parts if part)
        if summary and summary not in by_domain.setdefault(domain, []):
            by_domain[domain].append(summary)
    return {domain: " ; ".join(values) for domain, values in by_domain.items()}


def build_global_rows(
    domain_rows: Iterable[dict[str, Any]],
    whois_contact_rows: Iterable[dict[str, Any]],
    subdomain_rows: Iterable[dict[str, Any]],
    ip_rows: Iterable[dict[str, Any]],
    nmap_rows: Iterable[dict[str, Any]],
) -> list[dict[str, str]]:
    """Join normalized datasets at domain, subdomain, IP, and Nmap-port grain."""
    domains = {
        _text(row.get("Domaine")): row
        for row in domain_rows
        if _text(row.get("Domaine"))
    }
    admins = _admin_contacts(whois_contact_rows)
    ips = {
        _text(row.get("IP")): row
        for row in ip_rows
        if _text(row.get("IP"))
    }
    nmap_by_ip: dict[str, list[dict[str, Any]]] = {}
    for row in nmap_rows:
        ip = _text(row.get("IP"))
        if ip:
            nmap_by_ip.setdefault(ip, []).append(row)

    result: list[dict[str, str]] = []
    seen: set[tuple[str, ...]] = set()
    sorted_subdomains = sorted(
        subdomain_rows,
        key=lambda row: (
            _text(row.get("DomaineRacine")),
            _text(row.get("Nom")),
            _text(row.get("Type")),
            _text(row.get("IP")),
        ),
    )
    for subdomain in sorted_subdomains:
        root = _text(subdomain.get("DomaineRacine"))
        ip = _text(subdomain.get("IP"))
        domain = domains.get(root, {})
        attribution = ips.get(ip, {})
        scans = nmap_by_ip.get(ip) or [{}]
        for scan in sorted(
            scans,
            key=lambda row: (
                _text(row.get("Protocole")),
                int(_text(row.get("Port"))) if _text(row.get("Port")).isdigit() else 0,
            ),
        ):
            row = {
                "DomaineRacine": root,
                "Registrar": _text(domain.get("Registrar")),
                "ContactAdministratif": admins.get(root, ""),
                "SousDomaine": _text(subdomain.get("Nom")),
                "Type": _text(subdomain.get("Type")),
                "Resolu": _text(subdomain.get("StatutDNS")),
                "SourceSousDomaine": _text(subdomain.get("SourceSousDomaine")),
                "AdresseIP": ip,
                "Organisation": _text(attribution.get("Organisation")),
                "ISP": _text(attribution.get("ISP")),
                "HebergeurProbable": _text(attribution.get("HebergeurProbable")),
                "CDNouProxy": _text(attribution.get("CdnOuProxyProbable")),
                "SourceAttribution": _text(attribution.get("SourceAttribution")),
                "HoteEtat": _text(scan.get("HoteEtat")),
                "Port": _text(scan.get("Port")),
                "Etat": _text(scan.get("Etat")),
            }
            identity = tuple(row[field].casefold() for field in GLOBAL_FIELDS)
            if identity not in seen:
                result.append(row)
                seen.add(identity)
    return result


def write_global_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    """Atomically write the denormalized global CSV."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=GLOBAL_FIELDS, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)
