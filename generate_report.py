#!/usr/bin/env python3
"""Build a self-contained HTML report from Domain Inventory output files.

The generator is intentionally independent from the collection script. It reads
an existing output directory, never performs network requests, and never alters
the source CSV or JSON files.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


EXPECTED_FILES = (
    "domaines.csv",
    "contacts-rdap.csv",
    "contacts-whois.csv",
    "dnsdumpster.csv",
    "enregistrements-dns.csv",
    "sous-domaines-dns.csv",
    "adresses-ip.csv",
    "nmap.csv",
    "inventaire-global.csv",
)

TEXT = {
    "fr": {
        "title": "Rapport d’inventaire de domaines",
        "generated": "Rapport généré le",
        "source": "Dossier source",
        "overview": "Synthèse",
        "domains": "Domaines demandés",
        "names": "Noms découverts",
        "ips": "Adresses IP uniques",
        "rdap_contacts": "Contacts RDAP publics",
        "whois_contacts": "Contacts who.is publics",
        "dns_checks": "Contrôles DNS",
        "nmap_results": "Résultats Nmap",
        "open_ports": "Ports ouverts observés",
        "missing": "Fichiers absents",
        "missing_none": "Aucun fichier attendu n’est absent.",
        "method": "Périmètre et méthode",
        "summary_details": "Détails du résumé d’exécution",
        "no_data": "Aucune donnée disponible.",
        "rows": "ligne(s)",
        "file": "Fichier",
        "value": "Valeur",
        "field": "Champ",
        "status": "Statut",
        "available": "Disponible",
        "absent": "Absent",
        "sections": {
            "domaines.csv": "Domaines et informations d’enregistrement",
            "contacts-rdap.csv": "Contacts RDAP",
            "contacts-whois.csv": "Contacts who.is",
            "dnsdumpster.csv": "Enrichissement DNSDumpster",
            "enregistrements-dns.csv": "Enregistrements DNS et messagerie",
            "sous-domaines-dns.csv": "Sous-domaines et résolution DNS",
            "adresses-ip.csv": "Adresses IP et hébergeurs probables",
            "nmap.csv": "Analyse Nmap limitée",
            "inventaire-global.csv": "Inventaire global consolidé",
        },
        "descriptions": {
            "domaines.csv": "Registrar, dates, statuts, serveurs DNS et synthèses de contacts.",
            "contacts-rdap.csv": "Entités et rôles publiés par les services RDAP.",
            "contacts-whois.csv": "Contacts normalisés renvoyés par les endpoints who.is activés.",
            "dnsdumpster.csv": "Hôtes et données réseau renvoyés par DNSDumpster.",
            "enregistrements-dns.csv": "Résultats MX, TXT/SPF, NS, CNAME, AAAA, DMARC et DKIM.",
            "sous-domaines-dns.csv": "Noms découverts ou testés, adresses résolues et indicateur wildcard.",
            "adresses-ip.csv": "ASN, opérateur, pays et attribution probable de l’hébergement.",
            "nmap.csv": "États des ports du scan TCP connect borné, lorsqu’il était activé.",
            "inventaire-global.csv": "Vue dénormalisée par domaine, sous-domaine, IP et port Nmap.",
        },
        "notice": (
            "Les informations proviennent de sources publiques et peuvent être incomplètes, "
            "masquées ou obsolètes. Une attribution d’hébergeur peut désigner un CDN, un "
            "reverse proxy ou l’opérateur apparent de l’adresse IP."
        ),
    },
    "en": {
        "title": "Domain inventory report",
        "generated": "Report generated on",
        "source": "Source directory",
        "overview": "Overview",
        "domains": "Requested domains",
        "names": "Discovered names",
        "ips": "Unique IP addresses",
        "rdap_contacts": "Public RDAP contacts",
        "whois_contacts": "Public who.is contacts",
        "dns_checks": "DNS checks",
        "nmap_results": "Nmap results",
        "open_ports": "Observed open ports",
        "missing": "Missing files",
        "missing_none": "No expected file is missing.",
        "method": "Scope and method",
        "summary_details": "Execution summary details",
        "no_data": "No data available.",
        "rows": "row(s)",
        "file": "File",
        "value": "Value",
        "field": "Field",
        "status": "Status",
        "available": "Available",
        "absent": "Missing",
        "sections": {
            "domaines.csv": "Domains and registration information",
            "contacts-rdap.csv": "RDAP contacts",
            "contacts-whois.csv": "who.is contacts",
            "dnsdumpster.csv": "DNSDumpster enrichment",
            "enregistrements-dns.csv": "DNS and email records",
            "sous-domaines-dns.csv": "Subdomains and DNS resolution",
            "adresses-ip.csv": "IP addresses and probable hosting providers",
            "nmap.csv": "Bounded Nmap analysis",
            "inventaire-global.csv": "Consolidated global inventory",
        },
        "descriptions": {
            "domaines.csv": "Registrar, dates, statuses, name servers, and contact summaries.",
            "contacts-rdap.csv": "Entities and roles published by RDAP services.",
            "contacts-whois.csv": "Normalized contacts returned by enabled who.is endpoints.",
            "dnsdumpster.csv": "Hosts and network data returned by DNSDumpster.",
            "enregistrements-dns.csv": "MX, TXT/SPF, NS, CNAME, AAAA, DMARC, and DKIM results.",
            "sous-domaines-dns.csv": "Discovered or tested names, resolved addresses, and wildcard indicator.",
            "adresses-ip.csv": "ASN, operator, country, and probable hosting attribution.",
            "nmap.csv": "Port states from the bounded TCP connect scan, when enabled.",
            "inventaire-global.csv": "Denormalized view by domain, subdomain, IP address, and Nmap port.",
        },
        "notice": (
            "Information comes from public sources and may be incomplete, redacted, or stale. "
            "A hosting attribution may identify a CDN, reverse proxy, or the apparent operator "
            "of the IP address."
        ),
    },
}


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Read a semicolon-delimited UTF-8 CSV and preserve its column order."""
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=";")
        fields = list(reader.fieldnames or [])
        return fields, [dict(row) for row in reader]


def read_summary(path: Path) -> dict[str, Any]:
    """Read the execution summary and reject a non-object JSON root."""
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"The JSON root in {path} must be an object")
    return value


def scalar(value: Any) -> str:
    """Format a JSON value for a compact report cell."""
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(scalar(item) for item in value) or "—"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = str(value).strip()
    return text or "—"


def escape(value: Any) -> str:
    """HTML-escape a scalar value."""
    return html.escape(scalar(value), quote=True)


def table_html(fields: Iterable[str], rows: list[dict[str, Any]], no_data: str) -> str:
    """Render a complete, scrollable HTML table."""
    columns = list(fields)
    if not columns or not rows:
        return f'<p class="empty">{html.escape(no_data)}</p>'
    head = "".join(f"<th>{escape(field)}</th>" for field in columns)
    body = []
    for row in rows:
        cells = "".join(f"<td>{escape(row.get(field, ''))}</td>" for field in columns)
        body.append(f"<tr>{cells}</tr>")
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def count(summary: dict[str, Any], key: str, fallback: int) -> int | str:
    """Use a numeric summary value when present, otherwise use a row count."""
    value = summary.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else fallback


def build_report(input_dir: Path, language: str) -> str:
    """Load all known outputs and return a self-contained HTML document."""
    tr = TEXT[language]
    summary = read_summary(input_dir / "resume.json")
    datasets = {name: read_csv(input_dir / name) for name in EXPECTED_FILES}
    missing = [name for name in ("resume.json", *EXPECTED_FILES) if not (input_dir / name).exists()]

    domain_rows = datasets["domaines.csv"][1]
    rdap_rows = datasets["contacts-rdap.csv"][1]
    whois_rows = datasets["contacts-whois.csv"][1]
    dns_rows = datasets["enregistrements-dns.csv"][1]
    ip_rows = datasets["adresses-ip.csv"][1]
    nmap_rows = datasets["nmap.csv"][1]
    open_ports = [row for row in nmap_rows if str(row.get("Etat", "")).lower() == "open"]

    cards = (
        (tr["domains"], count(summary, "domaines_demandes", len(domain_rows))),
        (tr["names"], count(summary, "noms_decouverts", len(datasets["sous-domaines-dns.csv"][1]))),
        (tr["ips"], count(summary, "adresses_ip_uniques", len(ip_rows))),
        (tr["rdap_contacts"], count(summary, "contacts_rdap_publics", len(rdap_rows))),
        (tr["whois_contacts"], count(summary, "contacts_whois_publics", len(whois_rows))),
        (tr["dns_checks"], count(summary, "controles_dns", len(dns_rows))),
        (tr["nmap_results"], count(summary, "nmap_resultats", len(nmap_rows))),
        (tr["open_ports"], len(open_ports)),
    )
    cards_html = "".join(
        f'<div class="card"><span>{escape(label)}</span><strong>{escape(value)}</strong></div>'
        for label, value in cards
    )

    file_status_rows = [
        {
            tr["file"]: name,
            tr["status"]: tr["available"] if (input_dir / name).exists() else tr["absent"],
            tr["value"]: len(datasets[name][1]) if name in datasets else "—",
        }
        for name in ("resume.json", *EXPECTED_FILES)
    ]
    missing_html = (
        f'<ul class="warning">{"".join(f"<li>{escape(name)}</li>" for name in missing)}</ul>'
        if missing
        else f'<p class="ok">{escape(tr["missing_none"])}</p>'
    )

    summary_rows = [{tr["field"]: key, tr["value"]: scalar(value)} for key, value in summary.items()]
    sections = []
    for filename in EXPECTED_FILES:
        fields, rows = datasets[filename]
        sections.append(
            f'<section id="{html.escape(filename)}">'
            f'<h2>{escape(tr["sections"][filename])}</h2>'
            f'<p>{escape(tr["descriptions"][filename])} '
            f'<span class="badge">{len(rows)} {escape(tr["rows"])}</span></p>'
            f'{table_html(fields, rows, tr["no_data"])}</section>'
        )

    generated = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    css = """
    :root { color-scheme: light; --ink:#162033; --muted:#607089; --line:#d8e0eb;
      --accent:#165d9c; --accent2:#e9f3fc; --warn:#fff4dd; --ok:#e8f7ee; }
    * { box-sizing: border-box; }
    body { margin:0; font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;
      color:var(--ink); background:#f3f6fa; }
    header { color:white; padding:34px max(24px,calc((100% - 1480px)/2));
      background:linear-gradient(120deg,#123d67,#1671b8); }
    header h1 { margin:0 0 8px; font-size:30px; } header p { margin:3px 0; opacity:.9; }
    main { max-width:1480px; margin:0 auto; padding:24px; }
    section { background:white; border:1px solid var(--line); border-radius:10px;
      padding:20px; margin:0 0 20px; box-shadow:0 2px 8px #26374f0d; }
    h2 { color:#123d67; margin:0 0 8px; font-size:21px; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(175px,1fr)); gap:12px; }
    .card { background:var(--accent2); border-left:4px solid var(--accent); padding:14px;
      border-radius:7px; display:flex; flex-direction:column; gap:5px; }
    .card span { color:var(--muted); } .card strong { font-size:25px; color:#123d67; }
    .table-wrap { overflow:auto; max-height:620px; border:1px solid var(--line); border-radius:7px; }
    table { border-collapse:collapse; width:100%; font-size:12px; }
    th,td { padding:8px 10px; text-align:left; vertical-align:top; border-bottom:1px solid var(--line);
      white-space:pre-wrap; overflow-wrap:anywhere; max-width:440px; }
    th { position:sticky; top:0; z-index:1; color:white; background:#244e77; white-space:nowrap; }
    tbody tr:nth-child(even) { background:#f7f9fc; } tbody tr:hover { background:#edf5fc; }
    .badge { display:inline-block; margin-left:6px; padding:2px 7px; border-radius:999px;
      color:#244e77; background:var(--accent2); font-size:11px; }
    .warning { background:var(--warn); padding:12px 12px 12px 32px; border-radius:7px; }
    .ok { background:var(--ok); padding:12px; border-radius:7px; }
    .empty { color:var(--muted); font-style:italic; }
    footer { max-width:1480px; margin:0 auto; padding:0 24px 28px; color:var(--muted); }
    @media print { body{background:white;font-size:10px} header{padding:16px;color:black;background:white;
      border-bottom:2px solid #333} main{max-width:none;padding:10px} section{box-shadow:none;break-inside:avoid;
      padding:10px;margin-bottom:10px}.table-wrap{overflow:visible;max-height:none}th{position:static;color:black;background:#ddd}
      .cards{grid-template-columns:repeat(4,1fr)} }
    """
    return f"""<!doctype html>
<html lang="{language}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(tr['title'])}</title><style>{css}</style></head>
<body><header><h1>{escape(tr['title'])}</h1>
<p>{escape(tr['generated'])} {escape(generated)}</p>
<p>{escape(tr['source'])}: <code>{escape(input_dir)}</code></p></header>
<main><section><h2>{escape(tr['overview'])}</h2><div class="cards">{cards_html}</div></section>
<section><h2>{escape(tr['missing'])}</h2>{missing_html}
{table_html(file_status_rows[0].keys(), file_status_rows, tr['no_data'])}</section>
<section><h2>{escape(tr['method'])}</h2><p>{escape(tr['notice'])}</p></section>
<section><h2>{escape(tr['summary_details'])}</h2>
{table_html((tr['field'], tr['value']), summary_rows, tr['no_data'])}</section>
{''.join(sections)}</main><footer>{escape(tr['title'])}</footer></body></html>"""


def main() -> int:
    """Parse CLI arguments and write the report atomically."""
    parser = argparse.ArgumentParser(
        description="Generate a complete HTML report from Domain Inventory outputs"
    )
    parser.add_argument("--input-dir", "-i", required=True, help="Directory containing CSV and resume.json files")
    parser.add_argument("--output", "-o", help="HTML output path (default: <input-dir>/report.html)")
    parser.add_argument("--language", choices=("fr", "en"), default="fr", help="Report language (default: fr)")
    args = parser.parse_args()

    input_dir = Path(args.input_dir).expanduser().resolve()
    if not input_dir.is_dir():
        parser.error(f"input directory not found: {input_dir}")
    output = Path(args.output).expanduser().resolve() if args.output else input_dir / "report.html"
    if output.exists() and output.is_dir():
        parser.error(f"output path is a directory: {output}")

    try:
        document = build_report(input_dir, args.language)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(document, encoding="utf-8")
        temporary.replace(output)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Report generated: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
