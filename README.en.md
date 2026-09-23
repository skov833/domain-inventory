# Passive Domain Inventory — Python

Documentation française : [README.md](README.md). Script français :
[`domain_inventory.py`](domain_inventory.py).

`domain_inventory_en.py` collects public domain, contact, DNS, subdomain, IP,
and network-operator information. It can optionally run a bounded TCP connect
Nmap scan against discovered IP addresses.

The French and English scripts provide the same collection features and accept
the same command-line options. The English version keeps the established CSV
filenames and column names so existing integrations remain compatible, while
its source comments, docstrings, command-line help, warnings, and progress
messages are in English.

## Requirements

- Python 3.10 or newer;
- PyYAML 6.x;
- outbound HTTPS access to the enabled services;
- outbound DNS access;
- Nmap only when `--nmap` is enabled.

The passive sources include `rdap.org`, `crt.sh`, `dns.google`, and `ipwho.is`.
DNSDumpster and who.is are optional and require personal API keys.

## Installation on Windows

In PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
```

Install Nmap for Windows only if you intend to use `--nmap`. Ensure `nmap.exe`
is in `PATH`, or provide its location through `--nmap-path`.

## Installation on Debian/Linux

Using Debian packages:

```bash
sudo apt update
sudo apt install python3 python3-yaml ca-certificates
```

Install Nmap only when needed:

```bash
sudo apt install nmap
```

Alternatively, use an isolated Python environment:

```bash
sudo apt install python3 python3-venv ca-certificates
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Do not use `sudo pip install`. Use Debian's `python3-yaml` package or a virtual
environment. Official package references: [python3-yaml](https://packages.debian.org/stable/python/python3-yaml)
and [nmap](https://packages.debian.org/stable/nmap).

## Basic usage

Put one domain per line in `domains.txt`.

Windows:

```powershell
python .\domain_inventory_en.py --input .\domains.txt --output .\results
```

Debian/Linux:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results
```

For one or more domains without an input file:

```bash
python3 ./domain_inventory_en.py --domain example.com --domain example.org
```

Useful options include `--workers 12`, `--delay 0.35`, and `--retries 3`.

## YAML configuration

Copy the provided example before editing it.

Windows:

```powershell
Copy-Item .\config.example.yaml .\config.yaml
python .\domain_inventory_en.py --config .\config.yaml --input .\domains.txt
```

Debian/Linux:

```bash
cp ./config.example.yaml ./config.yaml
chmod 600 ./config.yaml
python3 ./domain_inventory_en.py --config ./config.yaml --input ./domains.txt
```

The default path is `config.yaml` in the current directory. The file is
optional; built-in values remain active when it does not exist. Use `--config`
to select another file.

The YAML configuration controls:

- the HTTP user agent;
- the domain validation regular expression;
- the CDN/reverse-proxy detection expression;
- common subdomain prefixes;
- default DKIM selectors;
- default Nmap ports;
- DNSDumpster and who.is API keys.

Minimal API-key section:

```yaml
api_keys:
  dnsdumpster: "your_dnsdumpster_key"
  whois: "your_whois_key"
```

`config.yaml` and `config.local.yaml` are ignored by Git. Never put real keys in
the tracked `config.example.yaml`. On Linux, protect a local secret-bearing file
with `chmod 600 config.yaml`.

Configuration precedence is:

1. command-line option, when an equivalent option exists;
2. environment variable for API keys;
3. YAML value;
4. built-in default.

## API keys through environment variables

Environment variables override YAML keys.

Windows PowerShell:

```powershell
$env:DNSDUMPSTER_API_KEY = "your_dnsdumpster_key"
$env:WHOIS_API_KEY = "your_whois_key"
python .\domain_inventory_en.py --input .\domains.txt --output .\results
Remove-Item Env:DNSDUMPSTER_API_KEY
Remove-Item Env:WHOIS_API_KEY
```

Bash/Linux:

```bash
export DNSDUMPSTER_API_KEY="your_dnsdumpster_key"
export WHOIS_API_KEY="your_whois_key"
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results
unset DNSDUMPSTER_API_KEY WHOIS_API_KEY
```

Keys are not written to CSV files, the JSON summary, or normal program logs.

## Quota tracking

The DNSDumpster Free User defaults are 50 requests per day with no more than
one request every two seconds. The who.is Free defaults are 500 credits per UTC
calendar month and one request per second.

Persistent counters are stored at:

- Windows: `%LOCALAPPDATA%\DomainInventory\dnsdumpster-usage.json` and
  `%LOCALAPPDATA%\DomainInventory\whois-usage.json`;
- Linux: `~/.domain-inventory/dnsdumpster-usage.json` and
  `~/.domain-inventory/whois-usage.json`.

Counter files contain no API key or domain. Provide dashboard usage when calls
were made from another tool:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --dnsdumpster-today-count 17
python3 ./domain_inventory_en.py --input ./domains.txt --whois-month-count 125
```

The higher of the supplied and persistent counters is retained. API rate-limit
headers take precedence when available.

## who.is modes

`--whois-source` accepts:

- `whois` — `/v1/whois/{domain}`, one credit per domain;
- `rdap` — `/v1/rdap/{domain}`, one credit per domain;
- `both` — WHOIS followed by RDAP, up to two credits per domain.

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --whois-source both
```

The script checks the remaining local quota before every endpoint call.

## DNS and email checks

For every domain, Google Public DNS over HTTPS is queried for:

- MX;
- TXT and SPF;
- CNAME;
- AAAA;
- DMARC at `_dmarc.<domain>`;
- DKIM using common configurable selectors.

DKIM selectors cannot be discovered generically through DNS. Override the
defaults by repeating `--dkim-selector`:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt \
  --dkim-selector selector1 \
  --dkim-selector selector2 \
  --dkim-selector custom-selector
```

The common names `ftp`, `mail`, `www`, `webmail`, `ns1`, and `ns2` are resolved
by default. A random nonexistent name is also resolved to detect wildcard DNS.

## Optional bounded Nmap scan

Nmap is disabled by default. Enable it only for IP addresses you own or are
explicitly authorized to audit:

```bash
python3 ./domain_inventory_en.py --input ./domains.txt --output ./results --nmap
```

The profile is intentionally bounded:

- TCP connect (`-sT`) only;
- 18 common TCP ports by default;
- `-T3` timing and a 50 ms scan delay;
- one retry at most;
- 30-second host timeout;
- no version detection, OS detection, NSE scripts, or UDP;
- public IP addresses only by default;
- 256 IP addresses at most per run.

Options:

```bash
# Explicit list, limited to 100 ports
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-ports 22,80,443

# Explicit Linux executable
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-path /usr/bin/nmap

# Lower target limit
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-max-ips 50

# Include private/non-global IPs only when authorized
python3 ./domain_inventory_en.py --input ./domains.txt --nmap --nmap-include-private
```

The `-sT` profile normally requires no root privileges. Do not run the complete
script with `sudo`; doing so changes file ownership and unnecessarily exposes
API keys to a privileged process. TCP connections can still be logged by the
target. "Low impact" does not mean invisible.

## Output files

- `domaines.csv`: registrar, dates, statuses, name servers, and contact summary;
- `contacts-rdap.csv`: public RDAP entities and roles;
- `contacts-whois.csv`: normalized who.is WHOIS/RDAP contacts;
- `dnsdumpster.csv`: DNSDumpster hosts, IPs, PTRs, ASNs, and countries;
- `enregistrements-dns.csv`: consolidated DNS and email checks;
- `sous-domaines-dns.csv`: discovered/tested names and A/AAAA resolution;
- `adresses-ip.csv`: ASN, operator, country, and probable hosting attribution;
- `nmap.csv`: bounded TCP port results when Nmap is enabled;
- `resume.json`: execution counts, quota state, and methodological warnings.

CSV files use semicolons and UTF-8 with BOM for spreadsheet compatibility. The
English script intentionally preserves the established French filenames and
column identifiers so both language versions can feed the same downstream
processing.

## Privacy and limitations

Domains and discovered names are transmitted to enabled public services.
Without optional keys, these services are `rdap.org`, `crt.sh`, `dns.google`,
and `ipwho.is`. Enabling DNSDumpster or who.is also sends domains to those
providers.

RDAP contact data may be redacted. Certificate Transparency logs are not an
exhaustive subdomain inventory. An IP may belong to a CDN, reverse proxy, or
cloud platform, so probable hosting identifies the apparent IP operator rather
than necessarily identifying the origin infrastructure.
