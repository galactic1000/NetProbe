# NetProbe

NetProbe is a modular Python network scanner for practical host discovery, port scanning, protocol-aware fingerprinting, and vulnerability/advisory reporting.

## Highlights

- Host discovery (ICMP + TCP probes, optional UDP hints)
- TCP connect scan (`-sT`), SYN scan (`-sS` with auto-fallback when unavailable), UDP scan (`-sU`)
- Combined TCP+UDP mode (`-sT -sU`)
- Protocol-aware fingerprinting with plugin probes
- Product/version extraction with consistent fallback formatting
- OS guess from passive scan evidence, with optional confidence/evidence output
- Vulnerability + advisory pipeline with dedupe and severity normalization
- Outdated-version detection driven by `data/fingerprint_db.json`
- CVE correlation (`off`, `cache`, `periodic`, `live`)
- Multi-target scans and aggregate/per-target report output (`json`, `csv`, `txt`, `md`)

## Run

Run directly from source:

```bash
python netprobe.py <target>
```

No install step is required to run scans from this repo.

## Quick Start

```bash
# Default scan profile
python netprobe.py scanme.nmap.org

# TCP connect scan on explicit ports
python netprobe.py 192.168.1.10 -sT -p 22,80,443

# SYN scan (requires raw-socket capability on your platform)
python netprobe.py 192.168.1.10 -sS -p common

# UDP scan
python netprobe.py 192.168.1.10 -sU -p 53,123,161

# Combined TCP + UDP
python netprobe.py 192.168.1.10 -sT -sU -p common

# IPv6 literal (raw)
python netprobe.py 2001:db8::10 -sT -p 22,80,443

# IPv6 literal (bracketed)
python netprobe.py [2001:db8::10] -sS -p common

# Prefer IPv6 when hostname has both A and AAAA
python netprobe.py example.com --prefer-ipv6 -sT -p common
```

## Profiles

Program profiles tune defaults for timeout/workers/rate/report/CVE behavior:

- `normal` (default)
- `safe`
- `deep`

```bash
python netprobe.py target.example --profile safe
```

## Core CLI

```bash
python netprobe.py --help
```

Common options:

- `targets...`
- `-iL, --targets-file FILE`
- `-p, --ports SPEC`
- `--ports-profile {common,web,remote,database,messaging,infrastructure}`
- `-sS, --syn`
- `-sT, --connect`
- `-sU, --udp`
- `-6, --prefer-ipv6`
- `-t, --timeout SECONDS`
- `-w, --workers COUNT`
- `--rate-limit auto|N|0`
- `--rate-profile {general,conservative,aggressive}`
- `--no-discovery`
- `--no-vuln-scans`
- `--os-confidence`
- `--os-evidence`
- `-o, --output FILE`
- `--format {json,csv,txt,md}`
- `--report-mode {aggregate,individual,both}`

## CVE Options

- `--cve`:
  - Shortcut that enables `periodic` mode unless `--cve-mode` is explicitly set
- `--cve-mode {off,cache,periodic,live}`
- `--cve-filter FILTER`
  - Accepted forms:
    - scope only: `remote` or `broad`
    - scope + services: `remote:http,ssh`
    - services only: `http,ssh`
- `--cve-refresh HOURS`
  - `0` means refresh every run in `periodic`
- `--cve-cache-file PATH`
- `--update-cve`

NVD API key is read from environment:

- `NVD_API_KEY`

Examples:

```bash
# Enable periodic mode via shortcut
python netprobe.py target.example --cve

# Live mode with scope+service filtering
python netprobe.py target.example --cve-mode live --cve-filter remote:http,ssh

# Force cache refresh into a custom file
python netprobe.py target.example --update-cve --cve-cache-file .cache/custom_cve.json
```

## IPv6 Support (Current Behavior)

- IPv6 is fully supported across resolution and scanning paths.
- Accepted IPv6 target input forms:
  - raw literal: `2001:db8::1`
  - bracketed literal: `[2001:db8::1]`
- Default family preference is IPv4-first when both A and AAAA exist.
- Use `--prefer-ipv6` to prioritize AAAA candidates.
- If `--prefer-ipv6` is set and the host has no IPv6 address, resolution fails fast with a clear error.
- Resolver uses light reachability probing to choose a usable address candidate before scan phases.

Common IPv6 examples:

```bash
python netprobe.py 2001:db8::20
python netprobe.py [2001:db8::20] -sU -p 53,123,161
python netprobe.py dualstack.example --prefer-ipv6 -sT -sU -p common
```

## Fingerprinting Notes

Current fingerprinting/probing includes:

- Web/service product extraction (server headers and banner patterns)
- SSH/HTTP/TLS/Telnet/FTP checks
- DNS, SNMP, NTP protocol-aware probes
- SMB probing with SMB generation/dialect hints and Samba labeling when detectable
- DB probes/hints for MySQL, PostgreSQL, MSSQL, Oracle, MongoDB
- Fallback display rules ensure VERSION column stays useful:
  - product + number -> `Product x.y`
  - product only -> `Product`
  - number only -> `service x.y`
  - nothing -> blank

## Vulnerability / Advisory Model

- Findings are typed as either:
  - `vulnerability`
  - `advisory`
- Severity is normalized and deduplicated.
- Terminal summary prints vuln/advisory counts separately.
- LOW vulnerabilities are reserved for CVE correlation findings.
- Outdated-version logic is data-driven via fingerprint DB rules:
  - service baselines
  - HTTP product baselines
  - service-product baselines (e.g., Samba, Postfix, Exim, Dovecot, Courier, Cyrus)

## Multi-Target Reporting

Input can be positional targets and/or `-iL` file entries.

With `-o` and multiple targets:

- `aggregate`: one merged report
- `individual`: one report per target
- `both`: merged report + per-target reports

## Testing

Dependencies are only required for test/development workflows:

```bash
pip install -r requirements.txt
```

Run tests:

```bash
pytest -q
```

## Known Constraints

- UDP scanning is probabilistic (`open|filtered` is expected in some cases).
- SYN scanning behavior depends on OS privileges and path/network behavior.
- Service and version detection are best-effort and depend on remote responses.

## Disclaimer

Use NetProbe only on systems you own or are explicitly authorized to test.
