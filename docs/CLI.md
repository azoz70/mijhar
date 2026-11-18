# MIJHAR CLI Reference

MIJHAR exposes a professional command-line interface built on Typer and Rich.

Running `mijhar` with no arguments opens the **interactive main menu** — it
shows the MIJHAR identity screen and then waits for input. A security scan is
never started automatically.

## Global options

| Option | Description |
| ------ | ----------- |
| `--version`, `-V` | Print the MIJHAR version and exit. |
| `--no-banner` | Suppress the startup identity screen. |
| `--help` | Show help. |

The identity screen is printed to **stderr**, so machine-readable output on
stdout is never polluted.

## Main menu

| # | Option | Purpose |
| - | ------ | ------- |
| 1 | Start Security Assessment | Select a target, detect the platform, review and run applicable checks. |
| 2 | Supported Platforms & Scan Types | Implemented vs. planned platforms and modules. |
| 3 | Framework Coverage | Supported frameworks, controls, and mappings. |
| 4 | View Previous Assessments | Scan history and summaries. |
| 5 | Remediation & Findings | Findings and remediation tracking. |
| 6 | Help & Usage Guide | What MIJHAR does and how to use it. |
| 7 | About MIJHAR | Description, version, creator, and LinkedIn. |
| 8 | Exit | Leave MIJHAR. |

## Commands

### `system-info`

Show host and MIJHAR environment information.

```bash
mijhar system-info
```

### `scan`

Run a platform-aware configuration security scan (read-only). Only checks
relevant to the selected platform execute; excluded checks are reported with
a reason.

```bash
# Local macOS scan (macOS checks only)
mijhar scan --target local --platform macos

# Local Linux scan (Linux checks only)
mijhar scan --target local --platform linux

# Remote Linux scan over SSH (key-based, read-only)
mijhar scan --target remote --platform linux --host 10.0.0.5 --user audit --port 22
```

| Option | Description |
| ------ | ----------- |
| `--target` | `local` (default) or `remote`. |
| `--platform`, `-p` | `macos` or `linux`. |
| `--frameworks` | Comma-separated frameworks to assess (`nca-ecc`, `sama-csf`, `cis`, `iso27001`). Default: all. |
| `--host` | Remote host (required for `--target remote`). |
| `--user`, `-u` | Remote SSH username (optional). |
| `--port` | Remote SSH port (default `22`). |

To assess against only one framework:

```bash
mijhar scan --target local --platform macos --frameworks cis
mijhar scan --target local --platform linux --frameworks cis,iso27001
```

The interactive menu (option 1) also asks which framework(s) to assess after
you select a target.

Remote scans use OpenSSH with `BatchMode=yes` (no password prompts) and
`StrictHostKeyChecking=yes`; the target must already be a known host and
accessible via your SSH key/agent.

### `results`

Show the findings for a scan (defaults to the most recent).

```bash
mijhar results
mijhar results --scan-id S-xxxxxxxxxx
```

### `history`

Show scan history.

```bash
mijhar history
```

### `rules list`

List all security rules (including their applicability metadata).

```bash
mijhar rules list
```

### `frameworks list`

List supported compliance frameworks (the complete catalog).

```bash
mijhar frameworks list
```

### `compliance`

Show a framework's platform-aware control assessment for the latest scan.
Controls that map only to checks for another platform are marked
`not_applicable` rather than `not_assessed`.

```bash
mijhar compliance --framework cis
mijhar compliance --framework nca-ecc
mijhar compliance --framework sama-csf
mijhar compliance --framework iso27001
```

### `report`

Generate a JSON, CSV, or HTML report for the latest (or specified) scan.
Reports include an assessment overview, statistics, findings, framework
mappings, and a dedicated "excluded checks" section.

```bash
mijhar report --format json
mijhar report --format csv
mijhar report --format html

# Write to a file instead of stdout
mijhar report --format html --output report.html
mijhar report --format json --scan-id S-xxxxxxxxxx --output report.json
```

### `review set` / `review list`

Manual reviewer assessment (overrides the automated control status).

```bash
mijhar review set --framework nca-ecc --control 2-8-3-3 \
  --status compliant --reviewer auditor --notes "verified via encryption report"

mijhar review list
mijhar review list --framework sama-csf
```

Valid `--status` values: `compliant`, `non_compliant`, `partially_compliant`,
`not_applicable`. Manual overrides are shown as `(manual)` in `mijhar compliance`.

### `remediations list` / `remediations close`

Track and close remediation items (auto-generated from failed/warning findings).

```bash
mijhar remediations list
mijhar remediations list --all
mijhar remediations close --id R-F-xxxxxxxxxx
```

### `evidence verify`

Verify the SHA-256 integrity of all stored evidence.

```bash
mijhar evidence verify
```

## Exit codes

- `0` — success.
- `1` — user error (invalid option, no scans available, etc.).
