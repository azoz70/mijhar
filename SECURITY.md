# Security Policy

MIJHAR is a read-only technical security assessment tool. Its purpose is to
*identify* misconfigurations, not to exploit them. If you believe you have
found a vulnerability in MIJHAR itself, please report it responsibly.

## Reporting a vulnerability

Please do **not** open a public issue for a security vulnerability. Instead,
report it privately to the maintainer.

When reporting, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce it.
- The affected MIJHAR version and target platform.
- Any suggested remediation (optional).

## Scope

This policy covers MIJHAR's own code — the collector, rules engine,
applicability engine, compliance engine, and reporting components. It does not
cover the systems you scan with MIJHAR.

## Expectations

- MIJHAR is **read-only by default** and never modifies a target.
- MIJHAR never stores credentials; remote scans use your existing SSH key
  (`BatchMode=yes`) and never prompt for or persist passwords.
- Do not submit reports that contain real credentials, keys, or the private
  data of systems you assessed.
