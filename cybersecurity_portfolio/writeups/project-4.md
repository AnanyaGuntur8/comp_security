# 04 | Injection, Sandboxing & Malware Triage

Draft technical report • Original contract due date: November 13, 2026

Evidence scope: assistant-executed local demonstration, not verified student or platform completion.

## Problem summary and threat context

Injection occurs when data crosses a boundary and is interpreted as instructions rather than remaining data. Command injection is especially dangerous when an application constructs commands from untrusted input and invokes a shell. Sandboxing limits what compromised code can access, while static triage helps analysts characterize suspicious files without executing them. The local experiment models token interpretation and inspects a deliberately non-executable synthetic byte fixture.

## Attacker walkthrough

Inspect the injection function in run_labs.py. The sample input contains a filename followed by a semicolon and a second fictional action. A naive parser splits the string into separate actions. The corrected model accepts only one of two explicitly permitted filenames. No subprocess or shell is invoked. The static triage fixture consists of an MZ prefix, padding and two printable markers. Compute its SHA-256 digest and extract printable strings using a regular expression. The fixture is not a valid PE executable and is not malware.

## Results and interpretation

The naive parser interprets two actions, while the allowlist accepts report.txt and rejects the compound input. Static inspection returns LAB_MARKER and example.invalid. The full reproducible fixture hash appears in lab-4.json. The MZ prefix alone does not prove a file is a Portable Executable. Strings and hashes can support triage but cannot establish malicious behavior, attribution or intent. The sample has no runtime behavior and its markers are not real indicators of compromise.

## Defender analysis

The parser model illustrates the data-versus-command boundary associated with OS command injection (CWE-78). Prefer library APIs for the operation itself instead of invoking an operating-system command. If an external process is necessary, use a fixed executable and structured arguments without shell interpretation, and validate values against their intended semantics. Avoid relying on a blacklist of punctuation. Least privilege limits impact but does not repair the injection flaw. Sandboxing mechanisms such as seccomp, namespaces and filesystem permissions can restrict capabilities; they need a deliberate policy and do not make unsafe parsing acceptable.

## Detection and production implications

Monitor unusual process ancestry, unexpected child processes, unexpected filesystem changes and network activity originating from application services. Establish baselines to avoid treating every shell invocation as malicious. For static triage, record hashes, file type, provenance, strings and structural observations before deciding whether further isolated analysis is warranted. Hash matching detects identical bytes, not all variants of a threat. Never execute an unknown sample on a personal or production machine. Access restrictions, logging, patch management and containment form complementary layers.

## Reflection and external work

The contract connects command injection, sandboxing and malware defense. The experiment demonstrates the reasoning behind safe parsing and static evidence collection, but does not run DVWA, PortSwigger command injection labs, Ghidra or PE analysis. Those authorized exercises and actual benign executable triage remain outstanding, along with the target volume of 8–10 labs. A later report should distinguish verified observations from hypotheses and document what the sandbox actually restricts.

## Reproducible code and recorded output

Run `python labs/run_labs.py` after installing requirements.

```python
def injection():
    # Token interpretation model only; never invokes a shell.
    sample='report.txt; second_action'; naive=sample.split(';'); allowed={'report.txt','summary.txt'}
    benign=b'MZ'+b'\0'*8+b'LAB_MARKER\0example.invalid\0'
    import re
    strings=[x.decode() for x in re.findall(rb'[ -~]{5,}',benign)]
    return {'unsafe model action count':len(naive),'allowlist accepts known file':'report.txt' in allowed,'allowlist rejects compound input':sample not in allowed,'synthetic fixture SHA256':hashlib.sha256(benign).hexdigest(),'fixture printable strings':strings,'fixture is executable':False}
```

```json
{
  "unsafe model action count": 2,
  "allowlist accepts known file": true,
  "allowlist rejects compound input": true,
  "synthetic fixture SHA256": "8c8f6964dbe9e6fc2985b76e30c47ba1a2191873af0e44b4e0d0ed3c0f79d3c8",
  "fixture printable strings": [
    "LAB_MARKER",
    "example.invalid"
  ],
  "fixture is executable": false
}
```

## Reference and further-reading links

- https://portswigger.net/web-security/os-command-injection
- https://cwe.mitre.org/data/definitions/78.html
- https://ghidra-sre.org/
- https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
