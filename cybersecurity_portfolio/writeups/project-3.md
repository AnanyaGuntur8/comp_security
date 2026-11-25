# 03 | Memory Corruption & Side Channels

Draft technical report • Original contract due date: October 30, 2026

Evidence scope: assistant-executed local demonstration, not verified student or platform completion.

## Problem summary and threat context

Memory corruption arises when operations violate the intended boundaries or lifetime of an object. A write beyond a buffer may affect adjacent data, including security-critical state. Side channels are different: even when architectural access checks work, timing or other observable effects may disclose information. This lab deliberately separates these mechanisms through a Python bytearray model and synthetic timing observations. It does not corrupt the Python interpreter, inspect another process or perform a hardware attack.

## Attacker walkthrough

Inspect the memory function in the shared script. The fictional arena has eight bytes reserved for an input buffer followed by an eight-byte guard string. A 12-byte input is copied into the modeled arena without checking the logical eight-byte boundary. Compare the guard after the copy with its initial value. Repeat using an explicit length check. For the timing exercise, compare two fixed arrays of synthetic observations representing hypothetical cache hits and misses. A threshold of 75 arbitrary units is placed between the two sets. No timer, cache instruction or victim data is involved.

## Results and interpretation

The unchecked model changes GUARD!!! into AAAAD!!!. The checked copy rejects the oversized input and preserves GUARD!!!. The synthetic hit and miss averages are 42.0 and 112.2 respectively. The threshold separates these particular constructed datasets by design. They are not measured CPU latencies and cannot support claims about Spectre exploitability, noise tolerance, or actual leakage. The example establishes how a boundary error and a timing distinction could be reasoned about in isolation.

## Defender analysis and mitigation study

The fictional overwrite models an out-of-bounds write (CWE-787). Validate lengths before writing and prefer memory-safe languages for new components when practical. Stack canaries detect some corruption before function return; they do not prevent every overwrite. ASLR randomizes locations, making address prediction harder but not impossible when an information leak exists. DEP/NX prevents execution from non-executable pages but cannot prevent reuse of existing executable code. Control-flow integrity constrains permitted indirect transfers; coverage depends on the implementation. These controls complement, rather than replace, bounds checking. Timing distinctions may correspond to CWE-208 when observable differences reveal sensitive state. Constant-time cryptographic implementations and appropriate hardware, firmware and operating-system mitigations address different parts of the problem.

## Detection and production implications

Use sanitizers and fuzzing during development to expose invalid memory accesses, review compiler hardening settings and investigate crashes rather than treating all crashes as harmless. Production telemetry may show anomalous faults, but absence of a crash does not demonstrate absence of memory corruption. For microarchitectural leakage, identify trust boundaries, apply vendor mitigations and evaluate performance and isolation tradeoffs. Spectre concerns speculative execution and side effects; Meltdown involves a different mechanism and affected hardware. A synthetic timing chart cannot establish that a specific processor is affected.

## Reflection and external work

The lab connects the contract’s memory-corruption lecture with defense in depth and side-channel reasoning. Its central limitation is that it is not a compiled binary or an actual processor experiment. The planned pwn.college and ROP Emporium ret2win/split exercises, debugger and Ghidra evidence, and annotation of a public Spectre or Meltdown proof of concept remain outstanding. The mitigation study can be expanded by recording actual compiler protections on authorized training binaries.

## Reproducible code and recorded output

Run `python labs/run_labs.py` after installing requirements.

```python
def memory():
    # Python bytearray deliberately models a fictional contiguous buffer and adjacent guard.
    arena=bytearray(b'........GUARD!!!'); payload=b'A'*12; arena[:len(payload)]=payload
    safe=bytearray(b'........GUARD!!!'); rejected=len(payload)>8
    if not rejected: safe[:len(payload)]=payload
    # Synthetic timing observations, not actual processor measurements.
    hit=[41,43,40,42,44]; miss=[112,109,115,111,114]
    return {'model overwritten guard':bytes(arena[8:]).decode(),'bounds check rejected':rejected,'protected guard':bytes(safe[8:]).decode(),'synthetic hit mean':sum(hit)/len(hit),'synthetic miss mean':sum(miss)/len(miss),'synthetic threshold':75}
```

```json
{
  "model overwritten guard": "AAAAD!!!",
  "bounds check rejected": true,
  "protected guard": "GUARD!!!",
  "synthetic hit mean": 42.0,
  "synthetic miss mean": 112.2,
  "synthetic threshold": 75
}
```

## Reference and further-reading links

- https://ropemporium.com/
- https://pwn.college/
- https://cwe.mitre.org/data/definitions/787.html
- https://cwe.mitre.org/data/definitions/208.html
