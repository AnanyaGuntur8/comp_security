# 05 | Network Security & Integrated Capstone

Draft technical report • Original contract due date: December 4, 2026

Evidence scope: assistant-executed local demonstration, not verified student or platform completion.

## Problem summary and threat context

Network defense requires visibility into traffic and policies that constrain which systems can communicate. Reflection and amplification can cause a small request to trigger a larger response; if source addresses are spoofed and services are reachable, this can contribute to denial of service. Segmentation reduces the impact of a compromised service. The combined local capstone uses synthetic flow summaries and policy decisions, then checks security properties from the earlier modules. It sends no network packets and uses no external target.

## Attacker walkthrough

Inspect network() in the shared script. Five fictional flows contain protocol labels and request/response byte totals. Divide response bytes by request bytes and flag ratios at or above 10. The segmentation model explicitly permits client-to-web on port 443 and web-to-database on port 5432, but not client-to-database. Evaluate each of these paths. The integrated portion reuses the previous local modules to check that a cross-user record request is denied, modified authenticated ciphertext is rejected and compound input fails validation. These are independent regression checks, not an exploited host or a full application integration test.

## Results and interpretation

The ratios are 15, 20, 10, 1.4 and 1.25. The first three flows meet the illustrative threshold. The client-to-web and web-to-database paths are allowed; direct client-to-database is denied. All three regression checks return true. A high ratio is not proof of abuse: legitimate services can have asymmetric request and response sizes. No packet capture, spoofed source, flood, service scan or real TLS handshake was produced by this experiment.

## Defender analysis and mitigation study

An exposed amplification-prone service may exhibit uncontrolled resource consumption (CWE-400) in context; the synthetic records alone are insufficient for a vulnerability assignment. Reduce unnecessary exposure, restrict services to authorized clients, use response rate limiting where appropriate and apply source-address validation at network boundaries. An IDS should combine traffic volume, destination concentration, protocol semantics and baselines rather than relying on the illustrative ratio alone. Segmentation should enforce explicit permitted flows and deny other traffic by default. A Zero Trust architecture adds identity, device and context-aware authorization; the static three-node model is not a complete Zero Trust deployment.

## Detection and production implications

Network monitoring should collect flow and packet metadata where authorized, with privacy and retention controls. Investigate spikes in packet rate, bandwidth and unusual destination patterns in context. TLS provides encrypted and authenticated transport when peer identity is validated, but it does not replace application authorization or prevent all denial-of-service attacks. VPNs similarly establish protected connectivity without automatically making every reachable service trustworthy. The capstone ties transport protection, application authorization, safe parsing and segmentation together as distinct defenses.

## Reflection and external work

This final combined report follows the contract’s network-security and capstone grouping. It provides a reproducible synthetic policy study, not the required authorized HackTheBox or TryHackMe box. Wireshark/tcpdump captures, lab-only nmap enumeration, VPN/TLS inspection, Scapy analysis and the target 8–10 analyses plus one box remain unverified. The contract also requires a dissemination component and documented exchange; the website and engagement template support that work but do not establish that it has occurred.

## Reproducible code and recorded output

Run `python labs/run_labs.py` after installing requirements.

```python
def network():
    # Synthetic flow records; no packets sent.
    flows=[('dns',60,900),('dns',60,1200),('ntp',48,480),('https',500,700),('https',800,1000)]
    ratios=[round(r/q,2) for _,q,r in flows]; flagged=[i+1 for i,v in enumerate(ratios) if v>=10]
    policy={('client','web',443),('web','db',5432)}
    checks=[('client','web',443),('client','db',5432),('web','db',5432)]
    return {'synthetic response/request ratios':ratios,'flows flagged at ratio >= 10':flagged,'segmentation decisions':[{'path':list(x),'allowed':x in policy} for x in checks],'capstone cross-user request blocked':auth()['checked cross-user blocked'],'capstone modified ciphertext rejected':crypto()['GCM tamper rejected'],'capstone compound input rejected':injection()['allowlist rejects compound input']}
```

```json
{
  "synthetic response/request ratios": [
    15.0,
    20.0,
    10.0,
    1.4,
    1.25
  ],
  "flows flagged at ratio >= 10": [
    1,
    2,
    3
  ],
  "segmentation decisions": [
    {
      "path": [
        "client",
        "web",
        443
      ],
      "allowed": true
    },
    {
      "path": [
        "client",
        "db",
        5432
      ],
      "allowed": false
    },
    {
      "path": [
        "web",
        "db",
        5432
      ],
      "allowed": true
    }
  ],
  "capstone cross-user request blocked": true,
  "capstone modified ciphertext rejected": true,
  "capstone compound input rejected": true
}
```

## Reference and further-reading links

- https://www.wireshark.org/
- https://tryhackme.com/
- https://www.hackthebox.com/
- https://csrc.nist.gov/pubs/sp/800/207/final
- https://cwe.mitre.org/data/definitions/400.html
