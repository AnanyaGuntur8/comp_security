# 02 | Authentication & Access Control

Draft technical report • Original contract due date: October 16, 2026

Evidence scope: assistant-executed local demonstration, not verified student or platform completion.

## Problem summary and threat context

Authentication establishes identity; authorization determines whether an authenticated identity may access a resource or perform an action. An application can verify credentials correctly while failing to restrict access to another account’s records. The experiment models two users with synthetic data and a password storage example. It also models an incomplete multifactor authentication session. No real accounts, password databases or web servers are involved.

## Attacker walkthrough

Run the shared script and inspect lab-2.json. Alice is the modeled session identity. The unchecked record lookup accepts a record identifier without considering the owner. Requesting record 2 returns Bob’s synthetic record. The corrected implementation compares the record owner with the authenticated identity before returning data. Test both Alice’s own record and Bob’s record so the fix demonstrates permitted and denied behavior. The password test compares a deliberately weak unsalted SHA-256 digest with three synthetic candidate strings. A separate test computes scrypt with two different salts for the same example password. The MFA model requires both factors to be complete.

## Results and interpretation

The unchecked function returns synthetic B, while the protected lookup denies the cross-user request and returns synthetic A for the legitimate owner. The weak digest matches the second candidate. Two salted scrypt outputs differ, showing why identical passwords should not automatically have identical stored verifiers. The incomplete MFA state is denied. This is not a password cracking benchmark, and no timing comparison between scrypt and SHA-256 was performed. The MFA boolean model is not an implementation of a real authentication protocol.

## Defender analysis

The missing ownership test represents an authorization bypass through a user-controlled key (CWE-639), also described as an insecure direct object reference. Enforce authorization on every request at the server and derive identity from a trusted session rather than a submitted user ID. Apply least privilege and deny by default. Fast general-purpose hashing for passwords represents insufficient computational effort (CWE-916). Use a dedicated password hashing function such as Argon2id or scrypt with unique random salts, tuned resource costs and controlled upgrade procedures. Salts prevent shared precomputation but do not make weak passwords strong. An incomplete MFA session must not receive privileges reserved for a fully authenticated session.

## Detection and production implications

Build a role-by-resource test matrix containing owner, non-owner, unauthenticated and administrative cases. Monitor repeated denied resource requests, unexpected privilege changes and abnormal authentication patterns while avoiding logging passwords or session secrets. Enforce MFA server-side on protected operations and secure account recovery as carefully as the primary login path. Rate limiting helps with online guessing but does not protect stolen password verifiers from offline attempts. Audit recovery and fallback paths because they can undermine otherwise strong authentication.

## Reflection and external work

The distinction between authentication and authorization directly matches the contract’s two lecture units. The model demonstrates policy logic but does not exercise HTTP sessions, Burp Suite, hashcat or John the Ripper. PortSwigger MFA, access-control, privilege escalation and traversal labs remain to be completed and documented with permitted screenshots. The contract targets roughly 8–10 labs plus hash sets; this local demonstration is a starting point rather than evidence of that volume.

## Reproducible code and recorded output

Run `python labs/run_labs.py` after installing requirements.

```python
def auth():
    records={1:('alice','synthetic A'),2:('bob','synthetic B')}; user='alice'
    def vulnerable(i): return records[i][1]
    def checked(i): return records[i][1] if records[i][0]==user else None
    password=b'example123'; weak=hashlib.sha256(password).digest(); candidates=[b'password',b'example123',b'not-it']; match=next((i for i,c in enumerate(candidates,1) if hmac.compare_digest(hashlib.sha256(c).digest(),weak)),None)
    salt1=b'lab-salt-0000001'; salt2=b'lab-salt-0000002'; a=hashlib.scrypt(password,salt=salt1,n=16384,r=8,p=1); b=hashlib.scrypt(password,salt=salt2,n=16384,r=8,p=1)
    return {'unchecked cross-user read':vulnerable(2),'checked cross-user blocked':checked(2) is None,'checked own record':checked(1),'weak hash candidate position':match,'salted scrypt outputs differ':a!=b,'MFA incomplete session denied':not all([True,False])}
```

```json
{
  "unchecked cross-user read": "synthetic B",
  "checked cross-user blocked": true,
  "checked own record": "synthetic A",
  "weak hash candidate position": 2,
  "salted scrypt outputs differ": true,
  "MFA incomplete session denied": true
}
```

## Reference and further-reading links

- https://portswigger.net/web-security/access-control
- https://portswigger.net/web-security/authentication
- https://cwe.mitre.org/data/definitions/639.html
- https://cwe.mitre.org/data/definitions/916.html
