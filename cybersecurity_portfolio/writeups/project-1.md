# 01 | Cryptography & PKI

Draft technical report • Original contract due date: September 25, 2026

Evidence scope: assistant-executed local demonstration, not verified student or platform completion.

## Problem summary and threat context

Cryptographic security depends on the construction as well as the primitive. AES can be secure while an inappropriate mode reveals relationships between plaintext blocks. Public-key systems similarly depend on adequate parameters, padding and authenticated key distribution. The experiments use entirely synthetic messages and deliberately insecure demonstration parameters. The threat model is an observer who can compare ciphertext blocks or alter an encrypted message, not an attacker interacting with an actual service.

## Attacker walkthrough

Run the shared lab script and inspect lab-1.json. The first experiment encrypts four identical 16-byte blocks under AES-ECB using a fixed demonstration key. Group the ciphertext into 16-byte blocks and count distinct values. The second experiment encrypts the same message using AES-GCM, changes one ciphertext byte and attempts authenticated decryption. The third performs textbook RSA arithmetic using the tiny primes 61 and 53, public exponent 17 and message integer 42. The private exponent is calculated from the known primes; modular exponentiation verifies recovery. Finally, compare SHA-256 digests of two messages differing in their last character and demonstrate that applying the same XOR mask twice recovers the original input.

## Results and interpretation

The ECB result is four ciphertext blocks but only one unique block. This reveals equality rather than the actual contents of the original block. AES-GCM rejects the altered ciphertext, demonstrating integrity verification. The toy RSA modulus is 3233, ciphertext 2557 and recovered integer 42. These values illustrate the mathematics, not the strength of production RSA. The hash comparison changes 123 of 256 bits; a single sample illustrates diffusion but does not establish a statistical guarantee. XOR reversibility is confirmed, but the experiment does not establish that all XOR-based constructions are insecure.

## Defender analysis

ECB pattern leakage illustrates risky cryptographic design (CWE-327); tiny RSA parameters illustrate inadequate encryption strength (CWE-326). Adopt authenticated encryption such as AES-GCM with a unique nonce per key and use a reviewed library rather than implementing primitives. The all-zero nonce and fixed key are isolated test fixtures, never deployment guidance. Reject failed authentication before processing plaintext. Use appropriately sized RSA keys where RSA is required, with standardized padding such as OAEP for encryption and PSS for signatures. A digest alone provides no sender authentication; use a MAC for shared-key authentication or a verified digital signature for public-key authentication.

## Detection and production implications

Inventory cryptographic call sites and configurations, check for ECB and obsolete algorithms, and include tamper-rejection tests in CI. A repeated ciphertext block can be a useful clue but is not a reliable standalone detector of insecure encryption. PKI validation requires a trusted chain, hostname or identity validation, validity checks and appropriate key usage. Certificate issuance and revocation operations should be monitored separately. Cryptographic errors should be handled consistently to avoid revealing distinctions that can become an oracle.

## Reflection and external work

This maps to the contract’s cryptography and public-key lectures by separating confidentiality, integrity and authenticity. The local lab covers five small concepts rather than the target 12–15 CryptoHack challenges. The padding-oracle exercise, CryptoHack challenge IDs, actual platform completion and certificate/signature exercises remain unverified. A useful follow-up is to compare a real certificate chain with the trust model and document why mathematical verification alone does not establish identity.

## Reproducible code and recorded output

Run `python labs/run_labs.py` after installing requirements.

```python
def crypto():
    key=bytes(range(16)); block=b'REPEATED BLOCK!!'; data=block*4
    e=Cipher(algorithms.AES(key),modes.ECB()).encryptor(); c=e.update(data)+e.finalize()
    a=AESGCM(key); nonce=bytes(12); sealed=a.encrypt(nonce,data,b'lab'); tampered=bytearray(sealed); tampered[0]^=1
    try: a.decrypt(nonce,bytes(tampered),b'lab'); rejected=False
    except InvalidTag: rejected=True
    p,q=61,53; n=p*q; exponent=17; d=pow(exponent,-1,(p-1)*(q-1)); m=42; enc=pow(m,exponent,n)
    msg=b'lab message'; changed=b'lab messagf'; digest=hashlib.sha256(msg).digest(); diff=sum((x^y).bit_count() for x,y in zip(digest,hashlib.sha256(changed).digest()))
    x=b'CTF demo'; mask=0x37; xor=bytes(v^mask for v in x)
    return {'ECB blocks':len(c)//16,'ECB unique blocks':len(set(c[i:i+16] for i in range(0,len(c),16))),'GCM tamper rejected':rejected,'toy RSA modulus':n,'toy RSA ciphertext':enc,'toy RSA recovered integer':pow(enc,d,n),'SHA256 changed bits':diff,'XOR round trip':bytes(v^mask for v in xor)==x}
```

```json
{
  "ECB blocks": 4,
  "ECB unique blocks": 1,
  "GCM tamper rejected": true,
  "toy RSA modulus": 3233,
  "toy RSA ciphertext": 2557,
  "toy RSA recovered integer": 42,
  "SHA256 changed bits": 123,
  "XOR round trip": true
}
```

## Reference and further-reading links

- https://cryptohack.org/
- https://csrc.nist.gov/pubs/sp/800/38/d/final
- https://cwe.mitre.org/data/definitions/327.html
- https://cwe.mitre.org/data/definitions/326.html
