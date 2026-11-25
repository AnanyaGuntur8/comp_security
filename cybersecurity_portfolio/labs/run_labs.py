"""Offline synthetic demonstrations. No network connections or external targets."""
import hashlib, hmac, json, math, struct, pathlib, sys, secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
ROOT=pathlib.Path(__file__).resolve().parents[1]
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
def auth():
    records={1:('alice','synthetic A'),2:('bob','synthetic B')}; user='alice'
    def vulnerable(i): return records[i][1]
    def checked(i): return records[i][1] if records[i][0]==user else None
    password=b'example123'; weak=hashlib.sha256(password).digest(); candidates=[b'password',b'example123',b'not-it']; match=next((i for i,c in enumerate(candidates,1) if hmac.compare_digest(hashlib.sha256(c).digest(),weak)),None)
    salt1=b'lab-salt-0000001'; salt2=b'lab-salt-0000002'; a=hashlib.scrypt(password,salt=salt1,n=16384,r=8,p=1); b=hashlib.scrypt(password,salt=salt2,n=16384,r=8,p=1)
    return {'unchecked cross-user read':vulnerable(2),'checked cross-user blocked':checked(2) is None,'checked own record':checked(1),'weak hash candidate position':match,'salted scrypt outputs differ':a!=b,'MFA incomplete session denied':not all([True,False])}
def memory():
    # Python bytearray deliberately models a fictional contiguous buffer and adjacent guard.
    arena=bytearray(b'........GUARD!!!'); payload=b'A'*12; arena[:len(payload)]=payload
    safe=bytearray(b'........GUARD!!!'); rejected=len(payload)>8
    if not rejected: safe[:len(payload)]=payload
    # Synthetic timing observations, not actual processor measurements.
    hit=[41,43,40,42,44]; miss=[112,109,115,111,114]
    return {'model overwritten guard':bytes(arena[8:]).decode(),'bounds check rejected':rejected,'protected guard':bytes(safe[8:]).decode(),'synthetic hit mean':sum(hit)/len(hit),'synthetic miss mean':sum(miss)/len(miss),'synthetic threshold':75}
def injection():
    # Token interpretation model only; never invokes a shell.
    sample='report.txt; second_action'; naive=sample.split(';'); allowed={'report.txt','summary.txt'}
    benign=b'MZ'+b'\0'*8+b'LAB_MARKER\0example.invalid\0'
    import re
    strings=[x.decode() for x in re.findall(rb'[ -~]{5,}',benign)]
    return {'unsafe model action count':len(naive),'allowlist accepts known file':'report.txt' in allowed,'allowlist rejects compound input':sample not in allowed,'synthetic fixture SHA256':hashlib.sha256(benign).hexdigest(),'fixture printable strings':strings,'fixture is executable':False}
def network():
    # Synthetic flow records; no packets sent.
    flows=[('dns',60,900),('dns',60,1200),('ntp',48,480),('https',500,700),('https',800,1000)]
    ratios=[round(r/q,2) for _,q,r in flows]; flagged=[i+1 for i,v in enumerate(ratios) if v>=10]
    policy={('client','web',443),('web','db',5432)}
    checks=[('client','web',443),('client','db',5432),('web','db',5432)]
    return {'synthetic response/request ratios':ratios,'flows flagged at ratio >= 10':flagged,'segmentation decisions':[{'path':list(x),'allowed':x in policy} for x in checks],'capstone cross-user request blocked':auth()['checked cross-user blocked'],'capstone modified ciphertext rejected':crypto()['GCM tamper rejected'],'capstone compound input rejected':injection()['allowlist rejects compound input']}
if __name__=='__main__':
    for i,fn in enumerate([crypto,auth,memory,injection,network],1):
        result=fn(); path=ROOT/'evidence'/f'lab-{i}.json'; path.parent.mkdir(exist_ok=True); path.write_text(json.dumps(result,indent=2)+'\n'); print(f'Lab {i}: {json.dumps(result)}')
