from ecdsa import SigningKey,VerifyingKey,NIST384p
import ecdsa.util as util
from ecdsa.ecdsa import Private_key,Public_key,Signature
from ecdsa._compat import normalise_bytes
from ecdsa.keys import _truncate_and_convert_digest

########################################################
#####################数据类型的转化#####################
def str_to_bytes(s): 
    return bytes(s, encoding = "utf8")  

def bytes_to_str(b):
    return str(b, encoding = "utf8")  
########################################################
###################扩展欧几里得算法求逆#################
def exgcd(a,b):     
    if b == 0:         
        return 1,0,a     
    else:         
        x,y,q = exgcd(b,a%b)        
        x,y = y,(x-(a//b)*y)         
        return x,y,q
    
def getinv(r,n): 
    r_inv,_,q = exgcd(r,n)
    if q==1:
        return r_inv
    else:
        return None
########################################################
##################ECDSA相关功能的实现###################
def KeyGen():
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.verifying_key
    return sk,vk

def Sign(sk, m, k=None):
    return sk.sign(str_to_bytes(m), k=k)

def Verify(vk, m, signature):
    return vk.verify(signature, str_to_bytes(m))

def Hash(m, sk):
    m = normalise_bytes(str_to_bytes(m))
    h = sk.default_hashfunc(m).digest()
    h = normalise_bytes(h) 
    e = _truncate_and_convert_digest(h, sk.curve, False)
    return e
########################################################
##############Schnorr签名算法相关功能的实现#############
def SchnorrSign(sk, e, k):
    n = sk.privkey.order
    d = sk.privkey.secret_multiplier 
    G = sk.verifying_key.pubkey.generator 
    P = sk.verifying_key.pubkey.point
    R = k*G
    s = (k+e*d)%n
    return R,s

def SchnorrVerify(vk, e, sig):
    R,s = sig
    G = vk.pubkey.generator
    P = vk.pubkey.point
    if s*G == R+e*P:
        return 1
    else:
        return 0
#########################################################
    
print("0.验证ECDSA正确性: ")
m="123456"
print("密文m =",m)
sk,vk = KeyGen()
sign = Sign(sk,m)
r,s = util.sigdecode_string(sign, sk.privkey.order)
tag = Verify(vk,m,sign)
print("签名(r,s) =",(r,s))
print("正确性：",tag)
print("\n")
#########################################################   

print("1.泄露k导致d的泄露: ")
k = 111111
sign = Sign(sk,m,k)
n = sk.privkey.order 
e = Hash(m, sk) 
r,s = util.sigdecode_string(sign, n)
r_inv,_,gcd = exgcd(r,n)
print("r的逆 =",r_inv)
print("e =",e)
print("真实的d =",sk.privkey.secret_multiplier)
d = (r_inv * (k*s-e)%n)%n 
print("恢复出d =",d)
print("\n")
##########################################################

print("2.重复使用k导致d的泄露: ")
k = 111111
m1 = "123"
m2 = "456"
sign1 = Sign(sk,m1,k)
sign2 = Sign(sk,m2,k)
e1 = Hash(m1, sk) 
e2 = Hash(m2, sk)
n = sk.privkey.order
r1,s1 = util.sigdecode_string(sign1, n) 
r1_inv,_,gcd1 = exgcd(r1,n) 
r2,s2 = util.sigdecode_string(sign2, n) 
r2_inv,_,gcd2 = exgcd(r2,n) 
print("真实的d =",sk.privkey.secret_multiplier)
d = (((s1*e2 - s2*e1)%n) * getinv(s2*r1 - s1*r2,n)) %n
print("恢复出d =",d)
print("\n")
##########################################################

print("3.使用相同的k导致d1d2的泄露: ")
sk1,vk1 = KeyGen()
sk2,vk2 = KeyGen()
k = 111111
m1 = "123"
m2 = "456"
sign1 = Sign(sk1,m1,k)
sign2 = Sign(sk2,m2,k)
e1 = Hash(m1, sk1) 
e2 = Hash(m2, sk2) 
n = sk.privkey.order
r1,s1 = util.sigdecode_string(sign1, n)
r1_inv,_,gcd1 = exgcd(r1,n) 
r2,s2 = util.sigdecode_string(sign2, n)
r2_inv,_,gcd2 = exgcd(r2,n) 
d1 = sk1.privkey.secret_multiplier
d2 = sk2.privkey.secret_multiplier
D1 = (((s1*e2 - s2*e1 + s1*d2*r2)%n) * getinv(s2*r1,n)) %n
D2 = (((s2*e1 - s1*e2 + s2*d1*r1)%n) * getinv(s1*r2,n)) %n
print("真实的d1 =",sk1.privkey.secret_multiplier)
print("恢复出d1 =",D1)
print("真实的d2 =",sk2.privkey.secret_multiplier)
print("恢复出d2 =",D2)
print("\n")
###########################################################

print("4.验证签名(r,-s)的合法性: ")
m="123456"
sk,vk = KeyGen()
n = sk.privkey.order
sign1 = Sign(sk,m)
r,s = util.sigdecode_string(sign1, n)
sign2 = util.sigencode_string(r, (-s)%n, n) 
tag1 = Verify(vk,m,sign1)
tag2 = Verify(vk,m,sign2)
print("验证签名(r,s)的合法性：",tag1)
print("验证签名(r,-s)的合法性：",tag2)
print("\n")
############################################################

print("5.当仅验证e时给出伪造: ")
sk,vk = KeyGen()
n = sk.privkey.order
G = vk.pubkey.generator 
P = vk.pubkey.point 
u=3
v=5
xy = u*G+v*P
r = xy.x() % n
s = (r*getinv(v,n))%n
e = (s*u)%n
sig = Signature(r,s)
tag = vk.pubkey.verifies(e, sig)
print("伪造的e =",e)
print("对应的签名(r,s) =",(r,s)) 
print("正确性验证：",tag)
print("\n")
############################################################

print("6.ECDSA和Schnorr使用相同的d和k导致d的泄露: ")
m="123456"
sk,vk = KeyGen()
n = sk.privkey.order
k = 111111
# ECDSA
e1 = Hash(m, sk)
sign = Sign(sk,m,k)
r1,s1 = util.sigdecode_string(sign, sk.privkey.order)
# Schnorr
e2 = hash(m)
sign2 = SchnorrSign(sk,e2,k)
R,s2 = sign2
print("真实的d =",sk.privkey.secret_multiplier)
d = (((s1*s2-e1)%n) * getinv(s1*e2+r1,n)) %n
print("恢复出d =",d)
print("\n")
##########################################################












