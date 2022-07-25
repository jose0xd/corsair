import subprocess

###
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
###

p0 = subprocess.run(["openssl", "prime", "-generate", "-bits", "256", "-hex"],
        stdout=subprocess.PIPE)
p0 = int(p0.stdout, 16)
p1 = subprocess.run(["openssl", "prime", "-generate", "-bits", "256", "-hex"],
        stdout=subprocess.PIPE)
p1 = int(p1.stdout, 16)
p2 = subprocess.run(["openssl", "prime", "-generate", "-bits", "256", "-hex"],
        stdout=subprocess.PIPE)
p2 = int(p2.stdout, 16)

n1 = p0 * p1
n2 = p0 * p2

e = 0x10001

r1 = (p0 - 1) * (p1 - 1)
r2 = (p0 - 1) * (p2 - 1)

d1 = modinv(e, r1)
d2 = modinv(e, r2)

e1_1 = d1 % (p0 - 1)
e1_2 = d1 % (p1 - 1)
e2_1 = d2 % (p0 - 1)
e2_2 = d2 % (p2 - 1)

coef1 = pow(p1, p0 - 2, p0)
coef2 = pow(p2, p0 - 2, p0)

print("** Key 1 **")
print("p0:", hex(p0))
print("p1:", hex(p1))
print("\nn1:", hex(n1))
print("e:", hex(e))
print("d1:", hex(d1))
print("e1_1:", hex(e1_1))
print("e1_2:", hex(e1_2))
print("coef1:", hex(coef1))

print("\n** Key 2 **")
print("p0:", hex(p0))
print("p2:", hex(p2))
print("\nn2:", hex(n2))
print("e:", hex(e))
print("d2:", hex(d2))
print("e2_1:", hex(e2_1))
print("e2_2:", hex(e2_2))
print("coef2:", hex(coef2))

# Put this all together into two text files in the appropriate format. Example:
'''
asn1=SEQUENCE:private_key
[private_key]
version=INTEGER:0

n=INTEGER:0xBB6FE79432CC6EA2D8F970675A5A87BFBE1AFF0BE63E879F2AFFB93644\
D4D2C6D000430DEC66ABF47829E74B8C5108623A1C0EE8BE217B3AD8D36D5EB4FCA1D9

e=INTEGER:0x010001

d=INTEGER:0x6F05EAD2F27FFAEC84BEC360C4B928FD5F3A9865D0FCAAD291E2A52F4A\
F810DC6373278C006A0ABBA27DC8C63BF97F7E666E27C5284D7D3B1FFFE16B7A87B51D

p=INTEGER:0xF3929B9435608F8A22C208D86795271D54EBDFB09DDEF539AB083DA912\
D4BD57

q=INTEGER:0xC50016F89DFF2561347ED1186A46E150E28BF2D0F539A1594BBD7FE467\
46EC4F

exp1=INTEGER:0x9E7D4326C924AFC1DEA40B45650134966D6F9DFA3A7F9D698CD4ABEA\
9C0A39B9

exp2=INTEGER:0xBA84003BB95355AFB7C50DF140C60513D0BA51D637272E355E397779\
E7B2458F

coeff=INTEGER:0x30B9E4F2AFA5AC679F920FC83F1F2DF1BAF1779CF989447FABC2F5\
628657053A
'''

# To construct the binary DER file:
# > openssl asn1parse -genconf <path to above file> -out newkey.der
# You can then run this through OpenSSL's rsa command to confirm:
# > openssl rsa -in newkey.der -inform der -text -check
# Convert DER Format To PEM Format For RSA Key
# > openssl rsa -inform DER -outform PEM -in mykey.der -out mykey.pem


# https://stackoverflow.com/questions/19850283/how-to-generate-rsa-keys-using-specific-input-numbers-in-openssl
# https://stackoverflow.com/questions/33705487/how-to-calculate-the-coefficient-of-a-rsa-private-key



# ** To generate a certificate from the private key **
# Generate certificate request
# > openssl req -new -nodes -key mykey.pem -out csr.pem -subj /CN=ejemplo
# Generate self-signed certificate (sign the certificate request)
# > openssl req -x509 -nodes -sha256 -days 36500 -key mykey.pem -in csr.pem -out cert.pem
# Get public key from certificate
# > openssl x509 -pubkey -noout -in cert.pem > pubkey.pem
