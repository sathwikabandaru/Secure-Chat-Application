from Crypto.PublicKey import RSA

# Generate a 2048-bit RSA key pair
key = RSA.generate(2048)

# Save private key
private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)

# Save public key
public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)

print("RSA key pair generated: private.pem and public.pem")