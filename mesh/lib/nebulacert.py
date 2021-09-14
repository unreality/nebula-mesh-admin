import binascii
import hashlib
import ipaddress
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import mesh.lib.cert_pb2 as cert_proto


class NebulaCertificate(object):

    def __init__(self):
        self.Name = ""
        self.Groups = []

        self.Ips = []
        self.Subnets = []

        self.IsCA = False
        self.NotBefore = int(time.time())
        self.NotAfter = int(time.time() + 3600)
        self.PublicKey = ""

        self.Fingerprint = ""

    def _decode_pem(self, pem):
        s = pem.split("-----")

        try:
            return base64.b64decode(s[2].strip())
        except KeyError:
            print("Bad key")
            return False
        except binascii.Error as err:
            print(f"Bad b64 {err}")
            return False

    def fingerprint(self):
        return hashlib.sha256(self.PublicKey)

    def set_public_key_pem(self, pk):
        public_key = self._decode_pem(pk)

        if public_key:
            self.PublicKey = public_key

        return public_key is not False

    def sign_to_pem(self, signing_key_pem, signing_cert_pem):

        signing_key_bytes = self._decode_pem(signing_key_pem)

        if signing_key_bytes is False:
            return False

        if len(signing_key_bytes) == 64:
            signing_key_bytes = signing_key_bytes[0:32]
        signing_key = Ed25519PrivateKey.from_private_bytes(signing_key_bytes)

        signing_cert_bytes = self._decode_pem(signing_cert_pem)
        fingerprint = hashlib.sha256(signing_cert_bytes)

        cert_details = cert_proto.RawNebulaCertificateDetails()
        cert_details.Name = self.Name
        for i, g in enumerate(self.Groups):
            self.Groups[i] = g.strip()
        cert_details.Groups.extend(self.Groups)
        cert_details.NotBefore = self.NotBefore
        cert_details.NotAfter = self.NotAfter

        cert_details.PublicKey = self.PublicKey
        cert_details.IsCA = self.IsCA

        for i in self.Ips:
            try:
                iface = ipaddress.ip_interface(i)
                cert_details.Ips.extend([int(iface.ip), int(iface.netmask)])
            except ValueError:
                pass

        for s in self.Subnets:
            try:
                subnet = ipaddress.ip_interface(s)
                cert_details.Subnets.extend([int(subnet.ip), int(subnet.netmask)])
            except ValueError:
                pass

        cert_details.Issuer = fingerprint.digest()

        signature = signing_key.sign(cert_details.SerializeToString())

        cert = cert_proto.RawNebulaCertificate()
        cert.Details.CopyFrom(cert_details)
        cert.Signature = signature

        cert_str = base64.b64encode(cert.SerializeToString()).decode('utf-8')

        return f"-----BEGIN NEBULA CERTIFICATE-----\n{cert_str}\n-----END NEBULA CERTIFICATE-----\n"

    def load_cert(self, cert_pem):
        b = self._decode_pem(cert_pem)
        cert = cert_proto.RawNebulaCertificate()
        cert.ParseFromString(b)

        self.Name = cert.Details.Name
        self.Fingerprint = hashlib.sha256(b).hexdigest()
        self.NotAfter = cert.Details.NotAfter
        self.NotBefore = cert.Details.NotBefore

    def generate_ca(self):
        ca_private_key = Ed25519PrivateKey.generate()
        ca_public_key = ca_private_key.public_key()

        cert_details = cert_proto.RawNebulaCertificateDetails()
        cert_details.Name = self.Name
        cert_details.Groups.extend(self.Groups)
        cert_details.NotBefore = self.NotBefore
        cert_details.NotAfter = self.NotAfter

        cert_details.PublicKey = ca_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        cert_details.IsCA = True

        for i in self.Ips:
            try:
                iface = ipaddress.ip_interface(i)
                cert_details.Ips.extend([int(iface.ip), int(iface.netmask)])
            except ValueError:
                pass

        for s in self.Subnets:
            try:
                subnet = ipaddress.ip_interface(s)
                cert_details.Subnets.extend([int(subnet.ip), int(subnet.netmask)])
            except ValueError:
                pass

        signature = ca_private_key.sign(cert_details.SerializeToString())

        cert = cert_proto.RawNebulaCertificate()
        cert.Details.CopyFrom(cert_details)
        cert.Signature = signature

        cert_str = base64.b64encode(cert.SerializeToString()).decode('utf-8')

        public_key_bytes = ca_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        public_key_str = base64.b64encode(public_key_bytes).decode('utf-8')

        private_key_bytes = ca_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        private_key_str = base64.b64encode(private_key_bytes + public_key_bytes).decode('utf-8')

        cert_pem = f"-----BEGIN NEBULA CERTIFICATE-----\n{cert_str}\n-----END NEBULA CERTIFICATE-----\n"
        public_key_pem = f"-----BEGIN NEBULA ED25519 PUBLIC KEY-----\n{public_key_str}\n-----END NEBULA ED25519 PUBLIC KEY-----\n"
        private_key_pem = f"-----BEGIN NEBULA ED25519 PRIVATE KEY-----\n{private_key_str}\n-----END NEBULA ED25519 PRIVATE KEY-----\n"

        return cert_pem, public_key_pem, private_key_pem


if __name__ == '__main__':
    print("Generating CA")

    nc = NebulaCertificate()
    nc.Name = "Nebula CA"
    nc.NotAfter = int(time.time() + 60*60*24*365)
    nc.NotBefore = int(time.time())
    cert_pem, public_key_pem, private_key_pem = nc.generate_ca()

    print(cert_pem)
    print(public_key_pem)
    print(private_key_pem)
