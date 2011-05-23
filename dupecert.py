#!/usr/bin/env python
import argparse
from OpenSSL import crypto

PEM = crypto.FILETYPE_PEM

# see: http://docs.ganeti.org/ganeti/master/html/design-x509-ca.html

def get_extension(cert, short_name, default=None):
    # For some reason not all certs have extensions... And if they don't, they
    # also have no 'get_extension_count' method.
    if not hasattr(cert, "get_extension_count"):
        return None
    for i in range(cert.get_extension_count()):
        extension = cert.get_extension(i)
        if extension.get_short_name() == short_name:
            return extension
    return default

def dupe(ca, cert):
    dst = crypto.X509()
    dst.set_serial_number(1337)
    dst.gmtime_adj_notBefore(0)
    dst.gmtime_adj_notAfter(60*60*24*360)
    dst.set_subject(cert.get_subject())
    alt_name = get_extension(cert, "subjectAltName")
    if alt_name is not None:
        dst.add_extensions([ alt_name ])

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    dst.set_pubkey(key)

    dst.sign(ca, "sha1")
    
    return dst, key

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", type=file,
                        default="cakey.pem",
                        help="The CA's key, in PEM format.")
    parser.add_argument("--ca-pass", default='', help="passphrase for CA")
    parser.add_argument("--cert", type=file,
                        default="facebook.pem",
                        help="The certificate to duplicate, in PEM format.")

    return parser.parse_args()

def main():
    args = parse_args()

    ca = crypto.load_privatekey(PEM, args.ca.read(), args.ca_pass)
    cert = crypto.load_certificate(PEM, args.cert.read())

    new_cert, new_pkey = dupe(ca, cert)
    print crypto.dump_certificate(PEM, new_cert)
    print crypto.dump_privatekey(PEM, new_pkey)

if __name__ == "__main__":
    main()
