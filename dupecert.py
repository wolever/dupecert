import argparse
from OpenSSL import crypto

PEM = crypto.FILETYPE_PEM

# see: http://docs.ganeti.org/ganeti/master/html/design-x509-ca.html

def dupe(cert):
    dst = crypto.X509()
    dst.set_subject(cert.get_subject())
    dst.set_serial_number(1337)
    dst.gmtime_adj_notBefore(0)
    dst.gmtime_adj_notAfter(60*60*24*360)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    dst.set_pubkey(key)
    
    return dst

def sign(ca, cert):
    cert.sign(ca, "sha1")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", type=file,
                        default="ca/cakey.pem",
                        help="The CA's key, in PEM format.")
    parser.add_argument("--ca-pass", default="asdf",
                        help="passphrase for CA")
    parser.add_argument("--cert", type=file,
                        default="facebook.pem",
                        help="The certificate to duplicate, in PEM format.")

    return parser.parse_args()

def main():
    args = parse_args()

    ca = crypto.load_privatekey(PEM, args.ca.read(), args.ca_pass)
    cert = crypto.load_certificate(PEM, args.cert.read())

    new = dupe(cert)
    sign(ca, new)
    print crypto.dump_certificate(PEM, new)
    print crypto.dump_privatekey(PEM, new.get_pubkey())

if __name__ == "__main__":
    main()
