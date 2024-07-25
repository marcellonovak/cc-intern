# cert_auth_server/generate_cert.py

from OpenSSL import crypto

def generate_cert():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = 'My CA'
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    with open('/app/ca.key', 'wb') as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open('/app/ca.crt', 'wb') as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

if __name__ == '__main__':
    generate_cert()
