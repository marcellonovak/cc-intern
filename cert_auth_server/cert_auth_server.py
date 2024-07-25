import os
import ssl
from flask import Flask, request, jsonify
from OpenSSL import crypto

app = Flask(__name__)

CA_CERT_FILE = '/app/ca.crt'
CA_KEY_FILE = '/app/ca.key'

def load_ca_cert_and_key():
    print("Loading CA certificate and key...")
    try:
        with open(CA_CERT_FILE, 'rb') as cert_file:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
        print("CA certificate loaded successfully.")
    except Exception as e:
        print(f"Error loading CA certificate: {e}")
        raise

    try:
        with open(CA_KEY_FILE, 'rb') as key_file:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
        print("CA key loaded successfully.")
    except Exception as e:
        print(f"Error loading CA key: {e}")
        raise

    return ca_cert, ca_key

def sign_csr(csr_data):
    print("Signing CSR...")
    ca_cert, ca_key = load_ca_cert_and_key()
    
    try:
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_data)
        print("CSR loaded successfully.")
    except Exception as e:
        print(f"Error loading CSR: {e}")
        raise

    cert = crypto.X509()
    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.sign(ca_key, 'sha256')

    print("CSR signed successfully.")
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

@app.route('/sign-csr', methods=['POST'])
def sign_csr_route():
    print("Received request for signing CSR.")
    csr_file = request.files.get('csr')
    if csr_file:
        print("CSR file received.")
        csr_data = csr_file.read()
        try:
            signed_cert = sign_csr(csr_data)
            print("Certificate signed and returned.")
            return signed_cert, 200, {'Content-Type': 'application/x-pem-file'}
        except Exception as e:
            print(f"Error signing CSR: {e}")
            return jsonify({'error': 'Error signing CSR'}), 500
    else:
        print("No CSR file provided in the request.")
        return jsonify({'error': 'No CSR file provided'}), 400

@app.route('/hello')
def hello():
    print("Hello route accessed.")
    return 'Hello from Certificate Authority Server!'

if __name__ == '__main__':
    print("Starting CA server...")
    app.run(host='0.0.0.0', port=4000, ssl_context='adhoc')  # Use adhoc context for development