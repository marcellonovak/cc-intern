import os
import requests
from flask import Flask, request, jsonify
from OpenSSL import crypto
import logging

# Enable verbose logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

ca_server_url = "https://cert_auth_server:4000/sign-csr"

def generate_keys():
    logging.info("Generating new key pair...")
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    return key

def generate_csr(key):
    logging.info("Generating CSR...")
    req = crypto.X509Req()
    req.get_subject().CN = 'sidecar'
    req.set_pubkey(key)
    req.sign(key, 'sha256')
    return req

def get_signed_certificate(csr):
    logging.info("Sending CSR to CA server...")
    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    files = {'csr': ('sidecar.csr', csr_pem, 'application/x-pem-file')}
    try:
        response = requests.post(ca_server_url, files=files, verify=False)
        logging.info(f"Received response from CA server. Status code: {response.status_code}")
        if response.ok:
            logging.info("Received signed certificate from CA")
            return response.content
        else:
            logging.error(f"Failed to get signed certificate. Response content: {response.content}")
            return None
    except requests.exceptions.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Request Exception: {e}")
        return None

def inspect_certificate(cert_pem):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    subject = cert.get_subject()
    logging.info(f"Certificate subject: {subject.CN}")

@app.route('/get-certificate', methods=['POST'])
def get_certificate():
    logging.info("Received request to generate certificate")
    key = generate_keys()
    csr = generate_csr(key)
    signed_cert = get_signed_certificate(csr)
    if signed_cert:
        inspect_certificate(signed_cert)
        return jsonify({
            'private_key': crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'),
            'certificate': signed_cert.decode('utf-8')
        })
    else:
        return jsonify({'error': 'Failed to obtain signed certificate'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
