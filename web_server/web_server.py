import os
import ssl
import requests
from OpenSSL import crypto
from flask import Flask
import logging

# Enable verbose logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

ca_server_url = "https://cert_auth_server:4000/sign-csr" 

def generate_keys():
    logging.info("Generating new key pair...")
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    logging.info("Saving private key to 'server_priv.key'...")
    with open('server_priv.key', 'wb') as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

def generate_csr():
    logging.info("Loading private key from 'server_priv.key'...")
    with open('server_priv.key', 'rb') as key_file:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
    
    logging.info("Creating Certificate Signing Request (CSR)...")
    req = crypto.X509Req()
    subj = req.get_subject()
    subj.CN = "web_server"
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    logging.info("Saving CSR to 'server.csr'...")
    with open('server.csr', 'wb') as csr_file:
        csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

    return req

def get_signed_certificate():
    logging.info("Loading CSR from 'server.csr'...")
    with open('server.csr', 'rb') as csr_file:
        csr = csr_file.read()
    
    files = {'csr': ('server.csr', csr, 'application/x-pem-file')}
    logging.info(f"Sending CSR to CA server at: {ca_server_url}")
    try:
        response = requests.post(ca_server_url, files=files, verify=False)
        logging.info(f"Received response from CA server: {response.status_code}")
        
        if response.status_code == 200:
            logging.info("Saving signed certificate to 'server_signed.crt'...")
            with open('server_signed.crt', 'wb') as cert_file:
                cert_file.write(response.content)
            logging.info("Received signed certificate from CA.")
            inspect_certificate('server_signed.crt')
        else:
            logging.error(f"Failed to get signed certificate from CA. Response: {response.text}")
    except requests.exceptions.SSLError as e:
        logging.error(f"SSL Error: {e}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request Exception: {e}")

def inspect_certificate(cert_path):
    with open(cert_path, 'rb') as cert_file:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
    subject = cert.get_subject()
    logging.info(f"Certificate subject: {subject.CN}")

def main():
    logging.info("Checking for existing keys and certificates...")
    if os.path.exists('server_priv.key') and os.path.exists('server_signed.crt'):
        logging.info("Existing keys and certificates found. Removing them...")
        os.remove('server_priv.key')
        os.remove('server_signed.crt')

    generate_keys()
    generate_csr()
    get_signed_certificate()
    
    try:
        logging.info("Loading signed certificate and private key for Flask app...")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server_signed.crt', keyfile='server_priv.key')
        logging.info("Starting Flask app with SSL...")
        app.run(host='0.0.0.0', port=3000, ssl_context=context)
    except Exception as e:
        logging.error(f"Error starting server: {e}")

@app.route('/')
def hello():
    logging.info("Received request from client.")
    return "Hello from Web Server!"

if __name__ == '__main__':
    main()
