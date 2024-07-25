import os
import ssl
import requests
from OpenSSL import crypto
from flask import Flask

app = Flask(__name__)

ca_server_url = "https://cert_auth_server:4000/sign-csr" 

def generate_keys():
    print("Generating new key pair...")
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Save keys to files in the current directory
    print("Saving private key to 'server_priv.key'...")
    with open('server_priv.key', 'wb') as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

def generate_csr():
    print("Loading private key from 'server_priv.key'...")
    with open('server_priv.key', 'rb') as key_file:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
    
    print("Creating Certificate Signing Request (CSR)...")
    req = crypto.X509Req()
    subj = req.get_subject()
    subj.CN = "Web Server"
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    # Save CSR to a file
    print("Saving CSR to 'server.csr'...")
    with open('server.csr', 'wb') as csr_file:
        csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

    return req

def get_signed_certificate():
    print("Loading CSR from 'server.csr'...")
    with open('server.csr', 'rb') as csr_file:
        csr = csr_file.read()
    
    # Send CSR to CA server
    files = {'csr': ('server.csr', csr, 'application/x-pem-file')}
    print("Sending CSR to CA server at:", ca_server_url)
    try:
        response = requests.post(ca_server_url, files=files, verify=False)  # Disable SSL verification for cert_auth_server
        print("Received response from CA server:", response.status_code)
        
        if response.status_code == 200:
            print("Saving signed certificate to 'server_signed.crt'...")
            with open('server_signed.crt', 'wb') as cert_file:
                cert_file.write(response.content)
            print("Received signed certificate from CA.")
        else:
            print("Failed to get signed certificate from CA. Response:", response.text)
    except requests.exceptions.SSLError as e:
        print("SSL Error:", e)
    except requests.exceptions.RequestException as e:
        print("Request Exception:", e)

def main():
    print("Checking for existing keys and certificates...")
    if os.path.exists('server_priv.key') and os.path.exists('server_signed.crt'):
        print("Existing keys and certificates found. Removing them...")
        os.remove('server_priv.key')
        os.remove('server_signed.crt')

    generate_keys()
    generate_csr()
    get_signed_certificate()
    
    # Start the Flask app with SSL context
    try:
        print("Loading signed certificate and private key for Flask app...")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server_signed.crt', keyfile='server_priv.key')  # Use the signed certificate
        print("Starting Flask app with SSL...")
        app.run(host='0.0.0.0', port=3000, ssl_context=context)  # Listen on all network interfaces
    except Exception as e:
        print("Error starting server:", e)

@app.route('/')
def hello():
    print("Received request from client.")
    return "Hello from Web Server!"

if __name__ == '__main__':
    main()
