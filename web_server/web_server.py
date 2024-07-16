import os
import ssl
import requests
from OpenSSL import crypto
from flask import Flask

app = Flask(__name__)

CA_SERVER_URL = "https://localhost:4000/sign-csr"  # Adjust the URL to your CA server

def generate_keys():
    # Generate new key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Save keys to files in current directory
    with open('server_priv.key', 'wb') as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open('server.crt', 'wb') as cert_file:
        cert = crypto.X509()
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def generate_csr():
    # Load private key
    with open('server_priv.key', 'rb') as key_file:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
    
    # Create a CSR
    req = crypto.X509Req()
    subj = req.get_subject()
    subj.CN = "Web Server"
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    # Save CSR to a file
    with open('server.csr', 'wb') as csr_file:
        csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

    return req

def get_signed_certificate():
    # Load CSR
    with open('server.csr', 'rb') as csr_file:
        csr = csr_file.read()
    
    # Send CSR to CA server
    files = {'csr': ('server.csr', csr, 'application/x-pem-file')}
    print("Sending CSR to CA server...")
    try:
        response = requests.post(CA_SERVER_URL, files=files, verify=False)  # Disable SSL verification for localhost
        print("Received response from CA server:", response.status_code)
        
        # Save received certificate
        with open('server_signed.crt', 'wb') as cert_file:
            cert_file.write(response.content)
        
        print("Received signed certificate from CA.")
    except requests.exceptions.SSLError as e:
        print("SSL Error:", e)
    except requests.exceptions.RequestException as e:
        print("Request Exception:", e)

def main():
    # Generate keys if they don't exist, otherwise delete and regenerate
    if os.path.exists('server_priv.key') and os.path.exists('server_signed.crt'):
        os.remove('server_priv.key')
        os.remove('server_signed.crt')
    generate_keys()
    
    # Generate CSR and send to CA for signing
    csr = generate_csr()
    get_signed_certificate()
    
    # Start the Flask app with SSL context
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server_signed.crt', keyfile='server_priv.key')  # Use the signed certificate
        app.run(ssl_context=context, port=3000, debug=True)
    except Exception as e:
        print("Error starting server:", e)

@app.route('/')
def hello():
    print("Received request from client.")
    return "Hello from Web Server!"

if __name__ == '__main__':
    main()
