import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from OpenSSL import crypto

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

url = "https://localhost:3000/"
ca_server_url = "https://localhost:4000/"

def generate_keys():
    # Generate new key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Save keys to files in current directory
    with open('client_priv.key', 'wb') as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

def generate_csr():
    # Load private key
    with open('client_priv.key', 'rb') as key_file:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
    
    # Create a CSR
    req = crypto.X509Req()
    req.get_subject().CN = 'client'
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    # Save CSR to a file
    with open('client.csr', 'wb') as csr_file:
        csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

    return req

def get_signed_certificate():
    # Load CSR
    with open('client.csr', 'rb') as csr_file:
        csr = csr_file.read()
    
    # Send CSR to CA server
    files = {'csr': ('client.csr', csr, 'application/x-pem-file')}
    print("Sending CSR to CA server...")
    try:
        response = requests.post(ca_server_url + 'sign-csr', files=files, verify=False)
        print("Received response from CA server:", response.status_code)
        
        # Save received certificate
        with open('client_signed.crt', 'wb') as cert_file:
            cert_file.write(response.content)
        
        print("Received signed certificate from CA.")
    except requests.exceptions.SSLError as e:
        print("SSL Error:", e)
    except requests.exceptions.RequestException as e:
        print("Request Exception:", e)

def main():
    # Generate keys if they don't exist, otherwise delete and regenerate
    if os.path.exists('client_priv.key') and os.path.exists('client_signed.crt'):
        os.remove('client_priv.key')
        os.remove('client_signed.crt')
    generate_keys()
    
    # Generate CSR and send to CA for signing
    csr = generate_csr()
    get_signed_certificate()
    
    # Establish mTLS connection with server
    try:
        response = requests.get(url, cert=('client_signed.crt', 'client_priv.key'), verify=False)
        print("Server response:", response.text)
    except requests.exceptions.SSLError as e:
        print("SSL Error when connecting to server:", e)
    except requests.exceptions.RequestException as e:
        print("Request Exception when connecting to server:", e)

if __name__ == '__main__':
    main()
