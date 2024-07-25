import os
import requests
from OpenSSL import crypto
import time

web_server_url = "https://web_server:3000/"
ca_server_url = "https://cert_auth_server:4000/"

def generate_keys():
    print("Generating new key pair...")
    # Generate new key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Save keys to files in current directory
    with open('client_priv.key', 'wb') as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    print("Private key saved to client_priv.key")

def generate_csr():
    print("Loading private key to generate CSR...")
    # Load private key
    with open('client_priv.key', 'rb') as key_file:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
    
    # Create a CSR
    req = crypto.X509Req()
    req.get_subject().CN = 'client'
    req.set_pubkey(key)
    req.sign(key, 'sha256')
    print("CSR created with subject CN=client")
    
    # Save CSR to a file
    with open('client.csr', 'wb') as csr_file:
        csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
    print("CSR saved to client.csr")

    return req

def get_signed_certificate():
    print("Loading CSR to send to CA server...")
    # Load CSR
    with open('client.csr', 'rb') as csr_file:
        csr = csr_file.read()
    
    # Send CSR to CA server
    files = {'csr': ('client.csr', csr, 'application/x-pem-file')}
    print("Sending CSR to CA server...")
    try:
        response = requests.post(ca_server_url + 'sign-csr', files=files, verify=False)
        print("Received response from CA server. Status code:", response.status_code)
        
        if response.ok:
            # Save received certificate
            with open('client_signed.crt', 'wb') as cert_file:
                cert_file.write(response.content)
            print("Received signed certificate from CA and saved to client_signed.crt")
        else:
            print("Failed to get signed certificate. Response content:", response.content)
    except requests.exceptions.SSLError as e:
        print("SSL Error:", e)
    except requests.exceptions.RequestException as e:
        print("Request Exception:", e)

def wait_for_server():
    print("Waiting for web server to be available...")
    for _ in range(10):  # Retry up to 10 times
        try:
            response = requests.get(web_server_url, cert=('client_signed.crt', 'client_priv.key'), verify=False)
            if response.ok:
                print("Server response:", response.text)
                return
            else:
                print("Server response was not OK. Status code:", response.status_code)
        except requests.exceptions.RequestException as e:
            print("Request Exception when connecting to server:", e)
        time.sleep(5)  # Wait for 5 seconds before retrying
    print("Failed to connect to web server after multiple attempts.")

def main():
    print("Starting client server script...")
    # Generate keys if they don't exist, otherwise delete and regenerate
    if os.path.exists('client_priv.key') and os.path.exists('client_signed.crt'):
        print("Existing keys and certificate found. Removing them...")
        os.remove('client_priv.key')
        os.remove('client_signed.crt')
    generate_keys()
    
    # Generate CSR and send to CA for signing
    csr = generate_csr()
    get_signed_certificate()
    
    # Wait for web server to be up
    wait_for_server()

if __name__ == '__main__':
    main()