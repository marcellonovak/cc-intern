import os
import requests
from OpenSSL import crypto
import time

web_server_url = "https://web_server:3000/"
sidecar_server_url = "https://sidecar_server:5000/"
ca_server_url = "https://cert_auth_server:4000/"

def request_from_sidecar(endpoint, files=None):
    for _ in range(10):  # Retry up to 10 times
        try:
            response = requests.post(sidecar_server_url + endpoint, files=files, verify=False)
            if response.ok:
                return response.content
            else:
                print(f"Request to {endpoint} failed. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request Exception when connecting to sidecar server: {e}")
        time.sleep(5)  # Wait for 5 seconds before retrying
    print(f"Failed to request {endpoint} from sidecar server after multiple attempts.")
    return None

def generate_keys():
    print("Requesting key generation from sidecar server...")
    key_pem = request_from_sidecar('generate-keys')
    if key_pem:
        with open('client_priv.key', 'wb') as key_file:
            key_file.write(key_pem)
        print("Private key saved to client_priv.key")

def generate_csr():
    print("Requesting CSR generation from sidecar server...")
    with open('client_priv.key', 'rb') as key_file:
        private_key = key_file.read()
    csr_pem = request_from_sidecar('generate-csr', files={'private_key': ('client_priv.key', private_key)})
    if csr_pem:
        with open('client.csr', 'wb') as csr_file:
            csr_file.write(csr_pem)
        print("CSR saved to client.csr")

def get_signed_certificate():
    print("Loading CSR to send to CA server...")
    with open('client.csr', 'rb') as csr_file:
        csr = csr_file.read()
    files = {'csr': ('client.csr', csr, 'application/x-pem-file')}
    print("Sending CSR to CA server...")
    try:
        response = requests.post(ca_server_url + 'sign-csr', files=files, verify=False)
        if response.ok:
            with open('client_signed.crt', 'wb') as cert_file:
                cert_file.write(response.content)
            print("Received signed certificate from CA and saved to client_signed.crt")
        else:
            print(f"Failed to get signed certificate. Response content: {response.content}")
    except requests.exceptions.RequestException as e:
        print(f"Request Exception when connecting to CA server: {e}")

def wait_for_server():
    print("Waiting for web server to be available...")
    for _ in range(10):  # Retry up to 10 times
        try:
            response = requests.get(web_server_url, cert=('client_signed.crt', 'client_priv.key'), verify=False)
            if response.ok:
                print("Server response:", response.text)
                return
            else:
                print(f"Server response was not OK. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request Exception when connecting to server: {e}")
        time.sleep(5)  # Wait for 5 seconds before retrying
    print("Failed to connect to web server after multiple attempts.")

def main():
    print("Starting client server script...")
    if os.path.exists('client_priv.key') and os.path.exists('client_signed.crt'):
        print("Existing keys and certificate found. Removing them...")
        os.remove('client_priv.key')
        os.remove('client_signed.crt')
    
    generate_keys()
    generate_csr()
    get_signed_certificate()
    wait_for_server()

if __name__ == '__main__':
    main()
