import os
import requests
from OpenSSL import crypto
import time
import logging

# Enable verbose logging
logging.basicConfig(level=logging.DEBUG)

web_server_url = "https://web_server:3000/"
sidecar_url = "http://sidecar_server:5000/get-certificate"

def get_certificate_from_sidecar():
    logging.info("Requesting certificate from sidecar...")
    for _ in range(10):  # Retry up to 10 times
        try:
            response = requests.post(sidecar_url)
            logging.info(f"Received response from sidecar. Status code: {response.status_code}")
            if response.ok:
                data = response.json()
                with open('client_priv.key', 'w') as key_file:
                    key_file.write(data['private_key'])
                with open('client_signed.crt', 'w') as cert_file:
                    cert_file.write(data['certificate'])
                logging.info("Received and saved private key and signed certificate from sidecar")
                return
            else:
                logging.error(f"Failed to get certificate from sidecar. Response content: {response.content}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Exception: {e}")
        time.sleep(5)
    logging.error("Failed to get certificate from sidecar after multiple attempts.")

def wait_for_server():
    logging.info("Waiting for web server to be available...")
    for _ in range(10):  # Retry up to 10 times
        try:
            response = requests.get(web_server_url, cert=('client_signed.crt', 'client_priv.key'), verify=False)
            if response.ok:
                logging.info(f"Server response: {response.text}")
                return
            else:
                logging.error(f"Server response was not OK. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Exception when connecting to server: {e}")
        time.sleep(5)
    logging.error("Failed to connect to web server after multiple attempts.")

def main():
    logging.info("Starting client server script...")
    if os.path.exists('client_priv.key') and os.path.exists('client_signed.crt'):
        logging.info("Existing keys and certificate found. Removing them...")
        os.remove('client_priv.key')
        os.remove('client_signed.crt')
    get_certificate_from_sidecar()
    wait_for_server()

if __name__ == '__main__':
    main()
