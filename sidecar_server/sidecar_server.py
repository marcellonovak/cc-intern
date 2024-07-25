from flask import Flask, request, jsonify
from OpenSSL import crypto
import os

app = Flask(__name__)

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    return key_pem, 200, {'Content-Type': 'application/x-pem-file'}

@app.route('/generate-csr', methods=['POST'])
def generate_csr():
    private_key_pem = request.files['private_key'].read()
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_pem)
    
    req = crypto.X509Req()
    req.get_subject().CN = 'client'
    req.set_pubkey(key)
    req.sign(key, 'sha256')
    
    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    return csr_pem, 200, {'Content-Type': 'application/x-pem-file'}

@app.route('/sign-csr', methods=['POST'])
def sign_csr():
    csr_data = request.files['csr'].read()
    # Forward CSR to CA server (omitted for simplicity)
    return jsonify({'message': 'CSR signed'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')  # Use adhoc context for development
