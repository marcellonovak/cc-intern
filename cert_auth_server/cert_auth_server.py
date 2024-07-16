from flask import Flask, request, send_file
from OpenSSL import crypto

app = Flask(__name__)

@app.route('/')
def hello():
    print("Received request from client.")
    return "Hello from Auth Server!"

@app.route('/sign-csr', methods=['POST'])
def sign_csr():
    print("Received CSR signing request from client.")
    
    csr_file = request.files['csr']
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_file.read())

    # Load CA key and certificate
    with open('ca.crt', 'rb') as ca_cert_file:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
    with open('ca.key', 'rb') as ca_key_file:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_file.read())

    # Issue signed certificate
    cert = crypto.X509()
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)  # Valid for 1 year
    cert.set_issuer(ca_cert.get_subject())
    cert.sign(ca_key, 'sha256')

    # Save signed certificate to a file
    cert_file_name = 'client_signed.crt'
    with open(cert_file_name, 'wb') as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    print("Signed certificate issued and sent to client.")
    return send_file(cert_file_name, as_attachment=True)

if __name__ == '__main__':
    app.run(ssl_context='adhoc', port=4000)
