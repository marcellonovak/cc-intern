#!/bin/sh
set -e

# Generate keys and CSR, get signed certificate
python -c "
import os
from client_server import generate_keys, generate_csr, get_signed_certificate

if os.path.exists('client_priv.key') and os.path.exists('client_signed.crt'):
    os.remove('client_priv.key')
    os.remove('client_signed.crt')

generate_keys()
generate_csr()
get_signed_certificate()
"

# Run the main application
exec "$@"
