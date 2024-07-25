#!/bin/sh
set -e

# Generate keys and CSR, get signed certificate
python -c "
import os
from web_server import generate_keys, generate_csr, get_signed_certificate

if os.path.exists('server_priv.key') and os.path.exists('server_signed.crt'):
    os.remove('server_priv.key')
    os.remove('server_signed.crt')

generate_keys()
generate_csr()
get_signed_certificate()
"

# Run the main application
exec "$@"
