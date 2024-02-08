#!/bin/bash

#  gencerts.sh
#  VerIDSDKIdentity
#
#  Created by Jakub Dolejs on 12/01/2024.
#  Copyright © 2024 Applied Recognition. All rights reserved.

# Generate private RSA key
openssl genrsa -out clientkey.pem 2048

# Create certificate signing request for verid.client.identity
openssl req -new -key clientkey.pem -new -subj '/CN=verid.client.identity' -outform PEM -out csr.pem

# Sign the CSR, making the certificate expire in 10 days
openssl x509 -req -in csr.pem -CA standalone.pem -CAkey standalone_key.pem -days 10 -outform PEM -out cert.pem

# Package the generated certificate and private key in a p12 file
expiry=${/bin/date --date='+10 days' -I}
openssl pkcs12 -in cert.pem -inkey clientkey.pem -export -legacy -out "Ver-ID identity exp ${expiry}.p12" -passout pass:dummy

# Sign the CSR, making the certificate expired
faketime 'last friday 1 am' /bin/bash -c 'openssl x509 -req -in csr.pem -CA standalone.pem -CAkey standalone_key.pem -days 1 -outform PEM -out certexpired.pem'

# Package the expired certificate and private key in a p12 file
openssl pkcs12 -in certexpired.pem -inkey clientkey.pem -export -legacy -out 'Ver-ID identity expired.p12' -passout pass:dummy
