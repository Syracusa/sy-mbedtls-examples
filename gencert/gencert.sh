./clean.sh

touch index.txt
echo 01 > serial
echo 1000 > crlnumber

mkdir -p private
mkdir -p certs
mkdir -p csr

# Generate RootCA Key
echo ''
echo '###############################'
echo '##### Generate RootCA Key #####'
echo '###############################'
echo ''
# (RSA) openssl genrsa -out private/cakey.pem 1024
openssl ecparam -out private/cakey.pem -name prime256v1 -genkey

# Generate RootCA Cert
echo ''
echo '################################'
echo '##### Generate RootCA Cert #####'
echo '################################'
echo ''
printf '\n\n\n\n\nRootCA\n\n' | \
openssl req -new -x509 -days 3650 -key private/cakey.pem -out certs/ca.cert.pem -extensions v3_ca

# Verify RootCA Cert
echo ''
echo '##############################'
echo '##### Verify RootCA Cert #####'
echo '##############################'
echo ''
openssl x509 -text -noout -in certs/ca.cert.pem



# Generate Server Key
echo ''
echo '###############################'
echo '##### Generate Server Key #####'
echo '###############################'
echo ''
# (RSA) openssl genrsa -out private/server.pem 1024
openssl ecparam -out private/server.pem -name prime256v1 -genkey

# Generate Server CSR
echo ''
echo '###############################'
echo '##### Generate Server CSR #####'
echo '###############################'
echo ''
printf '\n\n\n\n\nServer\n\n\n\n' | \
openssl req -new -sha256 -key private/server.pem -out csr/server.csr.pem

# Generate Server Cert
echo ''
echo '################################'
echo '##### Generate Server Cert #####'
echo '################################'
echo ''
openssl x509 -req -in csr/server.csr.pem -CA certs/ca.cert.pem -CAkey private/cakey.pem -out certs/server.cert.pem -CAcreateserial -days 3650 -sha256
# openssl ca -cert certs/ca-chain-bundle.cert.pem -in csr/server.csr.pem -out certs/server.cert.pem -days 3650 -config ica.cnf -extfile server.cnf

# Verify Server Cert
echo ''
echo '##############################'
echo '##### Verify Server Cert #####'
echo '##############################'
echo ''
openssl x509 -noout -text -in certs/server.cert.pem
openssl verify -verbose -CAfile certs/ca.cert.pem certs/server.cert.pem



# Generate Client Key
echo ''
echo '###############################'
echo '##### Generate Client Key #####'
echo '###############################'
echo ''
# (RSA) openssl genrsa -out private/cakey.pem 1024
openssl ecparam -out private/client.pem -name prime256v1 -genkey

# Generate Client CSR
echo ''
echo '###############################'
echo '##### Generate Client CSR #####'
echo '###############################'
echo ''
printf '\n\n\n\n\nClient\n\n\n\n' | \
openssl req -new -sha256 -key private/client.pem -out csr/client.csr.pem

# Generate Client Cert
echo ''
echo '################################'
echo '##### Generate Client Cert #####'
echo '################################'
echo ''
openssl x509 -req -in csr/client.csr.pem -CA certs/ca.cert.pem -CAkey private/cakey.pem -out certs/client.cert.pem -CAcreateserial -days 3650 -sha256
# openssl ca -cert certs/ca-chain-bundle.cert.pem -in csr/client.csr.pem -out certs/client.cert.pem -days 3650 -config ica.cnf -extfile client.cnf

# Verify Client Cert
echo ''
echo '##############################'
echo '##### Verify Client Cert #####'
echo '##############################'
echo ''
openssl x509 -noout -text -in certs/client.cert.pem
openssl verify -verbose -CAfile certs/ca.cert.pem certs/client.cert.pem