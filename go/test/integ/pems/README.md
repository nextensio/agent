
# DTLS Key/Cert generation

These steps are basically copied from the pion/dtls library from their file dtls/examples/certificates.
Instead of subjectAltName being IP address there we use hostname thats the difference.

EXTFILE='extfile.conf'
echo 'subjectAltName = DNS:gateway.nextensio.net' > "${EXTFILE}"

SERVER_NAME='server'
openssl ecparam -name prime256v1 -genkey -noout -out "${SERVER_NAME}.pem"
openssl req -key "${SERVER_NAME}.pem" -new -sha256 -subj '/C=NL' -out "${SERVER_NAME}.csr" -subj "/CN=gateway.nextensio.net/O=Nextensio Gateway"
openssl x509 -req -in "${SERVER_NAME}.csr" -extfile "${EXTFILE}" -days 365 -signkey "${SERVER_NAME}.pem" -sha256 -out "${SERVER_NAME}.pub.pem"




