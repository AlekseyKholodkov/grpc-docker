#!/bin/zsh

# Clean-up before certificate generation
rm -rf certificate
mkdir "certificate"

# Declare common variables
root_cert_validity_period=7300
ca_cert_validity_period=1825
server_cert_validity_period=730
password=certpassword

# Create a keystore and then generate the key pairs for root, ca and server
keytool -genkeypair -keystore certificate/root.jks -alias root -ext bc:c -keyalg RSA -validity $root_cert_validity_period -storepass $password \
-dname "CN=Root certificate, OU=Software Development, O=Organization Name, L=City, S=State, C=CountryCode"
keytool -genkeypair -keystore certificate/ca.jks -alias ca -ext bc:c -keyalg RSA -validity $ca_cert_validity_period -storepass $password \
-dname "CN=Certification Authority (CA) certificate, OU=Software Development, O=Organization Name, L=City, S=State, C=CountryCode"
keytool -genkeypair -keystore certificate/server.jks -alias server -ext bc:c -keyalg RSA -validity $server_cert_validity_period -storepass $password \
-dname "CN=Server certificate, OU=Software Development, O=Organization Name, L=City, S=State, C=CountryCode"

# Export root certificate and redirect stdout to root.pem file
keytool -exportcert -keystore certificate/root.jks -alias root -storepass $password -rfc > certificate/root.pem

# Generate a Certificate Signing Request (CSR) (-certreq) for CA certificate and pipe an output to -gencert command,
# to generate a certificate from a certificate request (-gencert)
keytool -certreq -keystore certificate/ca.jks -alias ca -storepass $password | \
keytool -gencert -keystore certificate/root.jks -alias root -validity $ca_cert_validity_period -storepass $password -ext BC=0 -rfc > certificate/ca.pem
# Read certificate(or certificate chain) from file, and store it in the keystore entry identified by -alias
cat certificate/root.pem certificate/ca.pem | \
keytool -importcert -keystore certificate/ca.jks -alias ca -noprompt -storepass $password

# Generate a Certificate Signing Request (CSR) (-certreq) for Server certificate and pipe an output to -gencert command,
# to generate a certificate from a certificate request (-gencert)
keytool -certreq -keystore certificate/server.jks -alias server -storepass $password | \
keytool -gencert -keystore certificate/ca.jks -alias ca -validity $server_cert_validity_period -storepass $password -ext ku:c=dig,keyEncipherment -rfc > certificate/server.pem

# Read certificates(or certificate chain) from file, and store it in the keystore entry identified by -alias
cat certificate/root.pem certificate/ca.pem certificate/server.pem | \
keytool -importcert -keystore certificate/server.jks -alias server -noprompt -storepass $password

# Create keystore in PKCS12 format
keytool -importkeystore \
  -srckeystore certificate/server.jks \
  -destkeystore certificate/server.p12 \
  -deststoretype PKCS12 \
  -srcalias server \
  -srcstorepass $password \
  -deststorepass $password \
  -destkeypass $password

# extract public and private dey from the PKCS12 container
openssl pkcs12 -in certificate/server.p12 -nocerts -nodes -passin pass:$password -out certificate/server-key.pem
openssl pkcs12 -in certificate/server.p12 -nokeys -nodes -passin pass:$password -out certificate/server-cert.pem

# Export root certificate and redirect stdout to root.pem file

# Read from server certificate
echo -e "\n ===> server.jks alias server"
keytool -list -v -keystore certificate/server.jks -alias server -storepass $password

#keytool -printcert -file certificate/server.pem -v
echo -e "\n ===> server-cert.pem"
keytool -printcert -file certificate/server-cert.pem