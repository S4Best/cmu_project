#!/bin/sh

DAYS=$((3*365))
LEVELS=1
DN="/C=KR/L=Seoul/O=LGE/OU=CMU_Project"
CHAIN=chain.crt

############################################################
# Generate root certificate authority cert
############################################################

#generate root key pair
openssl genrsa -out  LG_CMU_ROOTCA_KEY.pem 2048

#generate root self-signed cert
openssl req -new -x509 -days $DAYS -key LG_CMU_ROOTCA_KEY.pem -subj "$DN/CN=LGCMUROOTCA" -outform pem -out LG_CMU_ROOTCA.pem
openssl x509 -outform der -in LG_CMU_ROOTCA.pem -out LG_CMU_ROOTCA.crt
cat LG_CMU_ROOTCA.pem > $CHAIN

############################################################
# Generate subordinate certificate authority hierarchy
############################################################

for i in `seq 1 $LEVELS`; do
    echo "Level $i"
    if [ "$i" -eq 1 ]; then
        SIGNER_CERT=LG_CMU_ROOTCA.pem
        SIGNER_KEY=LG_CMU_ROOTCA_KEY.pem
    else
        SIGNER_CERT=ca$((i-1))-cert.pem
        SIGNER_KEY=ca$((i-1))-key.pem
    fi

    #generate key pair
    openssl genrsa -out ca$i-key.pem 2048

    #generate signing request
    openssl req -new -key ca$i-key.pem -subj "$DN/CN=plate.Level$i" -out ca$i-csr.pem

echo "-------------"
echo ">>>>>>>>>>>>>>>>>"$SIGNER_CERT
echo ">>>>>>>>>>>>>>>>>"$SIGNER_KEY

    #sign new cert
    openssl x509 -req -days $DAYS -in ca$i-csr.pem -CA $SIGNER_CERT -CAkey $SIGNER_KEY \
            -set_serial $i -out ca$i-cert.pem -extfile "C:\Program Files\OpenSSL-Win64\bin\openssl.cfg" -extensions v3_ca  
    cat ca$i-cert.pem >> $CHAIN
echo "-------------"

done

############################################################
# Generate cert for server signed by leaf CA
############################################################

#generate key pair
openssl genrsa -out server.key 2048

#generate signing request
openssl req -new -key server.key -subj "$DN/CN=plate.server" -out server.csr

#sign new cert
openssl x509 -req -days $DAYS -in server.csr -CA ca$LEVELS-cert.pem \
    -CAkey ca$LEVELS-key.pem -set_serial 500 -out server.cert

############################################################
# Generate cert for client signed by leaf CA
############################################################

#generate key pair
openssl genrsa -out client.key 2048

#generate signing request
openssl req -new -key client.key -subj "$DN/CN=plate.client" -out client.csr

#sign new cert
openssl x509 -req -days $DAYS -in client.csr -CA ca$LEVELS-cert.pem \
    -CAkey ca$LEVELS-key.pem -set_serial 400 -out client.cert

