#!/bin/bash

dir=`dirname $0`
#cd $dir

set -e
key_bits=2048
expire_days=3650
subj=/C="CA"/ST="California"/L="Sunnyvale"/O="OPENSSLAPIS"/OU="OSSLAPIS"/CN="osslapis.rsasingle.com"
ca_name=ca-root
root_cacer=$ca_name.cer
root_cakey=$ca_name.key
cacer=$ca_name.cer
cakey=$ca_name.key
param=ecdsa-single-pwd
cer=$param.cer
csr=$param.csr
key=$param.key
config=./openssl.cnf
passwd=osslapis-password

#Server cert
curves=prime256v1
curves=secp521r1
curves=secp256r1
openssl ecparam -name $curves -genkey | openssl ec -aes128 -passout pass:$passwd -out $key
openssl req -new -passin pass:$passwd -key $key -sha256 -out $csr -subj $subj -days $expire_days
openssl x509 -req -in $csr -sha256 -extfile $config -out $cer -CA $cacer -CAkey $cakey -CAserial t_ssl_ca.srl -CAcreateserial -days $expire_days -extensions v3_req
#openssl pkcs12 -export -clcerts -in client.cer -inkey client.key -out client.p12
rm -f *.srl

#cat $sub1_cacer $cacer $cer $key |tee $param.pem
cat $cer $key | tee $param.pem
echo "===================Gen All OK===================="
openssl verify -CAfile $cacer $cer
echo $cacer

