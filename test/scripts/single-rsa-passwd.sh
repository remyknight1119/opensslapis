#!/bin/bash

dir=`dirname $0`
#cd $dir

set -e
key_bits=4096
expire_days=3650
subj=/C="CA"/ST="California"/L="Sunnyvale"/O="OPENSSLAPIS"/OU="OSSLAPIS"/CN="osslapis.rsasingle.com"
ca_name=ca-root
root_cacer=$ca_name.cer
root_cakey=$ca_name.key
param=rsa-single-pwd
cacer=$ca_name.cer
cakey=$ca_name.key
cer=$param.cer
csr=$param.csr
key=$param.key
p12=$param.p12
pfx=$param.pfx
config=./openssl.cnf
srl=t_ssl_ca.srl
passwd=osslapis-password

#Server cert
openssl genrsa -aes128 -passout pass:$passwd -out $key $key_bits
openssl req -new -key $key -passin pass:$passwd -sha256 -out $csr -subj $subj
openssl x509 -req -in $csr -sha256 -out $cer -CA $cacer -CAkey $cakey -CAserial $srl -CAcreateserial -days $expire_days -extensions v3_req
#openssl ca -config $config -keyfile $key -out $cer -infiles $csr
#openssl pkcs12 -export -clcerts -in $cer -inkey $key -out $p12
#openssl pkcs12 -export -in $cer -inkey $key -out $pfx 

#cat $sub1_cacer $cacer $cer $key |tee $param.pem
cat $cer $key | tee $param.pem
echo "===================Gen All OK===================="
openssl verify -CAfile $root_cacer $cer

rm -f $srl $cer $key
