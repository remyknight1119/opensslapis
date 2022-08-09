#!/bin/bash

dir=`dirname $0`
#cd $dir

set -e
key_bits=4096
expire_days=3650
subj=/C="CA"/ST="California"/L="Sunnyvale"/O="OPENSSLAPIS"/OU="OSSLAPIS"/CN="www.rsasingle.com"
ca_name=ca-root
root_cacer=$ca_name.cer
root_cakey=$ca_name.key
param=dsa-single
cacer=$ca_name.cer
cakey=$ca_name.key
param_pem=$ca_name-param.pem
cer=$param.cer
csr=$param.csr
key=$param.key
p12=$param.p12
pfx=$param.pfx
config=./openssl.cnf
srl=t_ssl_ca.srl
pkcs_passwd=123456

#Server cert
openssl genrsa -out $key $key_bits
openssl dsaparam -out $param_pem $key_bits
openssl gendsa -out $key $param_pem
openssl req -new -key $key -sha256 -out $csr -subj $subj
openssl x509 -req -in $csr -extfile $config -sha256 -out $cer -CA $cacer -CAkey $cakey -CAserial $srl -CAcreateserial -days $expire_days -extensions v3_req
#openssl ca -config $config -keyfile $key -out $cer -infiles $csr
openssl pkcs12 -export -clcerts -passout pass:$pkcs_passwd -in $cer -inkey $key -out $p12
#openssl pkcs12 -export -in $cer -inkey $key -out $pfx 

#cat $sub1_cacer $cacer $cer $key |tee $param.pem
cat $cer $key | tee $param.pem
echo "===================Gen All OK===================="
openssl verify -CAfile $root_cacer $cer

rm -f $srl $cer $key $param_pem
