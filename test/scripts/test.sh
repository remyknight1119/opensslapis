#!/bin/bash

dir=test
#cd $dir

set -e
cacer=$dir/cert/ca-root.cer
cer=$dir/cert/rsa.pem
key=$dir/cert/rsa.pem
csr=$dir/cert/rsa.csr
der=$dir/cert/rsa.der
encrypted=$dir/cert/rsa-pwd.pem
ca_chain=$dir/cert/ca-chain.cer
passwd=osslapis-password
cat $cacer $cer | tee $ca_chain 1>/dev/null

openssl verify -CAfile $ca_chain $cer
rm -f $ca_chain
./$dir/opensslapis_test -t 1 -c $cer -k $key -s $csr -a $cacer -d $der -w $encrypted -p $passwd 
