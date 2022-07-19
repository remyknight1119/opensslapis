#!/bin/bash

dir=test
#cd $dir

set -e
cacer=$dir/cert/ca-root.cer
cer=$dir/cert/rsa.pem
key=$dir/cert/rsa.pem
csr=$dir/cert/rsa-single.csr
ca_chain=$dir/cert/ca-chain.cer
cat $cacer $cer | tee $ca_chain 1>/dev/null

openssl verify -CAfile $ca_chain $cer
rm -f $ca_chain
./$dir/opensslapis_test -c $cer -k $key -s $csr -a $cacer
