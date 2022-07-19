#!/bin/bash

dir=test
#cd $dir

set -e
cacer=$dir/cert/ca-root.cer
rsa_cer=$dir/cert/rsa.pem
rsa_key=$dir/cert/rsa.pem
rsa_csr=$dir/cert/rsa.csr
rsa_der=$dir/cert/rsa.der
rsa_encrypted=$dir/cert/rsa-pwd.pem
ecdsa_cer=$dir/cert/ecdsa.pem
ecdsa_key=$dir/cert/ecdsa.pem
ecdsa_csr=$dir/cert/ecdsa.csr
ecdsa_der=$dir/cert/ecdsa.der
ecdsa_encrypted=$dir/cert/ecdsa-pwd.pem
ca_chain=$dir/cert/ca-chain.cer
passwd=osslapis-password
cat $cacer $cer | tee $ca_chain 1>/dev/null

echo_label()
{
    echo -n "=============================="
}

start_info_print()
{
    echo_label
    echo -n "$1 test"
    echo_label
    echo " "
}

end_info_print()
{
    echo_label
    echo -n "Test end"
    echo_label
    echo " "
}

openssl verify -CAfile $ca_chain $rsa_cer
openssl verify -CAfile $ca_chain $ecdsa_cer
rm -f $ca_chain
start_info_print "RSA"
./$dir/opensslapis_test -t 1 -c $rsa_cer -k $rsa_key -s $rsa_csr -a $cacer -d $rsa_der -w $rsa_encrypted -p $passwd 
end_info_print
start_info_print "ECDSA"
./$dir/opensslapis_test -t 2 -c $ecdsa_cer -k $ecdsa_key -s $ecdsa_csr -a $cacer -d $ecdsa_der -w $ecdsa_encrypted -p $passwd 
end_info_print
