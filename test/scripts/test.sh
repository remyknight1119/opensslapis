#!/bin/bash

dir=test
#cd $dir

set -e
cacer=$dir/cert/ca-root.cer
rsa_cer=$dir/cert/rsa.pem
rsa_key=$dir/cert/rsa.pem
rsa_pub_key=$dir/cert/rsa-pub.pem
rsa_csr=$dir/cert/rsa.csr
rsa_der=$dir/cert/rsa.der
rsa_encrypted=$dir/cert/rsa-pwd.pem
ecdsa_cer=$dir/cert/ecdsa.pem
ecdsa_key=$dir/cert/ecdsa.pem
ecdsa_pub_key=$dir/cert/ecdsa-pub.pem
ecdsa_csr=$dir/cert/ecdsa.csr
ecdsa_der=$dir/cert/ecdsa.der
ecdsa_encrypted=$dir/cert/ecdsa-pwd.pem
dsa_cer=$dir/cert/dsa.pem
dsa_key=$dir/cert/dsa.pem
dsa_pub_key=$dir/cert/dsa-pub.pem
dsa_csr=$dir/cert/dsa.csr
dsa_der=$dir/cert/dsa.der
dsa_encrypted=$dir/cert/dsa-pwd.pem
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
key_bits=`openssl x509 -noout -text -in $rsa_cer | grep Public-Key | cut -d '(' -f 2 | awk '{print $1}'`
start_info_print "RSA"
./$dir/osslapis_test -t 1 -c $rsa_cer -k $rsa_key -s $rsa_csr -a $cacer -d $rsa_der -w $rsa_encrypted -p $passwd -l $key_bits -b $rsa_pub_key
end_info_print
key_bits=`openssl x509 -noout -text -in $ecdsa_cer | grep Public-Key | cut -d '(' -f 2 | awk '{print $1}'`
start_info_print "ECDSA"
./$dir/osslapis_test -t 2 -c $ecdsa_cer -k $ecdsa_key -s $ecdsa_csr -a $cacer -d $ecdsa_der -w $ecdsa_encrypted -p $passwd  -l $key_bits -b $ecdsa_pub_key
end_info_print
start_info_print "DSA"
./$dir/osslapis_test -t 3 -c $dsa_cer -k $dsa_key -s $dsa_csr -a $cacer -d $dsa_der -w $dsa_encrypted -p $passwd  -l $key_bits -b $dsa_pub_key
end_info_print
start_info_print "No Cert"
./$dir/osslapis_test -t 0
end_info_print
