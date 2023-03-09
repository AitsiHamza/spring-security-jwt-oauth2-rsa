#generate keypair

    openssl genrsa -out keypair.pem 2048

#generate private key

    openssl pkcs8 -topk8 -inform PEM -nocrypt -in keypair.pem -out private.pem

#generate public key 

    openssl rsa -in keypair.pem -pubout -out public.pem

