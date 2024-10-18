Usage of mTLS

Certs preparation: 

Server:

sudo apt-get install libssl-dev / OpenSSL installation

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes / priv key and the SSL cert

gcc -o server server.c -lssl -lcrypto / compilation


Client: 

openssl genpkey -algorithm RSA -out client_key.pem / pub key

openssl req -new -key client_key.pem -out client.csr / certificate signing reques

openssl x509 -req -in client.csr -CA cert.pem -CAkey key.pem -CAcreateserial -out client_cert.pem -days 365 / self-signed CA. We will use the server's certificate as a certificate authority.


openssl s_client -connect localhost:9999 -cert client_cert.pem -key client_key.pem / connection testing

openssl x509 -in cert.pem -noout -text / cert info

Fake client: 

openssl genpkey -algorithm RSA -out fake_client_key.pem

openssl req -new -key fake_client_key.pem -out fake_client.csr

openssl genpkey -algorithm RSA -out fake_ca_key.pem

openssl req -x509 -new -nodes -key fake_ca_key.pem -sha256 -days 365 -out fake_ca_cert.pem

openssl x509 -req -in fake_client.csr -CA fake_ca_cert.pem -CAkey fake_ca_key.pem -CAcreateserial -out fake_client_cert.pem -days 365

openssl s_client -connect localhost:9999 -cert fake_client_cert.pem -key fake_client_key.pem -CAfile cert.pem


Server interaction:

curl --cert client_cert.pem --key client_key.pem -k https://localhost:9998 / GET

curl --cert client_cert.pem --key client_key.pem -k https://localhost:9998 -X POST -H "Content-Type: application/json" -d '{"number": 50}' / POST

curl --cert /data/client_cert.pem --key /data/client_key.pem -k https://serverHTTPS:9998 -X POST -H "Content-Type: application/json" -d '{"number": 50}' /data -> node-red settings.js volume