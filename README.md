# Authorized Hostinger Node build-sandbox control

This repository is a harmless callback fixture for an authorized Hostinger
HackerOne investigation. It is intended only for the researcher's owned
Hostinger hosting order.

The initial control does three things:

1. prints a fixed build marker and non-sensitive runtime identity fields;
2. sends a nonce callback to the researcher-controlled VPS;
3. starts a minimal HTTP server after deployment.

It does not read environment values, cloud metadata, credentials, protected
files, other tenants, or internal services. Those capabilities must not be
added until controlled build execution is proven and the applicable triager
authorization is rechecked.

Expected build marker:

`HOSTINGER_NODE_BUILD_CONTROL:a0034-r1`

