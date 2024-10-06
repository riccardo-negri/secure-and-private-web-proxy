# Experiments Scripts

In the case you encounter issues with OpenSSL, you can try to set the `OPENSSL_CONF` environment variable to point to the `openssl.cnf` file in the current directory. This will allow `UnsafeLegacyRenegotiation`.

```bash
export OPENSSL_CONF=./openssl.cnf
```
