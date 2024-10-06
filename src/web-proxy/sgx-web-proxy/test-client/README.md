# Client for Testing SGX Web Proxy RA-TLS
## Build
Execute the following command in this directory to build the client:
```bash
make
```
## Run
Execute the following command in this directory to run the client:
```bash
./client-tls
```

## Troubleshooting
In the case the build process fails not finding the `libra-challenger.a` library, you can build it by running the following command in the `sgx-ra-tls` directory:
```bash
make all
```
