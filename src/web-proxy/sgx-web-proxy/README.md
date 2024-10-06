#  SGX Web Proxy

## Repository Structure
- `./app`: Contains the source code for the web proxy enclave.
- `./experiments`: Contains the scripts to run the experiments.
- `./test-client`: Contains the source code for the client written in C used to test the enclave.

## Setup the Development Environment

### Build the docker image
Run the following command in this directory to build the docker image:

```bash
docker build -t ratls .
```

### Run the docker container and bash into it 
Run the following command in this directory to run the docker container and bash into it:

```bash
docker run --network=host --device=/dev/isgx -v /var/run/aesmd:/var/run/aesmd -v$(pwd):/project -it ratls bash
```

### Build the sgx-ra-tls library

Note: the following steps are to be done inside the docker container.

Move into the project directory and build the sgx-ra-tls library:
```bash
cd /project
git clone https://github.com/cloud-security-research/sgx-ra-tls.git
```

Do the following changes
- Create the file ` ra_tls_options.c` inside the `sgx-ra-tls` directory. 
Add the following code to the file making sure to replace the SPID and subscription key with the ones provided by Intel. 
The SPID and subscription key can be obtained by enrolling in the [Intel SGX Attestation Service](https://api.portal.trustedservices.intel.com/EPID-attestation).
```c
#include "ra-attester.h"

struct ra_tls_options my_ra_tls_options = {
    // SPID format is 32 hex-character string, e.g., 0123456789abcdef0123456789abcdef
    .spid = {{0x1,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x1,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,}},
    .quote_type = SGX_LINKABLE_SIGNATURE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    // EPID_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "012345679abcdef012345679abcdef"
};

struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options = {
    // ECDSA_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = ""
};
```
- Change the version of the intel API to the latest available (v5) in `ias-ra.c`

- Set the current time in unix time format in `wolfssl-ra-attester.c` file at line 644.

- To enable debug options in wolfssl do the following:
    - trusted world: add `-DDEBUG_WOLFSSL` at line 351 of `sgx-ra-tls/Makefile`
    - untrusted world: add `--enable-debug` at line 333 of `sgx-ra-tls/Makefile`

- To support TLS supported curves and key share extensions add `-DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DHAVE_EXTENDED_MASTER -DHAVE_ENCRYPT_THEN_MAC -DHAVE_ONE_TIME_AUTH` at line 351 of `sgx-ra-tls/Makefile`

Build the library by running the following bash script in the `sgx-ra-tls` directory:
```bash
./build.sh sgxsdk
```

## Build the Web Proxy
To build the enclave run the following command in the `/app` directory: 

```bash
make SGX_MODE=HW SGX_DEBUG=1
```

If you get an error regarding `sgx_edger8r` not beign found, make sure to run `source /opt/intel/sgxsdk/environment` before running the build script.

## Run the Web Proxy
To run the enclave, run the following command in the `/app` directory: 

```bash
./App -s
```