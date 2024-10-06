# Proof Of Concept - Gramine 

# Setup 
Tested on Ubuntu 22.04 LTS without SGX.

Gramine was installed as explained in the [quick start guide](https://gramine.readthedocs.io/en/v1.4/quickstart.html).

# Building

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

# Run POC with Gramine

Without SGX:
```sh
gramine-direct poc
```

With SGX:
```sh
gramine-sgx poc
```

## Single command
Run with `make start`
