SGX_SDK ?= /opt/intel/sgxsdk
SGX_DCAP ?= ../sgx-ra-tls/deps/SGXDataCenterAttestationPrimitives/

SGX_DCAP_INC=-I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc -I$(SGX_DCAP)/QuoteGeneration/pce_wrapper/inc -I$(SGX_DCAP)/QuoteVerification/Src/AttestationLibrary/include

CFLAGS+=-std=gnu99 -I. -I$(SGX_SDK)/include -Ideps/local/include $(SGX_DCAP_INC) -fPIC -I../sgx-ra-tls/deps/wolfssl/ -I../sgx-ra-tls
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS+=$(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS+=-DSGX_GROUP_OUT_OF_DATE

WOLFSSL_CLIENT_LIBS=-l:libra-challenger.a -l:libwolfssl.a -lm

wolfssl-client: client-tls.c
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -L../sgx-ra-tls/deps/wolfssl -L../sgx-ra-tls/deps/local/lib -L../sgx-ra-tls/wolfssl $(WOLFSSL_CLIENT_LIBS) -L../sgx-ra-tls/deps/wolfssl/wolfssl

.PHONY: all
all: 
	wolfssl-client

clean:
	rm wolfssl-client
	