######## Intel(R) SGX SDK Settings ########
ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g -DSGX_DEBUG
else
        SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

SGX_WOLFSSL_LIB="../sgx-ra-tls/deps/wolfssl/IDE/LINUX-SGX"
WOLFSSL_ROOT="../sgx-ra-tls/deps/wolfssl"
SGX_RA_TLS_ROOT="../sgx-ra-tls"
SGX_RA_TLS_LIB=$(SGX_RA_TLS_ROOT)

Wolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DUSER_TIME -DWOLFSSL_CERT_EXT
Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT)/ \
						 -I$(WOLFSSL_ROOT)/wolfcrypt/


Enclave_C_Files := trusted/Enclave.c
Enclave_Include_Paths := -IInclude -Itrusted $(Wolfssl_Include_Paths)\
								   -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc\
								   -I$(SGX_SDK)/include/stlport \
									 -I$(SGX_RA_TLS_ROOT)

ifeq ($(HAVE_WOLFSSL_TEST), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/test/
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_TEST
endif

ifeq ($(HAVE_WOLFSSL_BENCHMARK), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/benchmark/
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_BENCHMARK
endif


Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) -fno-builtin -fno-builtin-printf -I.
Enclave_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags) $(Wolfssl_C_Extra_Flags)

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
  -L$(SGX_RA_TLS_LIB) -lsgx_ra_tls_wolfssl \
	-L$(SGX_WOLFSSL_LIB) -lwolfssl.sgx.static.lib \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=trusted/Enclave.lds

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)




ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: Enclave.so
	@echo "Build enclave Enclave.so [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the Enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo
else
all: Enclave.signed.so
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## Enclave Objects ########

trusted/Enclave_t.c: $(SGX_EDGER8R) ./trusted/Enclave.edl
	@cd ./trusted && $(SGX_EDGER8R) --trusted ../trusted/Enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path ../../sgx-ra-tls
	@echo "GEN  =>  $@"

trusted/Enclave_t.o: ./trusted/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

trusted/%.o: trusted/%.c
	@echo $(CC) $(Enclave_C_Flags) -c $< -o $@
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

Enclave.so: trusted/Enclave_t.o $(Enclave_C_Objects)
	@echo $(Enclave_Link_Flags)@
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

Enclave.signed.so: Enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key trusted/Enclave_private.pem -enclave Enclave.so -out $@ -config trusted/Enclave.config.xml
	@echo "SIGN =>  $@"
clean:
	@rm -f Enclave.* trusted/Enclave_t.*  $(Enclave_C_Objects)
