# Secure and Private Web Proxy with TEE Support

## Abstract
Web proxy services are critical tools that allow users to access web
content otherwise restricted by geographical or technological barriers. However, these services introduce significant security and privacy risks, as highlighted by research exposing vulnerabilities such
as man-in-the-middle attacks, credential theft, and session hijacking.
These risks primarily stem from the need to trust the service operators.

This project explores the feasibility of mitigating these risks by implementing a web proxy service within a Trusted Execution Environment
(TEE). By leveraging a TEE, the project aims to enhance the security of
web proxy services by safeguarding the integrity and confidentiality of
the processed content, even if the service operators are compromised.

The primary objective is to design and implement a secure web proxy
service within an SGX enclave, balancing the enclave’s limited capacity
with the performance, usability, and security requirements. The project
also includes a thorough evaluation of the system’s security and performance.

## Documentation

The documentation for this project is available in the `report` directory.

## Repository Structure
The repository structure is as follows:

- `src/firefox-extension`: Contains the files for the Firefox extension.
- `src/web-proxy/gramine-poc`: Contains the files for the proof of concept based on Gramine of the web proxy.
- `src/web-proxy/sgx-web-proxy`: Contains the files for the SGX-based web proxy.

Every directory contains a README file with more information about the contents, how to build, and how to run the code.

## Demo
The following video shows navigation to different websites using the web proxy service implemented in this project.

![Video](https://gitlab.inf.ethz.ch/OU-SYSSEC/syssec-all/riccardo-negri-semester-project/-/blob/main/media/demo.mp4)