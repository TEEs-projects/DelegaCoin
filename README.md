# **DelegaCoin**

This is a pure C++ experimental implementation of paper "An Offline Delegatable Cryptocurrency System".


## **Getting Started**

The codes are developed in C++ using the Intel® SGX SDK1.6  under  the  operating  system  of  Ubuntu  20.04.1  LTS. 

Benchmarks taken on Intel® Core™ i7 9th Gen CPU.

### **Prerequisites**

* [Intel(R) Software Guard Extensions for Linux* OS](https://github.com/intel/linux-sgx)\
(including SDK, PSW, and driver)
* [Intel® Software Guard Extensions SSL (Intel® SGX SSL) cryptographic library](https://github.com/intel/intel-sgx-ssl)

### **Build**

The source code should be built under Intel® SGX SDK directory.

To build the project, run:

```
sudo make
```
### Note 

- May run into pthread problems due to version mate issue between SGX SDK and SGX SSL. \
[A possibly related issue on Github](https://github.com/intel/intel-sgx-ssl/issues/51).

## **Running the tests**


To run the test:

```
./app
```

* The main functions are developed in *./isv_app/isv_app.cpp*.

* Core modules are included in *./isv_enclave/isv_enclave.cpp*, including address generation, transaction signing, etc.


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments
Source code is developed based on:
* [SGX Remote Attestation](https://github.com/intel/linux-sgx/tree/master/SampleCode/RemoteAttestation)
* [Bitcoin address generation](https://pastebin.com/JXnPqwLq)
* [Bitcoin transaction signing](https://github.com/keeshux/basic-blockchain-programming)

with modification respectively.
