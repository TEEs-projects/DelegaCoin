/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include<stdint.h>
#include <cstdio>
#include<iostream>
#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "string.h"
#include "addrHeader.h"
#include <map>
#include"pthread.h"
#include<ctime>
#include<time.h>
#include<vector>


#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/ripemd.h>
#include "include/common.h"
#include "include/endian.h"
#include "include/tx.h"
#include "include/hash.h"
#include "include/ec.h"

int create_address_from_string(const unsigned char *string,
		unsigned char *address,
		unsigned char *priv_key,
		bool base58,
		bool debug,
		EC_GROUP *precompgroup);
void print_hex(u_int8_t * buffer, unsigned int len);
void base58_encode(unsigned char *data, unsigned int len, char *result);
void prepare_for_address(unsigned char *data, int datalen, char start_byte);
void generateAdddr(unsigned char* addr, unsigned char *pk);
void create_address_from_string(uint8_t* addr,size_t len);

void set_initial_remain(int initial[1]);
class trans_record;
class seal_data;
void gen_trans_record(const unsigned char addr[64], int out[1]);
size_t return_size();
int global_remain=0;
unsigned char address[64];
unsigned char priv_key[64];
bool warning=0;


/* remote attestation module */

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enclave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocol expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
uint8_t g_secret[8] = {0};


#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    bool derive_ret = false;

    if (NULL == shared_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ISV_KDF_ID != kdf_id)
    {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
        return SGX_ERROR_KDF_MISMATCH;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
        smk_key, sk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
        mk_key, vk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}


// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the
//                 message.
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if
//         incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the
//         expected value.

sgx_status_t put_secret_data(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        if(secret_size != 8)
        {
            ret = SGX_ERROR_INVALID_PARAMETER;
            break;
        }

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }

        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         &g_secret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)
                                            (p_gcm_mac));

        uint32_t i;
        bool secret_match = true;
        for(i=0;i<secret_size;i++)
        {
            if(g_secret[i] != i)
            {
                secret_match = false;
            }
        }

        if(!secret_match)
        {
            ret = SGX_ERROR_UNEXPECTED;
        }

        // Once the server has the shared secret, it should be sealed to
        // persistent storage for future use. This will prevents having to
        // perform remote attestation until the secret goes stale. Once the
        // enclave is created again, the secret can be unsealed.
    } while(0);
    return ret;
}

/* bitcoin address generation module */
/* This module is based on https://pastebin.com/JXnPqwLq */
/* with some modification */
// creates a bitcoin address+private key from the SHA256*  hash of string. converts to base58 if base58 is 'true'*  returns 1 if successful, 0 if not

int create_address_from_string(const unsigned char *string,
		unsigned char *address,
		unsigned char *priv_key,
		bool base58,
		bool debug,
		EC_GROUP *precompgroup) {

    u_int8_t * hash = static_cast<uint8_t *>(malloc(SHA256_DIGEST_LENGTH));
    
    BIGNUM * n = BN_new();
    
    //first we hash the string
    SHA256 (string, strlen((const char*)(char*)string), hash);
	//then we convert the hash to the BIGNUM n
    
    n = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, n);

    BIGNUM * order = BN_new();
    BIGNUM * nmodorder = BN_new();
	BN_CTX *bnctx;
	bnctx = BN_CTX_new();

    //then we create a new EC group with the curve secp256k1
	EC_GROUP * pgroup;
	if (precompgroup == NULL)
		pgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
	else
		//unless one has been passed to this function. in which case we use that curve.
		pgroup = precompgroup;


    if (!pgroup) {
    	//printf("ERROR: Couldn't get new group\n");
    	return 0;
    }

    //now we need to get the order of the group, and make sure that
    //the number we use for the private key is less than or equal to
    //the group order by using "nmodorder = n % order"
    EC_GROUP_get_order(pgroup, order, NULL);
    BN_mod(nmodorder, n, order, bnctx);

    if (BN_is_zero(nmodorder)) {
    	//printf("ERROR: SHA256(string) %% order == 0. Pick another string.\n");
    	return 0;
    }

    //now we create a new EC point, ecpoint, and place in it the secp256k1
    //generator point multiplied by nmodorder. this newly created
    //point is the public key


    EC_POINT * ecpoint = EC_POINT_new(pgroup);

	if (!EC_POINT_mul(pgroup, ecpoint, nmodorder, NULL, NULL, NULL))
	{
    	//printf("ERROR: Couldn't multiply the generator point with n\n");
    	return 0;
    }

    if (debug) {
        BIGNUM *x=NULL, *y=NULL;
        x=BN_new();
        y=BN_new();

        if (!EC_POINT_get_affine_coordinates_GFp(pgroup, ecpoint, x, y, NULL)) {
        	//printf("ERROR: Failed getting coordinates.");
        	return 0;
        }

    	//printf ("x: %s, y: %s\n", BN_bn2dec(x), BN_bn2dec(y));

        BN_free(x);
        BN_free(y);
    }

    //then we need to convert the public key point to data
    //first we get the required size of the buffer in which the data is placed
    //by passing NULL as the buffer argument to EC_POINT_point2oct
    unsigned int bufsize = EC_POINT_point2oct (pgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    u_int8_t * buffer = static_cast<uint8_t *>(malloc(bufsize));
    //then we place the data in the buffer
    int len = EC_POINT_point2oct (pgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, buffer, bufsize, NULL);
    if (len == 0) {
    	//printf("ERROR: Couldn't convert point to octet string.");
    	return 0;
    }

    //next we need to hash the public key data. first with SHA256, then with RIPEMD160
    SHA256(buffer, len, hash);
    u_int8_t * ripemd = static_cast<uint8_t *>(malloc(RIPEMD160_DIGEST_LENGTH+1+4));
    RIPEMD160(hash, SHA256_DIGEST_LENGTH, ripemd);

    if (base58 == true) {
		//here we add the version byte to the beginning of the public key and four checksum
		//bytes at the end
		prepare_for_address(ripemd, RIPEMD160_DIGEST_LENGTH, 0x6F);


		if (debug)
			print_hex(ripemd, RIPEMD160_DIGEST_LENGTH+1+4);

		//and we convert the resulting data to base58
		base58_encode(ripemd, RIPEMD160_DIGEST_LENGTH+1+4,  (char*)address);
    } else {
    	memcpy(address, ripemd, RIPEMD160_DIGEST_LENGTH);
    }


    //now we need to convert the big number nmodorder (private key) to data
    int buflen = BN_num_bytes(nmodorder);
    u_int8_t * buf = static_cast<uint8_t *>(malloc(buflen+1+4));
    int datalen;

    //nmodorder is converted to binary representation
    datalen = BN_bn2bin(nmodorder, buf);


    if (base58 == true) {
		//and we add version byte and four byte checksum to the data
		prepare_for_address(buf, datalen, 0x80);

        //and convert this to base58
        base58_encode(buf, datalen+5,  (char*)priv_key);
    } else {
    	memcpy(priv_key, buf, datalen+5);
    }

    free(hash);
    free(buffer);
    free(ripemd);
    free(buf);
    BN_free(n);
    BN_free(order);
    BN_free(nmodorder);
    if (precompgroup == NULL)
    	EC_GROUP_free(pgroup);
    EC_POINT_free(ecpoint);
    BN_CTX_free(bnctx);
    
    BN_free(n);
    return 1;
    
}

//prepares data to be converted to address. specifically, it adds start_byte to the beginning and a four-byte doubleSHA256 checksum to the end 
void prepare_for_address(unsigned char *data, int datalen, char start_byte) {
	unsigned char *tmpbuf = static_cast<uint8_t *>(malloc(datalen));
    //get data into a temporary buffer
    memcpy(tmpbuf, data, datalen);
    //shift data one byte forward, to make room for star_byte
    memcpy(data+1, tmpbuf, datalen);
    data[0] = start_byte;

    unsigned char *hash = static_cast<uint8_t *>(malloc(SHA256_DIGEST_LENGTH));
    SHA256(data, datalen+1, hash);
    SHA256(hash, SHA256_DIGEST_LENGTH, hash);

    //copy four first bytes from hash to the end of data (checksum bytes)
    memcpy(data+datalen+1, hash, 4);
    free(tmpbuf);
    free(hash);
}

void print_hex(u_int8_t * buffer, unsigned int len) {
	int x;
	for (x = 0; x < len; x++) {
		//printf("%.2x",buffer[x]);
	}
	//printf("\n");
}

//return the base58 encoding of data
void base58_encode(unsigned char *data, unsigned int len, char *result) {
	const char code_string[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    BIGNUM *x, *rem, *base, *tmp, *tmp2;
    x = BN_new();
	rem = BN_new();
	base = BN_new();
	tmp = BN_new();
	char * output_string = (char*)(malloc(64));

	x = BN_bin2bn(data, len, x);

	BN_set_word(rem, 1);
	BN_set_word(base, 58);

	BN_CTX *bnctx;
	bnctx = BN_CTX_new();

	int i = 0;
	while (!BN_is_zero(x)) {
		BN_div(tmp, rem, x, base, bnctx);
		output_string[i++] = code_string[BN_get_word(rem)];


		tmp2 = x;
		x = tmp;
		tmp = tmp2;
	}


	//public key
	int i2 = 0;
	while (data[i2] == 0) {
		output_string[i++] = code_string[0];
		i2++;
	}

	int base58len = i;
	while (i>=0) {
		result[base58len-i] = output_string[i-1];
		i--;
	}
	result[base58len] = 0;

	BN_free(x);
	BN_free(base);
	BN_free(rem);
	BN_free(tmp);
	BN_CTX_free(bnctx);
	free(output_string);
}


void create_address_from_string(uint8_t* addr,size_t len) {
    unsigned char message[32] = "password";
    if (create_address_from_string(message, address, priv_key, true, false, NULL) == 1)
    {
		for(int i=0;i<len;i++){
			addr[i]=address[i];
		}
	}
}

/* class definition */

class trans_record{
public:
    unsigned char addr[64];
    int out_coin=0;
    //unsigned char * priv_key;
    int remaining_balance=0;
    trans_record(const unsigned char addr[64], int out){
        out_coin = out;
        for(int i=0;i<64;i++)
            this->addr[i]=addr[i];
        global_remain -= out;
        remaining_balance = global_remain;
        if(remaining_balance<0) warning=1;
    }
    trans_record(){
        for(int i=0;i<64;i++)
            this->addr[i]='*';
        out_coin=0;
        remaining_balance=0;
    }

};

////////generated after the generation of private key///////
class seal_data{
public:
    //std::vector<trans_record> trans_list;
    trans_record trans_list[10];
    int record_num=0;
    unsigned char* privkey=priv_key;
    seal_data();
};
seal_data::seal_data(){
    record_num=0;
    privkey=priv_key;
    //trans_list=new trans_record[100];

}

void set_initial_remain(int initial[1]){
    global_remain = initial[0];
};

seal_data global_seal_data;

/////////////trans record////////////


void gen_trans_record(const unsigned char addr[64], int out[1]){
    trans_record record(addr, out[0]);
    //global_seal_data.trans_list.push_back(record);
    global_seal_data.trans_list[global_seal_data.record_num]=record;
    global_seal_data.record_num++;

}

size_t return_size(){
    return sizeof(global_seal_data);
}
/*
sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
    sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
    return status;
}
*/
sgx_sealed_data_t* seal() {
    size_t sealed_size=sizeof(sgx_sealed_data_t)+sizeof(global_seal_data);
    uint8_t* sealed_data=(uint8_t*)malloc(sealed_size);
    sgx_status_t status = sgx_seal_data(0, NULL, sizeof(global_seal_data), (uint8_t*)&global_seal_data, sealed_size, (sgx_sealed_data_t*)sealed_data);
    return (sgx_sealed_data_t*)sealed_data;
}

/* build and sign transaction */
/* This module is based on https://github.com/keeshux/basic-blockchain-programming */
void generate_transaction(uint8_t *raw){
    uint8_t priv[32];
    EC_KEY *key;
    uint8_t digest[32];
    uint8_t *sig;
    unsigned int sig_len;

    /* build transaction */
    bbp_txout_t outs[2];
    bbp_txout_t prev_outs[1];
    bbp_txin_t ins_sign[1];
    bbp_txin_t ins[1];
    bbp_outpoint_t outpoint;
    bbp_tx_t tx;
    uint8_t *msg;
    size_t msg_len;

    /* output 1 (0.005 BTC) */
    bbp_txout_create_p2pkh(&outs[0], 500000, "3e546d0acc0de5aa3d66d7a920900ecbc66c2031");

    /* output 2 (change, 0.001 BTC) */
    bbp_txout_create_p2pkh(&outs[1], 100000, "50c5e11681e92bb2388cd763d07bf07047a6bd0d");

    /* input from utxo (0.87 BTC) */
    bbp_outpoint_fill(&outpoint, "3afb3137110fb4ad1219199a1d836fd2faf466b609b6ab30ea124949b697ebc8", 0);
    bbp_txout_create_p2pkh(&prev_outs[0], 600000, "50c5e11681e92bb2388cd763d07bf07047a6bd0d");
    bbp_txin_create_signable(&ins_sign[0], &outpoint, &prev_outs[0]);

    /* message */
    tx.version = bbp_eint32(BBP_LITTLE, 1);
    tx.outputs_len = 2;
    tx.outputs = outs;
    tx.inputs_len = 1;
    tx.inputs = ins_sign;
    tx.locktime = 0;
    msg_len = bbp_tx_size(&tx, BBP_SIGHASH_ALL);
    msg = static_cast<uint8_t *>(malloc(msg_len));
    bbp_tx_serialize(&tx, msg, BBP_SIGHASH_ALL);


    ///free(msg);
    bbp_txout_destroy(&outs[0]);
    bbp_txout_destroy(&outs[1]);
    bbp_txout_destroy(&prev_outs[0]);
    bbp_txin_destroy(&ins_sign[0]);

    /* sign transaction */

    /* keypair */
    bbp_parse_hex(priv, (const char*)(char*)priv_key);
    key = bbp_ec_new_keypair(priv);

    /* message */

    /* signature */
    bbp_hash256(digest, msg, msg_len);
    sig_len = ECDSA_size(key);
    sig = static_cast<uint8_t *>(malloc(sig_len));
    ECDSA_sign(0, digest, sizeof(digest), sig, &sig_len, key);

    bbp_txin_create_p2pkh(&ins[0], &outpoint, (const char*)(char*)sig, "B568858A407A8721923B89DF9963D30013639AC690CCE5F555529B77B83CBFC7", BBP_SIGHASH_ALL);

    /* pack */
    tx.inputs = ins_sign;
    uint8_t *rawtx;
    size_t rawtx_len;
    uint8_t txid[32];
    rawtx_len = bbp_tx_size(&tx, BBP_SIGHASH_ALL);
    rawtx = static_cast<uint8_t *>(malloc(rawtx_len));
    bbp_tx_serialize(&tx, rawtx, BBP_SIGHASH_ALL);

    /* txid (print big-endian) */
    bbp_hash256(txid, rawtx, rawtx_len);
    bbp_reverse(txid, 32);

    gen_trans_record("50c5e11681e92bb2388cd763d07bf07047a6bd0d",100000);

    for(int i=0;i<rawtx_len;i++){
        raw[i]=rawtx[i];
    }

    free(rawtx);
    bbp_txin_destroy(&ins[0]);
    free(sig);
    free(msg);
    EC_KEY_free(key);
}
