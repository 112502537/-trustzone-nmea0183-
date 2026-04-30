#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "receiver_ta.h"

#define RSA_MOD_SIZE        256
#define RSA_SIG_SIZE        256
#define RSA_KEY_SIZE_BITS   2048
#define SHA256_SIZE         32

#define MAX_EXP_SIZE        8

#define KEY_OBJ_ID          "pubkey_obj"
#define KEY_OBJ_ID_LEN      (sizeof(KEY_OBJ_ID) - 1)

struct stored_pubkey {
	uint32_t mod_len;
	uint32_t exp_len;
	uint8_t modulus[RSA_MOD_SIZE];
	uint8_t exponent[MAX_EXP_SIZE];
};

//use secure storage to store key
//handle is runtime resource, it life time end when TA reboot 
//so instead of store key, store modulus, exponent and length
static TEE_Result store_public_key(const uint8_t *modulus, uint32_t mod_len,
				   const uint8_t *exponent, uint32_t exp_len)
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	struct stored_pubkey keyblob;

    //check parameters
	if (!modulus || !exponent)
		return TEE_ERROR_BAD_PARAMETERS;

	if (mod_len != RSA_MOD_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (exp_len == 0 || exp_len > MAX_EXP_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemFill(&keyblob, 0, sizeof(keyblob));
	keyblob.mod_len = mod_len;
	keyblob.exp_len = exp_len;
	TEE_MemMove(keyblob.modulus, modulus, mod_len);
	TEE_MemMove(keyblob.exponent, exponent, exp_len);

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 (void *)KEY_OBJ_ID, KEY_OBJ_ID_LEN,
					 TEE_DATA_FLAG_ACCESS_READ |
					 TEE_DATA_FLAG_ACCESS_WRITE |
					 TEE_DATA_FLAG_ACCESS_WRITE_META |
					 TEE_DATA_FLAG_OVERWRITE,
					 TEE_HANDLE_NULL,
					 &keyblob, sizeof(keyblob),
					 &obj);
	if (res != TEE_SUCCESS) {
		EMSG("CreatePersistentObject failed: 0x%x", res);
		return res;
	}

	TEE_CloseObject(obj);
	return TEE_SUCCESS;
}

//load key from secure storage and calculate key
static TEE_Result load_public_key(struct stored_pubkey *keyblob)
{
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t read_bytes = 0;

	if (!keyblob)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemFill(keyblob, 0, sizeof(*keyblob));

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)KEY_OBJ_ID, KEY_OBJ_ID_LEN,
				       TEE_DATA_FLAG_ACCESS_READ,
				       &obj);
	if (res != TEE_SUCCESS) {
		EMSG("OpenPersistentObject failed: 0x%x", res);
		return res;
	}

	res = TEE_ReadObjectData(obj, keyblob, sizeof(*keyblob), &read_bytes);
	TEE_CloseObject(obj);

	if (res != TEE_SUCCESS)
		return res;

    //check size
	if (read_bytes != sizeof(*keyblob))
		return TEE_ERROR_CORRUPT_OBJECT;

    //check data
	if (keyblob->mod_len != RSA_MOD_SIZE)
		return TEE_ERROR_CORRUPT_OBJECT;

	if (keyblob->exp_len == 0 || keyblob->exp_len > MAX_EXP_SIZE)
		return TEE_ERROR_CORRUPT_OBJECT;

	return TEE_SUCCESS;
}

//build a key object by using data already loaded from secure storage
static TEE_Result build_rsa_public_key(const struct stored_pubkey *keyblob,
				       TEE_ObjectHandle *pubkey)
{
	TEE_Result res;
	TEE_Attribute attrs[2];

	if (!keyblob || !pubkey)
		return TEE_ERROR_BAD_PARAMETERS;

	*pubkey = TEE_HANDLE_NULL;

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY,
					  RSA_KEY_SIZE_BITS, pubkey);
	if (res != TEE_SUCCESS)
		return res;

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS,
			     (void *)keyblob->modulus, keyblob->mod_len);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,
			     (void *)keyblob->exponent, keyblob->exp_len);

	res = TEE_PopulateTransientObject(*pubkey, attrs, 2);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(*pubkey);
		*pubkey = TEE_HANDLE_NULL;
		return res;
	}

	return TEE_SUCCESS;
}

static TEE_Result sha256_digest(const uint8_t *msg, uint32_t msg_len,
				uint8_t digest[SHA256_SIZE])
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint32_t digest_len = SHA256_SIZE;

	if (!msg || !digest)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_DigestDoFinal(op, msg, msg_len, digest, &digest_len);
	TEE_FreeOperation(op);

	if (res != TEE_SUCCESS)
		return res;

	if (digest_len != SHA256_SIZE)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

//import key from secure storage
static TEE_Result cmd_import_public_key(uint32_t param_types,
					TEE_Param params[4])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
    //check parameter
	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || !params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
    
    //will return TEE_SUCCESS or error msg
	return store_public_key((const uint8_t *)params[0].memref.buffer,
				params[0].memref.size,
				(const uint8_t *)params[1].memref.buffer,
				params[1].memref.size);
}

//verify the data
static TEE_Result cmd_verify_signature(uint32_t param_types,
				       TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle pubkey = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	struct stored_pubkey keyblob;
	uint8_t digest[SHA256_SIZE];

	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
    
    //check parameters
	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || !params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size != RSA_SIG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
    
    /*1. load key data from secure storage*/
	res = load_public_key(&keyblob);
	if (res != TEE_SUCCESS)
		return res;
    
    /*2. use data to build key(a TEE_Object)*/
	res = build_rsa_public_key(&keyblob, &pubkey);
	if (res != TEE_SUCCESS)
		return res;
    /*3. verify data*/
	res = sha256_digest((const uint8_t *)params[0].memref.buffer,
			    params[0].memref.size,
			    digest);
    //if fail, return error msg
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&op,
				    TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
				    TEE_MODE_VERIFY,
				    RSA_KEY_SIZE_BITS);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(op, pubkey);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AsymmetricVerifyDigest(op,
					 NULL, 0,
					 digest, SHA256_SIZE,
					 params[1].memref.buffer,
					 params[1].memref.size);

out:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	if (pubkey != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(pubkey);

	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4],
				    void **session_ctx)
{
	(void)params;
	(void)session_ctx;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_ctx)
{
	(void)session_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	(void)session_ctx;

	switch (cmd_id) {
	case CMD_IMPORT_PUBLIC_KEY:
		return cmd_import_public_key(param_types, params);
	case CMD_VERIFY_SIGNATURE:
		return cmd_verify_signature(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
