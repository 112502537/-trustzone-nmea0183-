#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <sender_ta.h>

//Command IDs
#define CMD_GEN_KEY         0
#define CMD_SIGN_DATA       1
#define CMD_GET_PUBLIC_KEY  2

//RSA configuration
#define RSA_KEY_SIZE_BITS   2048
#define RSA_EXPONENT        65537
#define SHA256_HASH_SIZE    32

//secure storge config
#define KEY_OBJECT_ID      "sign_rsa_keypair"
#define KEY_OBJECT_ID_LEN  (sizeof(KEY_OBJECT_ID) - 1)


static TEE_ObjectHandle g_rsa_keypair = TEE_HANDLE_NULL;

//this function will check if key exist or not 
//if it doesn't exist, generate a new key and store it 
static TEE_Result ensure_rsa_keypair(void)
{
    TEE_Result res;
    TEE_Attribute attr;
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    uint8_t rsa_exp[] = { 0x01, 0x00, 0x01 }; /* 65537 in big-endian */


    if (g_rsa_keypair != TEE_HANDLE_NULL)
        return TEE_SUCCESS;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   KEY_OBJECT_ID,
                                   KEY_OBJECT_ID_LEN,
                                   TEE_DATA_FLAG_ACCESS_READ,
                                   &g_rsa_keypair);

    if (res == TEE_SUCCESS) {
        DMSG("ensure: opened existing persistent key");
        return TEE_SUCCESS;
    }

    if (res != TEE_ERROR_ITEM_NOT_FOUND) {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        return res;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
                                      RSA_KEY_SIZE_BITS,
                                      &transient_key);
    if (res != TEE_SUCCESS)
        return res;

    TEE_InitRefAttribute(&attr,
                         TEE_ATTR_RSA_PUBLIC_EXPONENT,
                         rsa_exp,
                         sizeof(rsa_exp));

    res = TEE_GenerateKey(transient_key,
                          RSA_KEY_SIZE_BITS,
                          &attr,
                          1);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    //create persistent object
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     KEY_OBJECT_ID,
                                     KEY_OBJECT_ID_LEN,
                                     TEE_DATA_FLAG_ACCESS_READ,
                                     transient_key,
                                     NULL,
                                     0,
                                     &g_rsa_keypair);

    TEE_FreeTransientObject(transient_key);

    if (res != TEE_SUCCESS) {
        g_rsa_keypair = TEE_HANDLE_NULL;
        return res;
    }

    return TEE_SUCCESS;
}

//Generate SHA-256 digest for input data.
static TEE_Result sha256_digest(const void *data, size_t data_len,
                                uint8_t digest[SHA256_HASH_SIZE])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    size_t digest_len = SHA256_HASH_SIZE;

    //TEE_AllocateOperation : allocates a handle for a new cryptographic operation and sets the mode and algorithm type
    //TEE_MODE_DIGEST : only hash
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation(SHA256) failed: 0x%x", res);
        return res;
    }

    res = TEE_DigestDoFinal(op, data, data_len, digest, &digest_len);
    TEE_FreeOperation(op);

    if (res != TEE_SUCCESS) {
        EMSG("TEE_DigestDoFinal failed: 0x%x", res);
        return res;
    }

    if (digest_len != SHA256_HASH_SIZE)
        return TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

/*
 * Command: generate RSA keypair
 * paramTypes: NONE, NONE, NONE, NONE
 */
static TEE_Result cmd_gen_key(uint32_t param_types, TEE_Param params[4])
{
    (void)params;
    //check parameters
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
     
    return ensure_rsa_keypair();
}

/*
 * Command: sign input data
 * param[0] = input data
 * param[1] = output signature buffer
 *
 * paramTypes:
 *   MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE
 */
static TEE_Result cmd_sign_data(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint8_t digest[SHA256_HASH_SIZE];
    size_t sig_len;

    //check parameters
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    res = ensure_rsa_keypair();
    if (res != TEE_SUCCESS)
        return res;

    res = sha256_digest(params[0].memref.buffer,
                        params[0].memref.size,
                        digest);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_AllocateOperation(&op,
                                TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
                                TEE_MODE_SIGN,
                                RSA_KEY_SIZE_BITS);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation(SIGN) failed: 0x%x", res);
        return res;
    }

    res = TEE_SetOperationKey(op, g_rsa_keypair);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey failed: 0x%x", res);
        TEE_FreeOperation(op);
        return res;
    }

    sig_len = params[1].memref.size;
    res = TEE_AsymmetricSignDigest(op,
                                   NULL, 0,
                                   digest, sizeof(digest),
                                   params[1].memref.buffer,
                                   &sig_len);
    TEE_FreeOperation(op);

    if (res == TEE_ERROR_SHORT_BUFFER) {
        params[1].memref.size = sig_len;
        return res;
    }

    if (res != TEE_SUCCESS) {
        EMSG("TEE_AsymmetricSignDigest failed: 0x%x", res);
        return res;
    }

    params[1].memref.size = sig_len;
    return TEE_SUCCESS;
}

/*
 * Command: export public key
 * param[0] = output modulus (n)
 * param[1] = output public exponent (e)
 *
 * paramTypes:
 *   MEMREF_OUTPUT, MEMREF_OUTPUT, NONE, NONE
 */
static TEE_Result cmd_get_public_key(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    size_t n_len;
    size_t e_len;
    
    //check parameters
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    
    //check key
    res = ensure_rsa_keypair();
    if (res != TEE_SUCCESS)
        return res;

    n_len = params[0].memref.size;
    res = TEE_GetObjectBufferAttribute(g_rsa_keypair,
                                       TEE_ATTR_RSA_MODULUS,
                                       params[0].memref.buffer,
                                       &n_len);
    if (res == TEE_ERROR_SHORT_BUFFER) {
        params[0].memref.size = n_len;
        return res;
    }
    if (res != TEE_SUCCESS) {
        EMSG("Get modulus failed: 0x%x", res);
        return res;
    }
    params[0].memref.size = n_len;

    e_len = params[1].memref.size;
    res = TEE_GetObjectBufferAttribute(g_rsa_keypair,
                                       TEE_ATTR_RSA_PUBLIC_EXPONENT,
                                       params[1].memref.buffer,
                                       &e_len);
    if (res == TEE_ERROR_SHORT_BUFFER) {
        params[1].memref.size = e_len;
        return res;
    }
    if (res != TEE_SUCCESS) {
        EMSG("Get exponent failed: 0x%x", res);
        return res;
    }
    params[1].memref.size = e_len;

    return TEE_SUCCESS;
}

//TA life cycle
TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("sign_ta: TA_CreateEntryPoint");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("sign_ta: TA_DestroyEntryPoint");

    if (g_rsa_keypair != TEE_HANDLE_NULL) {
        TEE_CloseObject(g_rsa_keypair);
        g_rsa_keypair = TEE_HANDLE_NULL;
    }
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx)
{
    (void)params;
    (void)sess_ctx;

    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    DMSG("sign_ta: session opened");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)sess_ctx;
    DMSG("sign_ta: session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)sess_ctx;

    switch (cmd_id) {
    case CMD_GEN_KEY:
        return cmd_gen_key(param_types, params);

    case CMD_SIGN_DATA:
        return cmd_sign_data(param_types, params);

    case CMD_GET_PUBLIC_KEY:
        return cmd_get_public_key(param_types, params);

    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
