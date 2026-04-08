#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <tee_client_api.h>
/* 假設接收端 TA 定義了這些 CMD */
#define CMD_IMPORT_PUBLIC_KEY 0
#define CMD_VERIFY_SIGNATURE  1

#define LISTEN_PORT 1234
#define MAX_PKT_SIZE 2048

int main(void) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = { /* 接收端 TA UUID */ };
    uint32_t err_origin;

    int sockfd;
    uint8_t recv_buf[MAX_PKT_SIZE];
    struct sockaddr_in servaddr;

    /* 1. 初始化 TEE 連線 */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "TEEC_InitializeContext failed");

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "TEEC_OpenSession failed");

    /* 2. 建立 UDP 監聽 */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(LISTEN_PORT);
    bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));

    printf("[Verifier] Listening on UDP %d...\n", LISTEN_PORT);

    while (1) {
        int n = recvfrom(sockfd, recv_buf, MAX_PKT_SIZE, 0, NULL, NULL);
        if (n <= 0) continue;

        /* --- 判斷 A: 收到公鑰封包 --- */
        if (strncmp((char*)recv_buf, "PUBKEY:", 7) == 0) {
            printf("[Verifier] Received Public Key packet.\n");
			/*
            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                             TEEC_NONE, TEEC_NONE);
            op.params[0].tmpref.buffer = recv_buf + 7;       // Modulus
            op.params[0].tmpref.size = 256;
            op.params[1].tmpref.buffer = recv_buf + 7 + 256; // Exponent
            op.params[1].tmpref.size = 4;

            res = TEEC_InvokeCommand(&sess, CMD_IMPORT_PUBLIC_KEY, &op, &err_origin);
            if (res == TEEC_SUCCESS) printf("[Verifier] Public key imported to TA.\n");
			*/
        }
        /* --- 判斷 B: 收到簽章資料 --- */
        else {
            // 尋找分隔符 " SIG:"
            char *sig_ptr = strstr((char*)recv_buf, " SIG:");
            if (sig_ptr) {
                int nmea_len = sig_ptr - (char*)recv_buf;
                uint8_t *signature = (uint8_t*)sig_ptr + 5;

                printf("[Verifier] Verifying NMEA: %.*s\n", nmea_len, recv_buf);

				/*
                memset(&op, 0, sizeof(op));
                op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                                 TEEC_NONE, TEEC_NONE);
                op.params[0].tmpref.buffer = recv_buf;  // 原始 NMEA 內容
                op.params[0].tmpref.size = nmea_len;
                op.params[1].tmpref.buffer = signature; // 簽章內容 (256 bytes)
                op.params[1].tmpref.size = 256;

                res = TEEC_InvokeCommand(&sess, CMD_VERIFY_SIGNATURE, &op, &err_origin);

                if (res == TEEC_SUCCESS) {
                    printf(">> [SUCCESS] Signature matches! Data is authentic.\n");
                } else {
                    printf(">> [FAILURE] Signature invalid! Data might be tampered.\n");
                }
				*/
            }
        }
    }

	close(sockfd);
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
