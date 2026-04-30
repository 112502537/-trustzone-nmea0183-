#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <tee_client_api.h>
#include <receiver_ta.h>

/* 定義監聽埠口與緩衝區 */
#define LISTEN_PORT 1234
#define MAX_PKT_SIZE 2048
#define RSA_SIG_SIZE 256  // 2048-bit RSA 簽章固定為 256 bytes

#define COLOR_RED	"\x1b[1;31m"
#define COLOR_GREEN	"\x1b[1;32m"
#define COLOR_RESET   	"\x1b[0m"
#define COLOR_CYAN    "\x1b[1;36m"

int main(void) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_RECEIVER_UUID;
    uint32_t err_origin;

    int sockfd;
    uint8_t recv_buf[MAX_PKT_SIZE];
    struct sockaddr_in servaddr;

    /* 1. 初始化 TEE 連線 */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "TEEC_InitializeContext failed");

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "OpenSession failed");

    /* 2. 建立 UDP 監聽 */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(LISTEN_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        close(sockfd);
        return -1;
    }

    printf("[Receiver] CA is ready. Listening on UDP %d...\n", LISTEN_PORT);

    while (1) {
        int n = recvfrom(sockfd, recv_buf, MAX_PKT_SIZE, 0, NULL, NULL);
        if (n <= 0) continue;

        /* --- 判斷 A: 收到公鑰封包 --- */
        /* 格式: "PUBKEY:" + Modulus(256B) + Exponent(4B) */
        if (n >= 7 && strncmp((char*)recv_buf, "PUBKEY:", 7) == 0) {
            printf("[Receiver] Received Public Key packet, importing to Secure Storage...\n");

            memset(&op, 0, sizeof(op));
            op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                             TEEC_MEMREF_TEMP_INPUT,
                                             TEEC_NONE, TEEC_NONE);

            // 參數 0: Modulus (偏移 7 bytes)
            op.params[0].tmpref.buffer = recv_buf + 7;
            op.params[0].tmpref.size = 256;

            // 參數 1: Exponent (偏移 7 + 256 bytes)
            op.params[1].tmpref.buffer = recv_buf + 7 + 256;
            op.params[1].tmpref.size = n - (7 + 256); // 動態計算剩下的 Exponent 長度

            res = TEEC_InvokeCommand(&sess, CMD_IMPORT_PUBLIC_KEY, &op, &err_origin);
            if (res == TEEC_SUCCESS) {
                printf("[Receiver] Success: Public key stored.\n");
            } else {
                printf("[Receiver] Error: Failed to import key (0x%x)\n", res);
            }
        }
        /* --- 判斷 B: 收到簽章資料 --- */
        /* 格式: [原始 NMEA] + " SIG:" + [256B 二進位簽章] */
        else {
            char *sig_ptr = strstr((char*)recv_buf, " SIG:");
            if (sig_ptr) {
                int nmea_len = (uint8_t*)sig_ptr - recv_buf;
                uint8_t *signature = (uint8_t*)sig_ptr + 5; // 跳過 " SIG:" 這 5 個字元

                printf("[Receiver] Verifying NMEA Data: %.*s\n", nmea_len, recv_buf);

                memset(&op, 0, sizeof(op));
                op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                                 TEEC_MEMREF_TEMP_INPUT,
                                                 TEEC_NONE, TEEC_NONE);

                // 參數 0: 原始資料 (做雜湊用)
                op.params[0].tmpref.buffer = recv_buf;
                op.params[0].tmpref.size = nmea_len;

                // 參數 1: 數位簽章 (做驗證用)
                op.params[1].tmpref.buffer = signature;
                op.params[1].tmpref.size = RSA_SIG_SIZE;

                res = TEEC_InvokeCommand(&sess, CMD_VERIFY_SIGNATURE, &op, &err_origin);

                if (res == TEEC_SUCCESS) {
                    printf(">> [RESULT] " COLOR_GREEN "VERIFICATION SUCCESS!" COLOR_RESET " Data is authentic.\n");
                    printf(">> [EXTRACTED DATA]: " COLOR_CYAN "%.*s" COLOR_RESET "\n\n", nmea_len, recv_buf);
                } else {
                    printf(">> [RESULT] " COLOR_RED "VERIFICATION FAILED (0x%x)!" COLOR_RESET " Possible tampering.\n\n", res);
                }
            }
        }
    }

    close(sockfd);
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
