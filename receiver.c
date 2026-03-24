#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <tee_client_api.h>
#include <receiver_ta.h>

#define LISTEN_PORT 1234
#define MAX_PKT_SIZE 1500
#define SIG_MARKER "\nSIGNATURE:"

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_RECEIVER_UUID;
	uint32_t err_origin;

	int sockfd;
	char full_packet[MAX_PKT_SIZE];
	struct sockaddr_in servaddr, cliaddr;
	socklen_t len;

	/* 1. 初始化 TEE Context & Session */
	res = TEEC_InitializeContext(NULL, &ctx);
	if(res != TEEC_SUCCESS) errx(1, "TEEC_InitializeContext failed");

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if(res != TEEC_SUCCESS) errx(1, "TEEC_OpenSession failed");

	/* 2. 準備 UDP Socket 監聽 1234 */
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("socket creation failed");
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(LISTEN_PORT);

	if(bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		perror("bind failed");
		close(sockfd);
		return -1;
	}

	printf("[Receiver CA] Listening on UDP port %d...\n", LISTEN_PORT);

	while(1){
		len = sizeof(cliaddr);
		int n = recvfrom(sockfd, full_packet, MAX_PKT_SIZE, 0, (struct sockaddr *)&cliaddr, &len);

		if(n <= 0) continue;

		/* 3. 解析封包：尋找分隔符 \nSIGNATURE: */
		char *sig_ptr = memmem(full_packet, n, SIG_MARKER, strlen(SIG_MARKER));

		if (sig_ptr == NULL) {
			printf("[Receiver CA] Invalid packet: No signature marker found.\n");
			continue;
		}

		// 計算原始訊息長度 (分隔符之前的部分)
		size_t msg_len = sig_ptr - full_packet;
		// 計算簽章長度 (分隔符之後的部分)
		size_t sig_start_offset = msg_len + strlen(SIG_MARKER);
		size_t sig_len = n - sig_start_offset;

		// 暫時將原始訊息結尾設為 \0 以便印出
		char original_msg[1024];
		if (msg_len < sizeof(original_msg)) {
			memcpy(original_msg, full_packet, msg_len);
			original_msg[msg_len] = '\0';
			printf("\n[Receiver CA] Received NMEA: %s\n", original_msg);
		}

		/* 4. 準備 TA 驗證參數 (Param 0: 訊息, Param 1: 簽章) */
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, // 原始數據
										 TEEC_MEMREF_TEMP_INPUT, // 簽章數據
										 TEEC_NONE, TEEC_NONE);

		op.params[0].tmpref.buffer = full_packet;
		op.params[0].tmpref.size = msg_len;
		op.params[1].tmpref.buffer = full_packet + sig_start_offset;
		op.params[1].tmpref.size = sig_len;

		printf("[Receiver CA] Forwarding to TA for verification...\n");

		// 呼叫接收端 TA 的驗證指令
		res = TEEC_InvokeCommand(&sess, TA_RECEIVER_VERIFY_SIG, &op, &err_origin);

		if(res == TEEC_SUCCESS){
			printf("[Receiver CA] ★★★ Verification SUCCESS: Data is authentic. ★★★\n");
		} else {
			printf("[Receiver CA] ✘✘✘ Verification FAILED: 0x%x ✘✘✘\n", res);
		}
	}

	/* 清理資源 */
	close(sockfd);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
