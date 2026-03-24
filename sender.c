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
#include <sender_ta.h>

// 定義目標主機資訊
#define DEST_IP "192.168.1.100"  // 另一台主機的實際 IP
#define DEST_PORT 5555           // 另一台主機 CA 監聽的連接埠
#define MAX_SIG_SIZE 256         // 假設的簽章長度

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SENDER_UUID;
	uint32_t err_origin;

	int sockfd;
	char buffer[1024];
	uint8_t sign_buffer[MAX_SIG_SIZE];
	char final_packet[1500]; // 組合後的封包緩衝區
	struct sockaddr_in servaddr, cliaddr, dest_addr;
	socklen_t len;

	/* 初始化 TEE Context & Session */
	res = TEEC_InitializeContext(NULL, &ctx);
	if(res != TEEC_SUCCESS) errx(1, "InitializeContext failed");

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if(res != TEEC_SUCCESS) errx(1, "OpenSession failed");

	/* 準備 UDP Socket */
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("socket creation failed");
		return -1;
	}

	// 設定本地監聽 (接收訊息)
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(1234);

	if(bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		perror("bind failed");
		close(sockfd);
		return -1;
	}

	// 設定目標主機的資訊
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(DEST_PORT);
	if(inet_pton(AF_INET, DEST_IP, &dest_addr.sin_addr) <= 0){
		perror("Invalid destination IP address");
		return -1;
	}

	printf("CA is running. Listening on 1234 and sending to %s:%d\n", DEST_IP, DEST_PORT);

	while(1){
		len = sizeof(cliaddr);
		int n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&cliaddr, &len);

		if(n <= 0) continue;
		buffer[n] = '\0';

		// 檢查 NMEA 格式
		if(buffer[0] != '$') continue;

		/* 設定 TA 簽章參數 (Param 0: Input, Param 1: Output) */
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
										 TEEC_MEMREF_TEMP_OUTPUT,
										 TEEC_NONE, TEEC_NONE);

		op.params[0].tmpref.buffer = buffer;
		op.params[0].tmpref.size = n;
		op.params[1].tmpref.buffer = sign_buffer;
		op.params[1].tmpref.size = MAX_SIG_SIZE;

		printf("[CA] Requesting Signature from TA...\n");
		res = TEEC_InvokeCommand(&sess, TA_SENDER_PRINT_MSG, &op, &err_origin);

		if(res == TEEC_SUCCESS){
			uint32_t sig_len = op.params[1].tmpref.size;

			/* 封裝封包：原始訊息 + 分隔符 + 二進制簽章 */
			int header_len = sprintf(final_packet, "%s\nSIGNATURE:", buffer);
			memcpy(final_packet + header_len, sign_buffer, sig_len);
			int total_send_size = header_len + sig_len;

			/* 發送給另一台主機的 CA */
			int send_res = sendto(sockfd, final_packet, total_send_size, 0,
								  (struct sockaddr *)&dest_addr, sizeof(dest_addr));

			if(send_res < 0){
				perror("[CA] sendto failed");
			}
			else{
				printf("[CA] Data + Signature sent to %s:%d\n", DEST_IP, DEST_PORT);
			}
		}
		else{
			printf("[CA] TA signing failed: 0x%x\n", res);
		}
	}

	close(sockfd);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
