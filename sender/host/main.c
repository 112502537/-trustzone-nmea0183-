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

/* Define communication parameters */
#define LISTEN_PORT 1234
#define DEST_IP "192.168.10.2"
#define DEST_PORT 5555
#define MAX_SIG_SIZE 256

#define COLOR_YELLOW	"\x1b[33m"
#define COLOR_RESET	"\x1b[0m"
#define COLOR_CYAN	"\x1b[1;36m"

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
	uint8_t modulus[256], exponent[4];
    	uint8_t final_packet[2048];
	struct sockaddr_in servaddr, dest_addr;

	/* Initialize TEE */
    	res = TEEC_InitializeContext(NULL, &ctx);
    	if (res != TEEC_SUCCESS) errx(1, "InitializeContext failed");

    	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    	if (res != TEEC_SUCCESS) errx(1, "OpenSession failed");

	/* Key management */

    	// Generate key pairs
    	printf("[CA] CMD_GEN_KEY: Ensuring RSA keypair exists...\n");
    	res = TEEC_InvokeCommand(&sess, CMD_GEN_KEY, NULL, &err_origin);
    	if (res != TEEC_SUCCESS) errx(1, "Key generation failed");

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        	perror("Socket creation failed");
        	return -1;
    	}

    	memset(&servaddr, 0, sizeof(servaddr));
    	servaddr.sin_family = AF_INET;
    	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    	servaddr.sin_port = htons(LISTEN_PORT);

    	if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        	perror("Bind failed");
        	return -1;
    	}

    	memset(&dest_addr, 0, sizeof(dest_addr));
    	dest_addr.sin_family = AF_INET;
    	dest_addr.sin_port = htons(DEST_PORT);
    	inet_pton(AF_INET, DEST_IP, &dest_addr.sin_addr);


    	// Get public key
    	printf("[CA] CMD_GET_PUBLIC_KEY: Exporting public key for verifier...\n");
    	memset(&op, 0, sizeof(op));
    	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    	op.params[0].tmpref.buffer = modulus;
    	op.params[0].tmpref.size = 256;
    	op.params[1].tmpref.buffer = exponent;
    	op.params[1].tmpref.size = 4;

    	res = TEEC_InvokeCommand(&sess, CMD_GET_PUBLIC_KEY, &op, &err_origin);
    	if (res == TEEC_SUCCESS) {
		// Send the public key to the receiver
		uint32_t mod_len = op.params[0].tmpref.size;
    		uint32_t exp_len = op.params[1].tmpref.size;

		uint8_t pubkey_packet[300];
		memcpy(pubkey_packet, "PUBKEY:", 7);
		memcpy(pubkey_packet + 7, modulus, mod_len);
		memcpy(pubkey_packet + 7 + mod_len, exponent, exp_len);
		sendto(sockfd, pubkey_packet, 7 + mod_len + exp_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    	}
    	else {
		printf("[CA] Failed to get public key: 0x%x\n", res);
    	}

	while(1){
		printf("[CA] Waiting the msg from Simulation...\n");
		int n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, NULL, NULL);
		if (n < 0) {
    			perror("recvfrom error");
    			continue;
		}
		printf("[CA] Received msg: " COLOR_YELLOW "%.20s..." COLOR_RESET "\n", buffer);
        	buffer[n] = '\0';
        	if (buffer[0] != '$') continue;


		memset(&op, 0, sizeof(op));
        	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        	op.params[0].tmpref.buffer = buffer;
        	op.params[0].tmpref.size = n;
        	op.params[1].tmpref.buffer = sign_buffer;
        	op.params[1].tmpref.size = MAX_SIG_SIZE;

        	res = TEEC_InvokeCommand(&sess, CMD_SIGN_DATA, &op, &err_origin);

        	if (res == TEEC_SUCCESS) {
            		uint32_t sig_len = op.params[1].tmpref.size;

            		// [NMEA] + " SIG:" + [Binary Signature]
            		memcpy(final_packet, buffer, n);
            		memcpy(final_packet + n, " SIG:", 5);
            		memcpy(final_packet + n + 5, sign_buffer, sig_len);

            		sendto(sockfd, final_packet, n + 5 + sig_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            		printf("[CA] Sent signed NMEA: " COLOR_CYAN "%.20s..." COLOR_RESET "\n", buffer);
		}
	}

	close(sockfd);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
