#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#define PACKETSIZE 4096

struct proxy_data {
	char *key;
	struct sockaddr_in rep_add;
	int new_sock;
};

struct ctr_state {
	unsigned char IVec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};
