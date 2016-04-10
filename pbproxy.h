#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

struct proxy_data {
	char *key;
	struct sockaddr_in rep_add;
	int new_sock;
};

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};
