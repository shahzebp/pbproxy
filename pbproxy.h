#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#define PACKETSIZE 	4096
#define IVSIZE		8

struct proxy_data {
	int 				new_sock;
	char 				*key;
	struct sockaddr_in 	final_add;
};

struct ctr_state {
	unsigned char 	IVec[AES_BLOCK_SIZE];  
	unsigned int 	num; 
	unsigned char 	ecount[AES_BLOCK_SIZE]; 
};
