#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "pbproxy.h"

int init_ctr(struct ctr_state *state, const unsigned char IV[8]) {

	state->num = 0;

	memset(state->ecount, 0, AES_BLOCK_SIZE);

	memset(state->IVec + 8, 0, 8);

	memcpy(state->IVec, IV, 8);
}

char * read_key(const char *filename) {

    long int size = 0;
    
    FILE *file = fopen(filename, "r");

    if (!file) {
        fprintf(stderr, "Open error for key file\n");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    char *result = (char *) malloc(size);
    
    if (!result) {
        fprintf(stderr, "Memory error for key allocation\n");
        return NULL;
    }

    if (fread(result, 1, size, file) != size) {
        fprintf(stderr, "Read error in key file\n");
        return NULL;
    }

    fclose(file);
    
    return result;
}

bool send_encr(char *raw_buffer, int n, int fd, AES_KEY * act_key){

	struct 	ctr_state 	state;
	unsigned char 		IV[8];
	unsigned char 		encryption[n];

	if(!RAND_bytes(IV, 8)) {
		fprintf(stderr, "Error generating random bytes\n");
		return false;
	}

	char *tmp = (char*) malloc(n + 8);
	memcpy(tmp, IV, 8);
	
	init_ctr(&state, IV);
	
	AES_ctr128_encrypt(raw_buffer, encryption, n, act_key, state.IVec,
		state.ecount, &state.num);

	memcpy(tmp + 8, encryption, n);
	
	write(fd, tmp, n + 8);
	
	free(tmp);

	return true;
}

bool recv_decr(char *raw_buffer, int n, int fd, AES_KEY * act_key) {

	struct 	ctr_state 	state;
	unsigned char 		IV[8];
	unsigned char 		decryption[n-8];

	memcpy(IV, raw_buffer, 8);

	init_ctr(&state, IV);
		
	AES_ctr128_encrypt(raw_buffer + 8, decryption, n - 8, act_key, state.IVec,
		state.ecount, &state.num);
		
	write(fd, decryption, n-8);

	return true;
}

void * server_routine(void * ptr) {

	pthread_detach(pthread_self());

	int 		accepted_session_fd = -1, n = 0;
	char 		buffer[PACKETSIZE];
	int 		flags;
	bool 		ssh_done = false;
	AES_KEY 	act_key;

	printf("New server proxy thread\n");

	struct proxy_data *p_data = (struct proxy_data *)ptr;

	accepted_session_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (-1 == connect(accepted_session_fd, (struct sockaddr *)&p_data->rep_add,
		sizeof(p_data->rep_add))) {
		fprintf(stderr, "Accepted Session Connect failed\n");
		fprintf(stderr, "Check of open ports\n");
		pthread_exit(NULL);
	} else
		printf("Connection Established Successfully\n");

	if (-1 == (flags = fcntl(p_data->new_sock, F_GETFL)))
		pthread_exit(NULL);

	fcntl(p_data->new_sock, F_SETFL, flags | O_NONBLOCK);

	if (-1 == (flags = fcntl(accepted_session_fd, F_GETFL)))
		pthread_exit(NULL);

	fcntl(accepted_session_fd, F_SETFL, flags | O_NONBLOCK);

	memset(buffer, 0, sizeof(buffer));
	
	if (AES_set_encrypt_key(p_data->key, 128, &act_key) < 0) {
		fprintf(stderr, "Set encryption key error!\n");
		exit(1);
	}
	
	while (1) {
		while ((n = read(p_data->new_sock, buffer, PACKETSIZE)) >= 0) {
			if (n == 0)
				pthread_exit(NULL);

			recv_decr(buffer, n, accepted_session_fd, &act_key);

			if (n < PACKETSIZE)
				break;
		}

		while ((n = read(accepted_session_fd, buffer, PACKETSIZE)) > 0) {
			
			if (n == 0)
				pthread_exit(NULL);

			if (n > 0)
				send_encr(buffer, n, p_data->new_sock, &act_key);
			
			if (ssh_done == false && n == 0)
				ssh_done = true;
			
			if (n < PACKETSIZE)
				break;
		}

		if (ssh_done)
			break;
	}

	pthread_exit(0);
}

void service_proxy(int listen_port, int dest_port, struct hostent * dest_entry,
			char *key) {

	pthread_t 			server_thread;
	int 				server_fd = -1;

	struct sockaddr_in 	serv_addr, rep_add;
	
	server_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= INADDR_ANY;
	serv_addr.sin_port 	 		= htons(listen_port);

	rep_add.sin_family			= AF_INET;
	rep_add.sin_addr.s_addr 	= ((struct in_addr *)
									(dest_entry->h_addr))->s_addr;
	rep_add.sin_port			= htons(dest_port);

	if (0 > bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
		fprintf(stderr, "Unable to bind the address\n");
		return;
	}

	if (0 > listen(server_fd, 10)) {
		fprintf(stderr, "Error in listening\n");
		return;
	}

	while (true) {
		struct sockaddr_in 		dest_addr;
		socklen_t 				len;
		int 					accepted_fd = -1;

		len = sizeof(dest_addr);

		if (0 > (accepted_fd = accept(server_fd, (struct sockaddr *)&dest_addr,
						&len))) {

			fprintf (stderr, "Error in accepting\n");	
			return;
		}

		struct proxy_data *p_data = (struct proxy_data *) malloc (
				sizeof(struct proxy_data));

		p_data->rep_add 	= rep_add;
		p_data->key 		= key;
		p_data->new_sock 	= accepted_fd;

		pthread_create(&server_thread, NULL, server_routine, (void *)p_data);
	}
}


void service_client(int dest_port, struct hostent * dest_entry, char *key) {

	AES_KEY 			act_key;

	int 				client_fd = -1, n = 0;
	struct 	sockaddr_in serv_addr, rep_add;	
	char 				buffer[PACKETSIZE];
	
	client_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_port 			= htons(dest_port);
	serv_addr.sin_addr.s_addr 	= ((struct in_addr *)
								(dest_entry->h_addr))->s_addr;
		
	if (-1 == connect(client_fd, (struct sockaddr *)&serv_addr,
			sizeof(serv_addr))) {

		fprintf(stderr, "Connection failed. Check if dest port is open\n");
		return;
	}

	printf ("Connection successfull\n");

	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	fcntl(client_fd, F_SETFL, O_NONBLOCK);
	
	if (AES_set_encrypt_key(key, 128, &act_key) < 0) {
		fprintf(stderr, "Set encryption key error\n");
		return;
	}	

	//TODO MORE ERROR CHECKING IN LOOP AND CLEANUP
	while (true) {
		while ((n = read(STDIN_FILENO, buffer, PACKETSIZE)) > 0) {

			send_encr(buffer, n, client_fd, &act_key);

			if (n < PACKETSIZE)
				break;
		}

		while ((n = read(client_fd, buffer, PACKETSIZE)) > 0) {

			recv_decr(buffer, n, STDOUT_FILENO, &act_key);

			if (n < PACKETSIZE)
				break;
		}
	}
}

int main (int argc, char *argv[]) {

	int 	option 		= 0;
	int 	listen_port	= -1;
	bool 	proxy_mode 	= false;
	char	key_file[PACKETSIZE];

	char	dest_entry[PACKETSIZE];
	int 	dest_port	= -1;

	while((option = getopt(argc, argv, "l:k:")) != -1) {
		switch(option) {
			case 'l':
				listen_port = atoi(optarg);
				proxy_mode  = true;
				break;
			case 'k':
				strcpy(key_file, optarg);
				break;
			case '?':
				printf("Unknown option\n");
				break;
			default:
				printf("Check options\nExiting\n");
				return 0;
		}
	}

	strcpy(dest_entry, argv[optind]);

	dest_port	 = atoi(argv[optind + 1]);

	char * key = read_key(key_file);

	if (!key) {
		fprintf(stderr, "%s\n", "Improper Key");
		return 0;
	}

	struct hostent *destination_entry =  NULL;

	destination_entry = gethostbyname(dest_entry);

	if (!destination_entry) {
		fprintf (stderr, "Couldnt resolve host address\n");
		return 0;
	}

	if (proxy_mode)
		service_proxy(listen_port, dest_port, destination_entry, key);
	else
		service_client(dest_port, destination_entry, key);

	return 0;
}
