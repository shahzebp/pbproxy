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

#include <pbproxy.h>

int init_ctr(struct ctr_state *state, const unsigned char iv[8]) {

	state->num = 0;

	memset(state->ecount, 0, AES_BLOCK_SIZE);

	memset(state->ivec + 8, 0, 8);

	memcpy(state->ivec, iv, 8);
}

char * read_key(const char *filename) {

    long int size = 0;
    FILE *file = fopen(filename, "r");

    if(!file) {
        fputs("File error.\n", stderr);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    char *result = (char *) malloc(size);
    if(!result) {
        fputs("Memory error.\n", stderr);
        return NULL;
    }

    if(fread(result, 1, size, file) != size) {
        fputs("Read error.\n", stderr);
        return NULL;
    }

    fclose(file);
    return result;
}

void * server_routine(void * ptr) {

	pthread_detach(pthread_self());

	int accepted_session_fd = -1, n = 0;
	char buffer[4096];
	int flags;
	bool ssh_done = false;

	printf("New server proxy thread\n");

	struct proxy_data *p_data = (struct proxy_data *)ptr;

	accepted_session_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (connect(accepted_session_fd, (struct sockaddr *)&p_data->rep_add,
		sizeof(p_data->rep_add)) == -1) {
		printf("Connect failed\n");
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

	struct ctr_state state;
	AES_KEY aes_key;
	unsigned char iv[8];
	
	if (AES_set_encrypt_key(p_data->key, 128, &aes_key) < 0) {
		fprintf(stderr, "Set encryption key error!\n");
		exit(1);
	}
	
	while (1) {
		while ((n = read(p_data->new_sock, buffer, 4096)) >= 0) {
			if (n == 0)
				pthread_exit(NULL);

			memcpy(iv, buffer, 8);

			unsigned char decryption[n-8];
			init_ctr(&state, iv);

			AES_ctr128_encrypt(buffer+8, decryption, n-8, &aes_key, state.ivec, state.ecount, &state.num);

			write(accepted_session_fd, decryption, n-8);

			if (n < 4096)
				break;
		}

		while ((n = read(accepted_session_fd, buffer, 4096)) > 0) {
			
			if (n == 0)
				pthread_exit(NULL);

			if (n > 0) {
				if(!RAND_bytes(iv, 8)) {
					fprintf(stderr, "Error generating random bytes.\n");
					exit(1);
				}
				char *tmp = (char*)malloc(n + 8);
				memcpy(tmp, iv, 8);
				
				unsigned char encryption[n];
				init_ctr(&state, iv);
				AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(tmp+8, encryption, n);
				
				write(p_data->new_sock, tmp, n + 8);
				
				free(tmp);
			}
			
			if (ssh_done == false && n == 0)
				ssh_done = true;
			
			if (n < 4096)
				break;
			
		}
		if (ssh_done)
			break;
	}

	pthread_exit(0);

}

void service_proxy(int listen_port, int dest_port,
		struct hostent * dest_address, char *key) {

	pthread_t server_thread;

	struct sockaddr_in serv_addr, rep_add;
	int server_fd = -1;

	server_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port 	 = htons(listen_port);

	rep_add.sin_family	= AF_INET;
	rep_add.sin_addr.s_addr = ((struct in_addr *)(dest_address->h_addr))->s_addr;
	rep_add.sin_port	= htons(dest_port);

	bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

	if (listen(server_fd, 10) < 0) {
		printf("Error in listening\n");
		return;
	}

	for(;;) {
		struct sockaddr_in cli_addr;
		socklen_t clilen;
		int accepted_fd = -1;

		clilen = sizeof(cli_addr);
		printf("Ready to accept connections\n");
		accepted_fd = accept(server_fd, (struct sockaddr *)&cli_addr,
						&clilen);

		if (accepted_fd < 0) {
			printf ("Error in accepting\n");	
			return;
		}

		struct proxy_data *p_data = (struct proxy_data *) malloc (
				sizeof(struct proxy_data));
		p_data->rep_add = rep_add;
		p_data->key 	= key;
		p_data->new_sock = accepted_fd;

		pthread_create(&server_thread, NULL, server_routine,
					(void *)p_data);
	}

}

void service_client(int dest_port, struct hostent * dest_address, char *key) {
	
	int client_fd = -1, n = 0;

	client_fd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in serv_addr, rep_add;

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(dest_port);
	serv_addr.sin_addr.s_addr = ((struct in_addr *)
								(dest_address->h_addr))->s_addr;
		
	if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))
		 == -1) {
		printf("Connection failed!\n");
		return;
	}

	printf ("Connection successfull\n");

	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	fcntl(client_fd, F_SETFL, O_NONBLOCK);

	char buffer[4096];

	struct ctr_state state;
	unsigned char iv[8];
	AES_KEY aes_key;
	
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		printf("Set encryption key error!\n");
		return;
	}	

	while (true) {
		while ((n = read(STDIN_FILENO, buffer, 4096)) > 0) {

			if(!RAND_bytes(iv, 8)) {
					printf("Error generating random bytes.\n");
					return;
			}

			char *tmp = (char*) malloc(n + 8);
			memcpy(tmp, iv, 8);
			
			unsigned char encryption[n];
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec,
				state.ecount, &state.num);
			memcpy(tmp + 8, encryption, n);
			write(client_fd, tmp, n + 8);
			free(tmp);

			if (n < 4096)
				break;
		}

		while ((n = read(client_fd, buffer, 4096)) > 0) {

			memcpy(iv, buffer, 8);

			unsigned char decryption[n-8];
			init_ctr(&state, iv);
				
			AES_ctr128_encrypt(buffer + 8, decryption, n - 8, &aes_key, state.ivec,
				state.ecount, &state.num);
				
			write(STDOUT_FILENO, decryption, n-8);

			if (n < 4096)
				break;
		}

	}
}

int main (int argc, char *argv[]) {

	int 	option 		= 0;
	int 	listen_port	= -1;
	bool 	proxy_mode 	= false;
	char	key_file[4096];

	char	dest_address[4096];
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

	strcpy(dest_address, argv[optind]);

	dest_port	 = atoi(argv[optind + 1]);

	char * key = read_key(key_file);

	struct hostent *destination_name =  NULL;

	destination_name = gethostbyname(dest_address);

	if (!destination_name) {
		printf ("Couldnt resolve host address\n");
		return 0;
	}

	if (proxy_mode)
		service_proxy(listen_port, dest_port, destination_name, key);
	else
		service_client(dest_port, destination_name, key);

	return 0;

}
