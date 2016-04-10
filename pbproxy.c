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

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

struct proxy_data {
	char *key;
	struct sockaddr_in rep_add;
	int new_sock;
};

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
	printf("New server proxy thread\n");
	while (1)
		;

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
	int client_fd = -1;
	int n 		  = 0;

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

	while (true) {

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
				printf("Check options\n");
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
