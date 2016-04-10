all: clean pbproxy 

pbproxy: pbproxy.c
	gcc -ggdb3 pbproxy.c -o pbproxy -Werror -lcrypto -lpthread

clean:
	rm -f *~ *.o *.out

