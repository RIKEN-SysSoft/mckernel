#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <memory.h>
#include <unistd.h>
#include "sock.h"
#include "debug.h"

//#define DEBUG_SOCK
#ifdef DEBUG_SOCK
#define dprintf printf
#else
#define dprintf(...)
#endif

int sock_connect(char *server_name, int port, int *listenfd){
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp = NULL;
	int rc = 0, sockfd = -1; 
    // fd for search, after accept (server)
    // for for search, after connect (client)
	char service[6];
    char addrstr[256];

    dprintf("sock_connect,enter\n");

    if(!server_name && *listenfd != -1) { sockfd = *listenfd; goto reuse_listenfd; }

	// set port as service name
	if (sprintf(service, "%d", port) < 0)
    goto sock_connect_exit;

	memset(&hints, 0, sizeof(struct addrinfo));
	if(server_name == NULL){
		hints.ai_flags = AI_PASSIVE; 
	}
	hints.ai_family = AF_UNSPEC;// IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM;//TCP
	hints.ai_protocol = 0; // any protocol
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	// get a list of addresses
	rc = getaddrinfo(server_name, service, &hints, &result);
	if(rc){
		dprintf("%s\n", gai_strerror(rc));
		goto sock_connect_exit;
	}
    dprintf("result=%p\n", result);

	// find a usable address
	for(rp = result; rp != NULL; rp = rp->ai_next){

            inet_ntop(rp->ai_family, rp->ai_addr->sa_data, addrstr, 100);
            void *ptr;
            switch(rp->ai_family) {
            case AF_INET:
                printf("ai_family=AF_INET\n");
                ptr= &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
                break;
            default:
                dprintf("ai_family=%08x\n", rp->ai_family);
            }
            inet_ntop(rp->ai_family, ptr, addrstr, 100);

            printf("trying to use addr=%s,port=%d\n", addrstr,port);
    }

	for(rp = result; rp != NULL; rp = rp->ai_next){
        
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(sockfd == -1)
            continue;
        
		// set socket reusable
		int on = 1;
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
			continue;

		// server mode
		if(server_name == NULL){
            inet_ntop(rp->ai_family, rp->ai_addr->sa_data, addrstr, 100);
            void *ptr;
            switch(rp->ai_family) {
            case AF_INET:
                dprintf("ai_family=AF_INET\n");
                ptr= &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
                break;
            default:
                dprintf("ai_family=%08x\n", rp->ai_family);
            }
            inet_ntop(rp->ai_family, ptr, addrstr, 100);

            printf("server mode,addr=%s,port=%d\n", addrstr,port);
			if(bind(sockfd, rp->ai_addr, rp->ai_addrlen) != 0)
				continue;
        reuse_listenfd:
            printf("listen=%d\n", sockfd);
			if(listen(sockfd, 1) != 0)
				continue;
			/* connect successfully */
			if(*listenfd == -1) { *listenfd = sockfd; }
			sockfd = accept(sockfd, NULL, NULL);
            printf("accept=%d\n", sockfd);
			goto sock_connect_success;

		// client mode
		}else{
            inet_ntop(rp->ai_family, rp->ai_addr->sa_data, addrstr, 100);
            void *ptr;
            switch(rp->ai_family) {
            case AF_INET:
                printf("ai_family=AF_INET\n");
                ptr= &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
                break;
            default:
                dprintf("ai_family=%08x\n", rp->ai_family);
            }
            inet_ntop(rp->ai_family, ptr, addrstr, 100);

            printf("client mode,addr=%s,port=%d\n", addrstr,port);
			rc = connect(sockfd, rp->ai_addr, rp->ai_addrlen);

			if(rc == 0) { 
                printf("connect succeeded,fd=%d\n", sockfd);
                goto sock_connect_success;
            } else {
                printf("connect failed, trying to use next\n");
            }
		}
	}

    //sock_connect_failure:
	if(rp == NULL){
		error_printf("All trial failed\n");
		sockfd = -1;
		goto sock_connect_exit;
	}
 sock_connect_success:
 sock_connect_exit:
#if 0
		if(listenfd > 0)
			close(listenfd);
#endif
		if(result)
			freeaddrinfo(result);
	return sockfd;	
}

int sock_sync_data(int sock, int data_bytes, char *local_data, char *remote_data){
	int rc = 0;
	int read_bytes = 0;
	// write to sock
	rc = write(sock, local_data, data_bytes);
	if(rc != data_bytes){
		rc =_SOCK_WRITE_ERR;
		goto sock_sync_data_exit;
	}

	// read from sock	
	rc = 0;
	while(!rc && read_bytes < data_bytes){
		rc = read(sock, remote_data, data_bytes);
		if(rc > 0){ 
			read_bytes += rc;
			rc = 0;
		}else{
			rc =_SOCK_READ_ERR;
			goto sock_sync_data_exit;
		}
	}

	sock_sync_data_exit:
	return rc;
}


