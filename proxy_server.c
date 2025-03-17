#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

 #define BUFSIZE 2048
 #define FILENAMESIZE 100
 #define FILETYPESIZE 100
 #define LISTENQ 24
 #define HTTP_REQUEST_FILENAME_START_POSTION 5
 #define WORKINGDIRECTORYPATHSIZE 1000
 #define HTTPVERSIONSIZE 100





//CITATION:  https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c
void signalHandler() {
    printf("SIGNAL HANDLER WORKED\n");
    // pthread_exit(0);
    exit(1);
}

void error(char *msg) {
    perror(msg);
    exit(1);
  }



//CITITATION: BEEJ GUIDE 7.4 sendall function
int sendall(int s, char *buf, int len){
    int total = 0;        
    int bytesleft = len; 
    int n;
    while(total < len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }
    if (n == -1) return -1;
    return total;
} 

//strdup creates a copy of the string
//strtok_r breaks the strings into tokens
int verify_HTTP_Header(char http_req_header[BUFSIZE]) {
    
    char *http_body_separator = strstr(http_req_header, "\r\n\r\n");
    if (http_body_separator == NULL) return 1; //verify double carriage return

    char *saveptr_http_header;
    char* copy_http_req_header = strdup(http_req_header);

    printf("This is the COPY http req header:\n\n%s\n", copy_http_req_header);
    char* http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header); //Will be first line with verb, path, version
    
    char *saveptr_line_http_header;
    char *copy_http_header_line = strdup(http_header_line);
    char *http_verb =  strtok_r(copy_http_header_line, " ", &saveptr_line_http_header);
    char *http_url =  strtok_r(NULL, " ", &saveptr_line_http_header);
    char *http_version =  strtok_r(NULL, " ", &saveptr_line_http_header);

    printf("HTTP Verb: %s\n", http_verb);
    printf("HTTP url: %s\n", http_url);
    printf("HTTP Version: %s\n", http_version);
    
    // while (http_header_line !=NULL) {
    //     printf("This is http header line :\n%s\n", http_header_line);
    //     http_header_line = strtok_r(NULL, "\r\n", &saveptr);
    // }

    return 0;
}

void *handle_connection(void *p_client_socket) {
    int client_socket = * ((int*)p_client_socket);
    free(p_client_socket);

    char buf[BUFSIZE]; 
    FILE *fp; 
    int n; 
    int bytes_read;

    bzero(buf, BUFSIZE);

    n = recv(client_socket, buf, BUFSIZE, 0);
    if (n < 0) error("ERROR in recvfrom\n");
    

    // fp = fopen(filename, "r"); //Checking for file existense and readability happens in buildHTTPResponseHeader
    // n = send(client_socket, response_http_header, strlen(response_http_header), 0);
    verify_HTTP_Header(buf);
    bzero(buf, BUFSIZE); 
    // while (1){
    //   bytes_read = fread(buf, 1, BUFSIZE, fp);
    //   if (bytes_read < 1) {
    //     break;
    //   }
    //   if (sendall(client_socket, buf, BUFSIZE) == -1) {
    //     error("Error in sending file data");
    //   }
    //   bzero(buf, BUFSIZE);
    // } 

    close(client_socket);
    // fclose(fp);
    bzero(buf, BUFSIZE);

    return NULL;
}

//CITATION: https://www.youtube.com/watch?v=Pg_4Jz8ZIH4
/*
void *handle_connection(void *p_client_socket) {
    int client_socket = * ((int*)p_client_socket);
    free(p_client_socket);

    char buf[BUFSIZE]; 
    char filename[FILENAMESIZE];
    char file_type[FILETYPESIZE];
    char http_version[HTTPVERSIONSIZE];
    char responseType[100];
    char http_connection_status[40];
    char content_length[100];
    char response_http_header[200];
    FILE *fp; 
    int n; 
    int bytes_read;

    bzero(buf, BUFSIZE);
    bzero(filename, FILENAMESIZE);
    bzero(file_type, FILETYPESIZE);
    bzero(http_version, HTTPVERSIONSIZE);
    bzero(responseType, 100);
    bzero(http_connection_status, 40);
    bzero(content_length, 100);
    bzero(response_http_header, 200);

    
    n = recv(client_socket, buf, BUFSIZE, 0);
    if (n < 0) error("ERROR in recvfrom\n");
    
    if(buildHTTPResponseHeader(response_http_header, buf, http_version, filename,  file_type, responseType,  http_connection_status, content_length, client_socket) == -1) {
        n = send(client_socket, response_http_header, strlen(response_http_header), 0);
        
        close(client_socket);    
        bzero(buf, BUFSIZE);
        bzero(http_version, HTTPVERSIONSIZE);
        bzero(filename, FILENAMESIZE);    
        bzero(file_type, FILETYPESIZE);    
        bzero(responseType,100);    
        bzero(http_connection_status, 40);
        bzero(content_length, 100);
        bzero(response_http_header, 200);

        return NULL;
    }

    fp = fopen(filename, "r"); //Checking for file existense and readability happens in buildHTTPResponseHeader
    n = send(client_socket, response_http_header, strlen(response_http_header), 0);

    bzero(response_http_header, 200);
    bzero(buf, BUFSIZE); 
    while (1){
      bytes_read = fread(buf, 1, BUFSIZE, fp);
      if (bytes_read < 1) {
        break;
      }
      if (sendall(client_socket, buf, BUFSIZE) == -1) {
        error("Error in sending file data");
      }
      bzero(buf, BUFSIZE);
    } 

    close(client_socket);
    fclose(fp);
    bzero(buf, BUFSIZE);
    bzero(http_version, HTTPVERSIONSIZE);
    bzero(filename, FILENAMESIZE);    
    bzero(file_type, FILETYPESIZE);    
    bzero(responseType,100);    
    bzero(http_connection_status, 40);
    bzero(content_length, 100);
    bzero(response_http_header, 200);


    return NULL;
}
 */



 int main(int argc, char **argv) {
    int listenfd, connfd;
    int portno; 
    int clientlen;
    struct sockaddr_in serveraddr; 
    struct sockaddr_in clientaddr;
    struct hostent *hostp;
    char *hostaddrp;
    int optval;
    int n; 
    char buf[BUFSIZE]; 
 
    if (argc != 2) {
      fprintf(stderr, "usage: %s <port>\n", argv[0]);
      exit(1);
    }
 
    portno = atoi(argv[1]);
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) error("ERROR opening socket\n");
 
    signal(SIGINT, signalHandler);
 
 
    optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
 
 
    
 
 
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)portno);
 
 
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) error("ERROR on binding\n");
    listen (listenfd, LISTENQ);
    clientlen = sizeof(clientaddr);
 
    while (1) {
     connfd = accept(listenfd, (struct sockaddr *) &clientaddr, &clientlen );
     printf("\nconnection from %s, port %d\n", inet_ntop(AF_INET, &clientaddr.sin_addr, buf, sizeof(buf)), ntohs(clientaddr.sin_port) );
     //CITATION: https://www.youtube.com/watch?v=Pg_4Jz8ZIH4
     int *pclient = malloc(sizeof(int));
     *pclient = connfd;
     handle_connection(pclient);
 
     // pthread_t t;
     // pthread_create(&t, NULL, handle_connection, pclient);
     // pthread_detach(t);
    }
 
 
    return 0;
 
    /* WHEN IT IS PTHREAD TIME
    while (1) {
     connfd = accept(listenfd, (struct sockaddr *) &clientaddr, &clientlen );
     printf("\nconnection from %s, port %d\n", inet_ntop(AF_INET, &clientaddr.sin_addr, buf, sizeof(buf)), ntohs(clientaddr.sin_port) );
     //CITATION: https://www.youtube.com/watch?v=Pg_4Jz8ZIH4
     pthread_t t;
     int *pclient = malloc(sizeof(int));
     *pclient = connfd;
     pthread_create(&t, NULL, handle_connection, pclient);
     pthread_detach(t);
    }
    
    pthread_exit(0);
    */
  }