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

// CITATION: https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
#include <openssl/md5.h>


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
    exit(EXIT_FAILURE);
}

void error(char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
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

//Verify the HTTP Request Header: Verify double carriage return, No other Method but GET used, and Host Name resolves to IP Address
int verify_HTTP_Req_Header(char http_req_header[BUFSIZE]) {
    struct hostent *req_host;
    char *http_body_separator;
    char *saveptr_http_header;
    char* copy_http_req_header;
    char* http_header_line;
    char *saveptr_line_http_header;
    char *copy_http_header_line; 
    char *http_verb;
    char *http_url;
    char *http_version; 
    char *saveptr_line_host;
    char *copy_header_line_host;
    char *host_name;


    http_body_separator = strstr(http_req_header, "\r\n\r\n");
    if (http_body_separator == NULL){
        //TODO: Need to put a 400 Bad Request
        printf("The HTTP Body does not have a double carriage return. Improperly formatted"); 
        return 1; 
    }

    copy_http_req_header = strdup(http_req_header);//TODO: chek if strdup fails
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header); //TODO: Check if it fails ?    
    copy_http_header_line = strdup(http_header_line);//TODO: chek if strdup fails
    http_verb =  strtok_r(copy_http_header_line, " ", &saveptr_line_http_header);
    http_url =  strtok_r(NULL, " ", &saveptr_line_http_header); //TODO: Delete ? Unsure if I am checking these
    http_version =  strtok_r(NULL, " ", &saveptr_line_http_header);// TODO: delete? 

    if (strcasecmp(http_verb, "GET") != 0){
        printf("The verb was not GET\n");
        return 1;
    } 

    http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header); 
    copy_header_line_host = strdup(http_header_line);//TODO: chek if strdup fails
    strtok_r(copy_header_line_host, " ", &saveptr_line_host);
    host_name = strtok_r(NULL, " ", &saveptr_line_host);
    req_host = gethostbyname(host_name); //TODO: Replace with getaddrinfo since gethostbyname is not thread safe

    if (req_host == NULL) {//if there is no ip address, req_host will be NULL
        //TODO: NEED to put 404 NOT Found
        printf("gethostbyname returned NULL.\n");
        return 1;
    }


    //TODO: http method verification ????

    //TODO: Check for Content Length! Need to do!

    return 0;
}

int grabContentLength(char http_res_header[BUFSIZE]) {
    char *content_length_exists;
    char *saveptr_http__res_header;
    char* copy_http_res_header;
    char* http_header_line;
    char *saveptr_content_length_line;
    char *char_content_length;
    int content_length;
    
    // TODO: Build a function verifynig the response header???
    // printf("http_res_header: \n%s\n", http_res_header);
    content_length_exists = strstr(http_res_header, "Content-Length");
    if (content_length_exists == NULL){
        printf("Content-Length Does not Exist.\n"); 
        return -1; 
    }

    copy_http_res_header = strdup(http_res_header);//TODO: chek if strdup fails
    http_header_line = strtok_r(copy_http_res_header, "\r\n", &saveptr_http__res_header); //TODO: Check if it fails ?    

    while (1) {
        content_length_exists = strstr(http_header_line, "Content-Length"); //TODO: Concerned if the content-length is spelled differently
        if (content_length_exists != NULL) break;
        http_header_line = strtok_r(NULL, "\r\n", &saveptr_http__res_header); //TODO: Check if it fails ?    
    }

    char_content_length = strtok_r(http_header_line, " ", &saveptr_content_length_line);
    char_content_length = strtok_r(NULL, " ", &saveptr_content_length_line);
    content_length = atoi(char_content_length);
    return content_length;
}

int grabFileName(char http_res_header[BUFSIZE], char file_name[200]) {
    char *saveptr_http__res_header;
    char* copy_http_res_header;
    char* http_header_line;
    char *saveptr_http_res_url;
    char *http_res_url;
    
    // TODO: Build a function verifynig the response header???
    copy_http_res_header = strdup(http_res_header);//TODO: chek if strdup fails
    http_header_line = strtok_r(copy_http_res_header, "\r\n", &saveptr_http__res_header); //TODO: Check if it fails ?  
    http_res_url = strtok_r(http_header_line, " ", &saveptr_http_res_url); //TODO: Check if it fails ?  
    http_res_url = strtok_r(NULL, " ", &saveptr_http_res_url); //TODO: Check if it fails ?  
    strncpy(file_name, http_res_url, strlen(http_res_url));
    return 0;
}

//CITATION of str2md5: https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c. 
char *str2md5(const char *str, int length) {
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = (char*)malloc(33);
    MD5_Init(&c);
    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }
    MD5_Final(digest, &c);
    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }
    return out;
}

int writeFileToCache(FILE *fp, char http_res[BUFSIZE], char full_path[400], int n, int content_length, int client_sockfd, int http_res_body_bytes_recv, int http_res_header_bytes){
    //START OF RECEIVING HTTP FROM SERVER AND WRITING IT TO FILE
    fwrite(http_res + http_res_header_bytes, 1, (n - http_res_header_bytes), fp);

    while (http_res_body_bytes_recv < content_length) {
        n =  recv(client_sockfd, http_res, BUFSIZE, 0);
        if ( (n+ http_res_body_bytes_recv) > content_length) {
            char remainder_of_body[2048];
            strncpy(remainder_of_body, http_res, n - (n+http_res_body_bytes_recv-content_length) );
            fwrite(remainder_of_body, 1, (n - (n+http_res_body_bytes_recv-content_length)), fp);

            http_res_body_bytes_recv = http_res_body_bytes_recv + n - (n+http_res_body_bytes_recv-content_length) ;
            // printf("content_length: %d, n: %d, http_res_header_bytes: %d, http_res_body_bytes_recv: %d\n", content_length,n, http_res_header_bytes, http_res_body_bytes_recv);
            //TODO: the print statement below may go below the body by a byte or two. Need to recheck if my files end up not matching by a byte 
            // printf("IF AFTER RECV:remainder_of_body: \n%s\n", remainder_of_body); 
            break;
        }else {
            http_res_body_bytes_recv = http_res_body_bytes_recv + n;
            fwrite(http_res, 1, n, fp);

            // printf("content_length: %d, n: %d, http_res_header_bytes: %d, http_res_body_bytes_recv: %d\n", content_length,n, http_res_header_bytes, http_res_body_bytes_recv);
            // printf("ELSE AFTER RECV:BUF: \n%s\n", buf); 
        }
    }

    if (fclose(fp) !=0) printf("Error closing the file\n");
    //END OF RECEIVING HTTP FROM SERVER AND WRITING IT TO FILE
    return 0;
}

void *handle_connection(void *p_client_socket) {
    int client_socket = * ((int*)p_client_socket);
    free(p_client_socket);

    char buf[BUFSIZE]; 
    FILE *fp; 
    int n; 

    int portno;
    int client_sockfd;
    int optval;
    int clientlen;
    struct sockaddr_in serveraddr; 
    struct sockaddr_in clientaddr;
    struct hostent *hostp;
    char *hostaddrp;

    struct hostent *req_host;
    char *saveptr_http_header;
    char* copy_http_req_header;
    char* http_header_line;
    char *saveptr_line_host;
    char *header_line_host;
    char *host_name;
    char *http_res_ends;

    char file_name[200];
    char full_path[400];
    int content_length;
    int http_res_body_bytes_recv = 0;
    int http_res_header_bytes;

    char *md5_file_name;

    bzero(buf, BUFSIZE);

    n = recv(client_socket, buf, BUFSIZE, 0);
    if (n < 0) error("ERROR in recvfrom\n");
    
    if (verify_HTTP_Req_Header(buf) !=0) {
        printf("Verify HTTP Req Header had some error\n");
        error("HTTP Verification Failed");
        // return 1;
    }

    //TODO: Create a second socket and send a request to the specified server
    
    copy_http_req_header = strdup(buf);//TODO: chek if strdup fails
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header); //TODO: Check if it fails ?  
    
    http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header); 
    header_line_host = strdup(http_header_line);//TODO: chek if strdup fails
    strtok_r(header_line_host, " ", &saveptr_line_host);
    host_name = strtok_r(NULL, " ", &saveptr_line_host);
    req_host = gethostbyname(host_name); //TODO: Replace with getaddrinfo since gethostbyname is not thread safe

    // printf("req_host.h_addr_list[0]: %s\n", req_host->h_addr_list[0]);

    // portno = atoi(argv[1]);
    portno = 80; //TODO: Build in functionality for the user setting the port
    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd < 0) error("ERROR opening socket\n");
    
    
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    memcpy(&serveraddr.sin_addr.s_addr, req_host->h_addr_list[0], req_host->h_length);
    serveraddr.sin_port = htons((unsigned short)portno);

    if (connect(client_sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr)) == -1){
        printf("There was a problem connecting to the actual server\n");
        error("connect:");
        close(client_sockfd);
        exit(EXIT_FAILURE);
    }

    grabFileName(buf,file_name);

    sendall(client_sockfd, buf, BUFSIZE);
    bzero(buf, BUFSIZE); 

    n =  recv(client_sockfd, buf, BUFSIZE, 0);
    content_length = grabContentLength(buf);
    http_res_ends = strstr(buf, "\r\n\r\n");
    http_res_header_bytes = http_res_ends + 4 - buf;
    http_res_body_bytes_recv = n - http_res_header_bytes;
    
    md5_file_name = str2md5(file_name, strlen(file_name));
    sprintf(full_path, "./cache/%s", md5_file_name);

    //TODO: Check if file within timeout! add and symbal to this if statment
    if (access(full_path, F_OK)){
        fp = fopen(full_path, "r");

    }else {
        fp = fopen(full_path, "w");
        //TODO: Making the followiong variables writeFIleToCache local variables: n, content lenght, httpres_body_bytes recv, and http_res_header_bytes
        writeFileToCache(fp, buf, full_path, n, content_length, client_sockfd, http_res_body_bytes_recv, http_res_header_bytes);
    }



    //TODO: relay the results for the server (socket2) to the client (socket1)

    // fp = fopen(filename, "r"); //Checking for file existense and readability happens in buildHTTPResponseHeader
    // n = send(client_socket, response_http_header, strlen(response_http_header), 0);
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
      exit(EXIT_FAILURE);
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
     *pclient = connfd;Y f
     pthread_create(&t, NULL, handle_connection, pclient);
     pthread_detach(t);
    }
    w
    pthread_exit(0);
    */
  }

/*
Run with: lcrypto

cc -Wextra proxy_server.c -o proxy_server -lcrypto
*/