#define _GNU_SOURCE

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

#include <fcntl.h>


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

int grab_url(char http_res_header[BUFSIZE], char url[200]) {
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
    strncpy(url, http_res_url, strlen(http_res_url));
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

//Receive data from the server and write to the cache folder
int writeFileToCache(FILE *fp, char http_res[BUFSIZE], int client_sockfd){
    int n;
    int content_length;
    int http_res_body_bytes_recv;
    int http_res_header_bytes;
    char *http_res_ends;
    char remainder_of_body[BUFSIZE];

    n =  recv(client_sockfd, http_res, BUFSIZE, 0);
    content_length = grabContentLength(http_res);
    http_res_ends = strstr(http_res, "\r\n\r\n");
    http_res_header_bytes = http_res_ends + 4 - http_res;
    http_res_body_bytes_recv = n - http_res_header_bytes;
    fwrite(http_res + http_res_header_bytes, 1, (n - http_res_header_bytes), fp);

    while (http_res_body_bytes_recv < content_length) {
        n =  recv(client_sockfd, http_res, BUFSIZE, 0);
        if ( (n+ http_res_body_bytes_recv) > content_length) {
            strncpy(remainder_of_body, http_res, n - (n+http_res_body_bytes_recv-content_length) );
            fwrite(remainder_of_body, 1, (n - (n+http_res_body_bytes_recv-content_length)), fp);
            http_res_body_bytes_recv = http_res_body_bytes_recv + n - (n+http_res_body_bytes_recv-content_length) ;
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
    return 0;
}

int grab_host_by_name(char http_res[BUFSIZE], struct hostent **req_host) {
    char *saveptr_http_header;
    char* copy_http_req_header;
    char* http_header_line;
    char *saveptr_line_host;
    char *header_line_host;
    char *host_name;
    
    copy_http_req_header = strdup(http_res);//TODO: chek if strdup fails
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header); //TODO: Check if it fails ?  
    http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header); 
    header_line_host = strdup(http_header_line);//TODO: chek if strdup fails
    strtok_r(header_line_host, " ", &saveptr_line_host);
    host_name = strtok_r(NULL, " ", &saveptr_line_host);
    *req_host = gethostbyname(host_name); //TODO: Replace with getaddrinfo since gethostbyname is not thread safe
    return 0;
}

long long int get_time_since_creation(char full_path[400]){
    time_t current_seconds;
    struct statx stx_buf;
    statx(AT_FDCWD, full_path, 0, STATX_BTIME, &stx_buf);
    // citation: https://stackoverflow.com/questions/2242963/get-the-current-time-in-seconds
    current_seconds = time(NULL);
    return (current_seconds - stx_buf.stx_btime.tv_sec);
}

int grab_http_version(char http_header[BUFSIZE], char **http_version_return) {
    char *saveptr_http_header;
    char* copy_http_req_header;
    char* http_header_line;
    char *saveptr_line_http_header;
    char *copy_http_header_line; 
    char *http_verb;
    char *http_url;
    char *http_version; 
    copy_http_req_header = strdup(http_header);//TODO: chek if strdup fails
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header); //TODO: Check if it fails ?    
    copy_http_header_line = strdup(http_header_line);//TODO: chek if strdup fails
    http_verb =  strtok_r(copy_http_header_line, " ", &saveptr_line_http_header);
    http_url =  strtok_r(NULL, " ", &saveptr_line_http_header); //TODO: Delete ? Unsure if I am checking these
    http_version =  strtok_r(NULL, " ", &saveptr_line_http_header);// TODO: delete? 
    *http_version_return = http_version; 
    return 0;
}

int set_status_code() {
    return 0;
}

int set_response_content_type(char file_type[FILETYPESIZE], char content_type[100]) {
    if (strcasecmp(file_type, "html") == 0) {
        strncpy(content_type, "Content-Type: text/html", sizeof("Content-Type: text/htlm"));
    } else if (strcasecmp(file_type, "txt") == 0) {
        strncpy(content_type, "Content-Type: text/plain", sizeof("Content-Type: text/plain"));
    } else if (strcasecmp(file_type, "png") == 0) {
        strncpy(content_type, "Content-Type: image/png", sizeof("Content-Type: image/png"));
    }  else if (strcasecmp(file_type, "gif") == 0) {
        strncpy(content_type, "Content-Type: image/gif", sizeof("Content-Type: image/gif"));
    }  else if (strcasecmp(file_type, "jpg") == 0) {
        strncpy(content_type, "Content-Type: image/jpg", sizeof("Content-Type: image/jpg"));
    }  else if (strcasecmp(file_type, "ico") == 0) {
        strncpy(content_type, "Content-Type: image/x-icon", sizeof("Content-Type: image/x-icon"));
    }  else if (strcasecmp(file_type, "css") == 0) {
        strncpy(content_type, "Content-Type: text/css", sizeof("Content-Type: text/css"));
    } else if (strcasecmp(file_type, "js") == 0) {
        strncpy(content_type, "Content-Type: application/javascript", sizeof("Content-Type: application/javascript"));
    } else {
        strncpy(content_type, "Content-Type: unknown", sizeof("Content-Type: unknown"));
        return -1;
    }

    return 0;
    
}
int grab_file_type(char file_type[20], char url[200]) {
    //Citation: https://stackoverflow.com/questions/5309471/getting-file-extension-in-c
    char *file_at_end_of_url = strrchr(url, '/');
    char *ext;
    // if (file_at_end_of_url == NULL) Note: Consider Error checking here if I don't put the check in http verification function
    //We are assuming url is fully formed, so if there is nothing at the end of the last slash then the assumption is that the request is for an index.html
    if (( *(file_at_end_of_url+1)) == '\0'){
        strcpy(file_type, "html");
    }else { 
        ext = strrchr(file_at_end_of_url, '.');
        if (ext) {
            strcpy(file_type, ext +1);       
        }   
    }
    return 0;
}

int determine_connection_status(char http_client_req_header[BUFSIZE], char *http_version, char **connection_status) {
    char *connection_status_exists;
    char *saveptr_http__res_header;
    char *copy_http_req_header;
    char *http_header_line;
    char *saveptr_connection_status_line;
    char *char_content_length;
    int content_length;
    

    connection_status_exists = strstr(http_client_req_header, "Connection:");
    if (connection_status_exists == NULL) {
        printf("Connections status does not Exist.\n"); 
        if (strcasecmp(http_version, "HTTP/1.1") == 0) {
            *connection_status = "Keep-Alive";
        }else {
            *connection_status = "Close";
        }
        return 0; 
    }

    copy_http_req_header = strdup(http_client_req_header);//TODO: chek if strdup fails
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http__res_header); //TODO: Check if it fails ?    

    while (1) {
        connection_status_exists = strstr(http_header_line, "Connection:"); //TODO: Concerned if the content-length is spelled differently
        if (connection_status_exists != NULL) break;
        http_header_line = strtok_r(NULL, "\r\n", &saveptr_http__res_header); //TODO: Check if it fails ?    
    }

    //TODO: Need to build in a check for if the connection status is not HTTP/1.1 or HTTP/1.0 But that probably shouldn't be here, it should be in my gett http function
    *connection_status  = strtok_r(http_header_line, " ", &saveptr_connection_status_line);
    *connection_status  = strtok_r(NULL, " ", &saveptr_connection_status_line);
    return 0;
}

long long int grab_content_length_from_file(char url[200]){
    char *md5_file_name;
    char full_path[400];
    md5_file_name = str2md5(url, strlen(url));
    struct stat stat_inst;

    sprintf(full_path, "./cache/%s", md5_file_name);    
    if (stat(full_path, &stat_inst) == -1) {
        printf("GETTING FILE CONTENT WITH STAT DID NOT WORK");
        return -1; // Indicate an error
    }
    

    return stat_inst.st_size; 
}
//TODO: full_path parameter might need to be filename. I'm undecided. Or URL
int build_http_response_for_client(char http_client_req_header[BUFSIZE], char response_header[BUFSIZE]){
    //I think everything I need is in the client req header. B/c from there, I should be able to get the f
    char *http_version;
    char file_type[20];
    char url[200];
    char content_type[100];
    char *http_connection_status;
    long long int content_length;

    //TODO: Need to make sure error checking is happening in all these functions
    grab_http_version(http_client_req_header, &http_version);
    grab_url(http_client_req_header, url);
    grab_file_type(file_type, url);
    set_response_content_type(file_type, content_type);
    determine_connection_status(http_client_req_header, http_version, &http_connection_status);
    content_length = grab_content_length_from_file(url);


    //TODO: Ensure other responses are built when error occurs (400 or 404)
    sprintf(response_header, "%s 200 OK\r\n%s\r\nContent-Length: %lld\r\nConnection: %s\r\n\r\n", http_version, content_type, content_length, http_connection_status);
    printf("Response Header: \n%s\n", response_header);


    //Response header hould look like 
    /*
HTTP/1.1 200 OK
Content-Type: <> # Tells about the type of content and the formatting of <file contents> 
Content-Length:<> # Numeric value of the number of bytes of <file contents>
<file contents>
    */
    //TODO: Read the file (Sync? Might be unnecessary due to sync over if statement that calls this), send the HTTP Response Header and the file data to the client.

    return 0;
}

void *handle_connection(void *p_client_socket, int timeout) {
    int client_to_proxy_socket = * ((int*)p_client_socket);
    free(p_client_socket);

    char buf[BUFSIZE]; 
    char *http_req_header_client;
    FILE *fp; 
    int n; 
    int bytes_read;

    int portno;
    int proxy_to_server_socket;
    int optval;
    int clientlen;
    struct sockaddr_in serveraddr; 
    struct sockaddr_in clientaddr;
    struct hostent *hostp;
    char *hostaddrp;

    struct hostent *req_host = NULL; //initalized to null b/c compiling with -Wextra was giving me a uninitalized warning (due to me using it in grab_host_name fn without initializing).
    char url[200];
    char full_path[400];
    char *md5_file_name;
    long long int time_since_creation;
    char *copy_server_response_http_header;
    char file_type[20];

    bzero(buf, BUFSIZE);
    // bzero(http_req_header_client, BUFSIZE);

    n = recv(client_to_proxy_socket, buf, BUFSIZE, 0);
    if (n < 0) error("ERROR in recvfrom\n");
    
    if (verify_HTTP_Req_Header(buf) !=0) {
        printf("Verify HTTP Req Header had some error\n");
        error("HTTP Verification Failed");
        // return 1;
    }

    printf("Buf: \n%s\n", buf);
    // grab_http_version(buf);
    // copy_server_response_http_header = strdup(buf);    //Actually, buf is the client http request I think rather than the server response right now
    http_req_header_client = strdup(buf);    //Actually, buf is the client http request I think rather than the server response right now
    grab_host_by_name(buf, &req_host);
    //TODO: Build in functionality for the user setting the port
    portno = 80; 
    proxy_to_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_to_server_socket < 0) error("ERROR opening socket\n");
    
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    memcpy(&serveraddr.sin_addr.s_addr, req_host->h_addr_list[0], req_host->h_length);
    serveraddr.sin_port = htons((unsigned short)portno);
    if (connect(proxy_to_server_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr)) == -1){
        printf("There was a problem connecting to the actual server\n");
        error("connect:");
        close(proxy_to_server_socket);
        exit(EXIT_FAILURE);
    }

    grab_url(buf,url);
    grab_file_type(file_type, url);
    sendall(proxy_to_server_socket, buf, BUFSIZE);
    bzero(buf, BUFSIZE); 

    md5_file_name = str2md5(url, strlen(url));
    sprintf(full_path, "./cache/%s", md5_file_name);
    //TODO: When Multi-Threading, will need to look portions of this, probably all of this if else chunk
    if (access(full_path, F_OK) == 0){
        time_since_creation = get_time_since_creation(full_path);
        if (time_since_creation < timeout){
            // fp = fopen(full_path, "r");
        } else {
            remove(full_path);
            fp = fopen(full_path, "w");
            writeFileToCache(fp, buf, proxy_to_server_socket);
        }
    }else {
        fp = fopen(full_path, "w");
        writeFileToCache(fp, buf, proxy_to_server_socket);
    }

    bzero(buf, BUFSIZE); 
    build_http_response_for_client(http_req_header_client, buf);

    //TODO: relay the results for the server (socket2) to the client (socket1)

    fp = fopen(full_path, "r"); //Checking for file existense and readability happens in buildHTTPResponseHeader
    //sending http response header
    n = send(client_to_proxy_socket, buf, strlen(buf), 0);
    
    while (1){
      bytes_read = fread(buf, 1, BUFSIZE, fp);
      if (bytes_read < 1) {
        break;
      }
      //if I do BUFSIZE in sendall and do a verbose curl, I get * Excess found in a read: excess = 1020, size = 5124, maxdownload = 5124, bytecount = 0
      //If I do strlen(buf), I do not get that note.
      //I believe this means the programs I am using to test are cutting off unrelated bytes. I'm not sure I hould worry about this given my content lenght cuts off excess bytes 
      if (sendall(client_to_proxy_socket, buf, BUFSIZE) == -1) {
    //   if (sendall(client_to_proxy_socket, buf, strlen(buf) == -1) {
            printf("Error in sending file data");
      }
      bzero(buf, BUFSIZE);
    } 
    
    close(proxy_to_server_socket);
    close(client_to_proxy_socket);
    // fclose(fp); //unsure if this should be turned back on, 
    bzero(buf, BUFSIZE);
    return NULL;
}

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
 
    if (argc != 3) {
        fprintf(stderr, "You need to execute this file with two arguments, port number and timeout number (in seconds)\n");
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
     handle_connection(pclient, atoi(argv[2]));
    
    
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