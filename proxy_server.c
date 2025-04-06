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
#include <semaphore.h>
// CITATION: https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
#include <openssl/md5.h>
#include <fcntl.h>
#include <regex.h>
#include <glob.h>


#define BUFSIZE 2048
#define FILENAMESIZE 100
#define FILETYPESIZE 100
#define LISTENQ 24
#define HTTP_REQUEST_FILENAME_START_POSTION 5
#define WORKINGDIRECTORYPATHSIZE 1000
#define HTTPVERSIONSIZE 100

sem_t cache_folder_sem;
sem_t blocklist_file_sem;
sem_t sockopt_sem;
sem_t thread_data_sem;

//CITATION For Thread Args: https://hpc-tutorials.llnl.gov/posix/passing_args/
struct thread_args{
    int  portno;
    int timeout;
    int  *pclient;
};

//CITATION:  https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c
void signalHandler() {
    printf("\nSIGNAL HANDLER WORKED\n");
    rmdir("./glob_files");
    pthread_exit(0);

    // exit(EXIT_FAILURE);
}
void signalPipeHandler() {
    printf("\nSIGNALPIPE HANDLER WORKED\n");
    rmdir("./glob_files");
    // pthread_exit(0);

    // exit(EXIT_FAILURE);
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
        if (n == -1) { 
            break; 
        }
        total += n;
        bytesleft -= n;
    }
    if (n == -1) return -1;
    return total;
} 

//Verify the HTTP Request Header: Verify double carriage return, No other Method but GET used, and Host Name resolves to IP Address
int verify_HTTP_Req_Header(char http_req_header[BUFSIZE], int client_to_proxy_socket) {
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
    char *host_exists;
    char response_header[200];
    char host_name_no_port[100];

    bzero(host_name_no_port, 100);
    bzero(response_header, 200);

    http_body_separator = strstr(http_req_header, "\r\n\r\n");
    if (http_body_separator == NULL){
        sprintf(response_header, "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request\n");        
        send(client_to_proxy_socket, response_header, strlen(response_header), 0);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("In verify_http_req_header socket send timeout");
            // Close the socket due to inactivity
        }
        return -1; 
    }

    copy_http_req_header = strdup(http_req_header);
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header);    
    copy_http_header_line = strdup(http_header_line);
    http_verb =  strtok_r(copy_http_header_line, " ", &saveptr_line_http_header);
    http_url =  strtok_r(NULL, " ", &saveptr_line_http_header);
    http_version =  strtok_r(NULL, " ", &saveptr_line_http_header); 

    if (strcasecmp(http_verb, "GET") != 0){
        sprintf(response_header, "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request\n");  
        send(client_to_proxy_socket, response_header, strlen(response_header), 0);
        return -1;
    }
 
    if (strcasecmp(http_version, "HTTP/1.1") != 0 && strcasecmp(http_version, "HTTP/1.0") != 0){
        sprintf(response_header, "HTTP/1.1 400 Bad Request\r\n\r\n400 Bad Request\n");  
        send(client_to_proxy_socket, response_header, strlen(response_header), 0);
        return -1;
    } 

    http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header); 

    while (1) {
        host_exists = strstr(http_header_line, "Host:"); 
        if (host_exists != NULL) break;
        http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header);    
    }

    copy_header_line_host = strdup(http_header_line);
    strtok_r(copy_header_line_host, " ", &saveptr_line_host);
    host_name = strtok_r(NULL, " ", &saveptr_line_host);
    char *colon = strstr(host_name, ":");
    if (colon == NULL) {
        req_host = gethostbyname(host_name); 

    } else{ 
        strncpy(host_name_no_port, host_name, strlen(host_name) - strlen(colon));
        req_host = gethostbyname(host_name_no_port); 

    }
    
    if (req_host == NULL) {
        sprintf(response_header, "HTTP/1.1 404 Not Found\r\n\r\n404 Not Found\n");  
        send(client_to_proxy_socket, response_header, strlen(response_header), 0);

        return -1;
    }


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
    
    content_length_exists = strstr(http_res_header, "Content-Length");
    if (content_length_exists == NULL){
        return -1; 
    }
    copy_http_res_header = strdup(http_res_header);
    http_header_line = strtok_r(copy_http_res_header, "\r\n", &saveptr_http__res_header);     
    while (1) {
        content_length_exists = strstr(http_header_line, "Content-Length"); 
        if (content_length_exists != NULL) break;
        http_header_line = strtok_r(NULL, "\r\n", &saveptr_http__res_header);    
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
    copy_http_res_header = strdup(http_res_header);
    http_header_line = strtok_r(copy_http_res_header, "\r\n", &saveptr_http__res_header); 
    http_res_url = strtok_r(http_header_line, " ", &saveptr_http_res_url); 
    http_res_url = strtok_r(NULL, " ", &saveptr_http_res_url); 
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

int writeFileToCache(FILE *fp, char http_res[BUFSIZE], int client_sockfd){
    int n;
    int content_length;
    int http_res_body_bytes_recv;
    int http_res_header_bytes;
    char *http_res_ends;
    char remainder_of_body[BUFSIZE];
    bzero(remainder_of_body, BUFSIZE);

    n =  recv(client_sockfd, http_res, BUFSIZE, 0);
    content_length = grabContentLength(http_res);
    http_res_ends = strstr(http_res, "\r\n\r\n");
    http_res_header_bytes = http_res_ends + 4 - http_res;
    http_res_body_bytes_recv = n - http_res_header_bytes;
    fwrite(http_res + http_res_header_bytes, 1, (n - http_res_header_bytes), fp);
    
    bzero(http_res, BUFSIZE);
    while (http_res_body_bytes_recv < content_length) {
        n =  recv(client_sockfd, http_res, BUFSIZE, 0);
        if ( (n+ http_res_body_bytes_recv) > content_length) {
            strncpy(remainder_of_body, http_res, n - (n+http_res_body_bytes_recv-content_length) );
            fwrite(remainder_of_body, 1, (n - (n+http_res_body_bytes_recv-content_length)), fp);
            http_res_body_bytes_recv = http_res_body_bytes_recv + n - (n+http_res_body_bytes_recv-content_length) ;
            break;
        }else {
            http_res_body_bytes_recv = http_res_body_bytes_recv + n;
            fwrite(http_res, 1, n, fp);
        }
        bzero(http_res, BUFSIZE);
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
    char *host_exists;
    char *colon_before_port;
    char host_name_no_port[100];
    bzero(host_name_no_port, 100);
    copy_http_req_header = strdup(http_res);
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header);  
    http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header); 
    while (1) {
        host_exists = strstr(http_header_line, "Host:");
        if (host_exists != NULL) break;
        http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header);    
    }
    header_line_host = strdup(http_header_line);
    strtok_r(header_line_host, " ", &saveptr_line_host);
    host_name = strtok_r(NULL, " ", &saveptr_line_host);
    colon_before_port = strstr(host_name, ":");
    if (colon_before_port == NULL){
        *req_host = gethostbyname(host_name); 
    }else {
        strncpy(host_name_no_port, host_name, colon_before_port - host_name);
        *req_host = gethostbyname(host_name_no_port); 
    }
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
    
    copy_http_req_header = strdup(http_header);
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header);     
    copy_http_header_line = strdup(http_header_line);
    strtok_r(copy_http_header_line, " ", &saveptr_line_http_header);
    strtok_r(NULL, " ", &saveptr_line_http_header); 
    *http_version_return =  strtok_r(NULL, " ", &saveptr_line_http_header); 
    if (strcasecmp(*http_version_return, "HTTP/1.1") == 0 || strcasecmp(*http_version_return, "HTTP/1.0") == 0) return 0;
    return -1;
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
        if (strcasecmp(http_version, "HTTP/1.1") == 0) {
            *connection_status = "Keep-Alive";
        }else if (strcasecmp(http_version, "HTTP/1.0") == 0) { 
            *connection_status = "Close";
        } else {
            return -1;
        }

        return 0; 
    }

    copy_http_req_header = strdup(http_client_req_header);
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http__res_header);     
    while (1) {
        connection_status_exists = strstr(http_header_line, "Connection:"); 
        if (connection_status_exists != NULL) break;
        http_header_line = strtok_r(NULL, "\r\n", &saveptr_http__res_header);     
    }
    *connection_status  = strtok_r(http_header_line, " ", &saveptr_connection_status_line);
    *connection_status  = strtok_r(NULL, " ", &saveptr_connection_status_line);
    return 0;
}

long long int grab_content_length_from_file(char full_path[400]){
    struct stat stat_inst;
    if (stat(full_path, &stat_inst) == -1) {
        printf("errno: %d\n", errno); // Print the errno value
        return -1; // Indicate an error
    }    
    return stat_inst.st_size; 
}

int check_block_list(struct hostent **req_host, int client_to_proxy_socket) {
    FILE *fp = fopen("./blocklist", "r");
    char file_line_pattern[200];
    char file_line_pattern_with_directory[400];
    char *alias = "Not Null";
    char **ip_addr;
    int aliases_ele = 0;
    glob_t glob_obj;
    int match_result;
    char ip_buf[400];
    char response_header[200];
    int fd;
    bzero(file_line_pattern, 200);
    bzero(file_line_pattern_with_directory, 400);
    bzero(ip_buf, 400);
    bzero(response_header, 200);

    if (fp == NULL) {
        return -1; 
    }
    while (fgets(file_line_pattern, 400, fp) != NULL) {
        file_line_pattern[strcspn(file_line_pattern, "\n")] = '\0'; //\n was causing it not to match
        char h_name_buf[400];
        bzero(h_name_buf, 400);
        sprintf(h_name_buf, "glob_files/%s", (*req_host)->h_name);
        sprintf(file_line_pattern_with_directory, "glob_files/%s", file_line_pattern);
        fd = open(h_name_buf, O_CREAT, 0644);
        match_result = glob(file_line_pattern_with_directory, 0, NULL, &glob_obj);
        if (match_result == 0) {
            sprintf(response_header, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n403 Forbidden\n");  
            send(client_to_proxy_socket, response_header, strlen(response_header), 0);
            close(fd);
            remove(h_name_buf);
            globfree(&glob_obj);
            return -1;
    
        } else if (match_result == GLOB_NOMATCH) {
            remove(h_name_buf);
        }
        close(fd);

        if ((*req_host)->h_aliases[aliases_ele] != NULL) {
            while ((*req_host)->h_aliases[aliases_ele] != NULL){
                alias = (*req_host)->h_aliases[aliases_ele];
                char alias_buf[400];
                bzero(alias_buf, 400); 
                sprintf(alias_buf, "glob_files/%s", alias);
                sprintf(file_line_pattern_with_directory, "glob_files/%s", file_line_pattern);
                int fd = open(alias_buf, O_CREAT, 0644);   
             
                match_result = glob(file_line_pattern_with_directory, 0, NULL, &glob_obj);
                if (match_result == 0) {
                    sprintf(response_header, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n403 Forbidden\n");  
                    send(client_to_proxy_socket, response_header, strlen(response_header), 0);
                    close(fd);
                    remove(alias_buf);
                    globfree(&glob_obj);
                    return -1;
            
                } else if (match_result == GLOB_NOMATCH) {
                    remove(alias_buf);
                }
                close(fd);
                aliases_ele = aliases_ele + 1;

            }
        }
        aliases_ele = 0;


        if ((*req_host)->h_addr_list != NULL) {
            ip_addr = (*req_host)->h_addr_list;
            while (*ip_addr != NULL){
                struct in_addr in_addr_for_reg_check;
                memcpy(&in_addr_for_reg_check.s_addr, *ip_addr, (*req_host)->h_length);
                char ip_buf[400]; 
                sprintf(ip_buf, "glob_files/%s", inet_ntoa(in_addr_for_reg_check));
                sprintf(file_line_pattern_with_directory, "glob_files/%s", file_line_pattern);
                int fd = open(ip_buf, O_CREAT, 0644);                
                match_result = glob(file_line_pattern_with_directory, 0, NULL, &glob_obj);

                if (match_result == 0) {
                    sprintf(response_header, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n403 Forbidden\n");  
                    send(client_to_proxy_socket, response_header, strlen(response_header), 0);
                    close(fd);
                    remove(ip_buf);
                    globfree(&glob_obj);
                    return -1;
                } else if (match_result == GLOB_NOMATCH) {
                    remove(ip_buf);
                }
                close(fd);
                ip_addr = ip_addr + 1;
            }
        }
    }
    globfree(&glob_obj);
}

int pre_fetch_link(char link_string[100], char *http_req_header_client, int timeout, int portno) {
    char *saveptr_http_header;
    char *copy_http_req_header;
    char *http_header_line;
    char *saveptr_line_http_header;
    char *copy_http_header_line; 
    char *http_verb;
    char *http_url;
    char *http_version; 
    char *saveptr_line_host;
    char *copy_header_line_host;
    char *host_name;
    char *host_exists;
    char *check_for_http;
    char *check_for_https;
    char *check_for_relative_path;
    char *check_for_num_sign;
    char *md5_file_name;
    char new_rel_path[100];
    char url[200];
    char full_path[400];
    char http_request_for_pre_fetch_link[BUFSIZE];
    char buf[BUFSIZE];
    char pre_fetch_url[200];
    FILE *fp;
    struct hostent *req_host;
    long long int time_since_creation;
    int proxy_to_server_socket;
    struct sockaddr_in serveraddr; 
    char *colon_before_port;
    char host_name_no_port[100];
    bzero(buf, BUFSIZE);
    bzero(http_request_for_pre_fetch_link, BUFSIZE);
    bzero(pre_fetch_url, 200);
    bzero(full_path, 400);
    bzero(url, 100);
    bzero(new_rel_path, 100);
    bzero(host_name_no_port, 100);

    copy_http_req_header = strdup(http_req_header_client);
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header);     
    copy_http_header_line = strdup(http_header_line);
    http_verb =  strtok_r(copy_http_header_line, " ", &saveptr_line_http_header);
    http_url =  strtok_r(NULL, " ", &saveptr_line_http_header); 
    http_version =  strtok_r(NULL, " ", &saveptr_line_http_header); 
    http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header); 
    while (1) {
        host_exists = strstr(http_header_line, "Host:"); 
        if (host_exists != NULL) break;
        http_header_line = strtok_r(NULL, "\r\n", &saveptr_http_header);     
    }

    copy_header_line_host = strdup(http_header_line);
    strtok_r(copy_header_line_host, " ", &saveptr_line_host);
    host_name = strtok_r(NULL, " ", &saveptr_line_host);
    colon_before_port = strstr(host_name, ":");
    check_for_http = strstr(link_string, "http:");
    check_for_https = strstr(link_string, "https:");
    check_for_relative_path = strstr(link_string, "./");
    check_for_num_sign = strstr(link_string, "#");


    if (check_for_http != NULL){
        return 0;
    } else if (check_for_https != NULL){
        return 0;

    } else if (check_for_relative_path != NULL) {
        strcpy(new_rel_path, link_string + 2); // Copy from the third character
        sprintf(pre_fetch_url, "http://%s/%s", host_name, new_rel_path);  
        sprintf(http_request_for_pre_fetch_link, "%s %s %s\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", http_verb, pre_fetch_url, http_version, host_name);  
    } else if (check_for_num_sign != NULL) {
        return 0;

    } else {
        sprintf(pre_fetch_url, "http://%s/%s", host_name, link_string);  
        sprintf(http_request_for_pre_fetch_link, "%s %s %s\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", http_verb, pre_fetch_url, http_version, host_name);  

    }

    if (colon_before_port == NULL){
        req_host = gethostbyname(host_name); 
        portno = 80;

    }else {
        //TODO: result I get when portno is different than 80 is failure but I think it is failure because the origin server does not serve resources at that port.
        portno = atoi(colon_before_port+1);
        strncpy(host_name_no_port, host_name, colon_before_port - host_name);
        req_host = gethostbyname(host_name_no_port); 
    }

    proxy_to_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_to_server_socket < 0) error("ERROR opening socket\n");
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    memcpy(&serveraddr.sin_addr.s_addr, req_host->h_addr_list[0], req_host->h_length);
    serveraddr.sin_port = htons((unsigned short)portno);
    if (connect(proxy_to_server_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr)) == -1){
        close(proxy_to_server_socket);
        exit(EXIT_FAILURE);
    }
    sendall(proxy_to_server_socket, http_request_for_pre_fetch_link, BUFSIZE);
    bzero(http_request_for_pre_fetch_link, BUFSIZE);
    md5_file_name = str2md5(pre_fetch_url, strlen(pre_fetch_url));

    sprintf(full_path, "./cache/%s", md5_file_name);
    if (access(full_path, F_OK) == 0){
        time_since_creation = get_time_since_creation(full_path);
        if (time_since_creation < timeout){

        } else {
            remove(full_path);
            fp = fopen(full_path, "w");
            writeFileToCache(fp, http_request_for_pre_fetch_link, proxy_to_server_socket);
        }
    }else {
        fp = fopen(full_path, "w");
        writeFileToCache(fp, http_request_for_pre_fetch_link, proxy_to_server_socket);
    }

    return 0;

}

//CITATION: https://stackoverflow.com/questions/13482519/c-find-all-occurrences-of-substring
//The citation above is somewhat helpful, really just for using addition of the length to move past the first occurence
int searching_for_links(char full_path[400], char *http_req_header_client, int timeout, int portno) {
    char *href_text = "href=\"";
    char *src_text = "src=\"";
    char *quotation_text = "\"";
    char file_content[64000];
    FILE *fp = fopen(full_path, "r");
    int bytes_read;
    int byte_found_href;
    int byte_found_src;
    int byte_found_ending_quotation_mark_for_href;
    int byte_found_ending_quotation_mark_for_src;
    int copy_link_bytes;
    char *find_href;
    char *find_src;
    char *find_quotation_after_href;
    char *find_quotation_after_src;
    char link_string[100];

    bzero(file_content, 64000);
    bzero(link_string, 100);
    if (fp == NULL) {
        return -1; 
    }

    while (1){
        bytes_read = fread(file_content, 1, 64000, fp);
        if (bytes_read < 1) {
          break;
        }
        find_href = file_content;
        while(1) {
            find_href = strstr(find_href, href_text);
            if (find_href == NULL) break;
            byte_found_href = find_href - file_content;
            find_href += strlen(href_text);
            find_quotation_after_href = strstr(find_href, quotation_text);
            byte_found_ending_quotation_mark_for_href = find_quotation_after_href - file_content;
            copy_link_bytes = byte_found_ending_quotation_mark_for_href - byte_found_href - strlen(href_text);
            strncpy(link_string, find_href, copy_link_bytes);
            pre_fetch_link(link_string, http_req_header_client, timeout, portno);
            bzero(link_string, 100);
        }
        bzero(file_content, 64000);
      } 


    fclose(fp);
    fp = fopen(full_path, "r");

    while (1){
        bytes_read = fread(file_content, 1, 64000, fp);
        if (bytes_read < 1) {
          break;
        }
        find_src = file_content;
        while(1) {
            find_src = strstr(find_src, src_text);
            if (find_src == NULL) break;
            byte_found_src = find_src - file_content;
            find_src += strlen(src_text);
            find_quotation_after_src = strstr(find_src, quotation_text);
            byte_found_ending_quotation_mark_for_src = find_quotation_after_src - file_content;
            copy_link_bytes = byte_found_ending_quotation_mark_for_src - byte_found_src - strlen(src_text);
            strncpy(link_string, find_src, copy_link_bytes);
            pre_fetch_link(link_string, http_req_header_client, timeout, portno);

            bzero(link_string, 100);
        }
        bzero(file_content, 64000);
      } 
    fclose(fp);
    return 0;
}

int build_http_response_for_client(char http_client_req_header[BUFSIZE], char response_header[BUFSIZE], char full_path[400]){
    char *http_version;
    char file_type[20];
    char url[200];
    char content_type[100];
    char *http_connection_status;
    long long int content_length;    
    bzero(url, 200);
    bzero(file_type, 20);
    bzero(content_type, 100);

    grab_http_version(http_client_req_header, &http_version);
    grab_url(http_client_req_header, url);
    grab_file_type(file_type, url);
    set_response_content_type(file_type, content_type);
    determine_connection_status(http_client_req_header, http_version, &http_connection_status);
    content_length = grab_content_length_from_file(full_path);
    sprintf(response_header, "%s 200 OK\r\n%s\r\nContent-Length: %lld\r\nConnection: %s\r\n\r\n", http_version, content_type, content_length, http_connection_status);
    return 0;
}

int grab_port_num(char http_cli_req_header[BUFSIZE]) {
    char *http_body_separator;
    char *saveptr_http_header;
    char* copy_http_req_header;
    char* http_header_line;
    char *saveptr_line_http_header;
    char *copy_http_header_line; 
    char *http_url;
    char *first_colon;
    char *second_colon;
    char *end_of_port_string;
    int byte_found_second_colon;
    int byte_found_ending_port_string;
    int copy_link_bytes;
    char portno[30];

    bzero(portno, 30);

    copy_http_req_header = strdup(http_cli_req_header);
    http_header_line = strtok_r(copy_http_req_header, "\r\n", &saveptr_http_header);     
    copy_http_header_line = strdup(http_header_line);
    strtok_r(copy_http_header_line, " ", &saveptr_line_http_header);
    http_url =  strtok_r(NULL, " ", &saveptr_line_http_header);

    first_colon = strstr(http_url, ":");
    second_colon = strstr(first_colon + 1, ":");
    
    if (second_colon == NULL) {
        return 80;
    }

    byte_found_second_colon = second_colon - http_cli_req_header;
    end_of_port_string = strstr(second_colon, "/");
    byte_found_ending_port_string = end_of_port_string - http_cli_req_header;
    copy_link_bytes = byte_found_ending_port_string - byte_found_second_colon - 1;
    strncpy(portno, second_colon +1, copy_link_bytes);
    return atoi(portno);


}

void *handle_connection(void *thread_args) {

    //This was necessary and felt like it should not be. Meaning my shoddy programming of sending data even after the connection is closed is what was causing 
        //the sigpipe error. I worked around it my ignoring it but that is bad form. I'm unclear why signal(SIGPIPE, SIG_IGN) didn't work in the main or in the 
        // indivudal thread
    //CITATION: https://stackoverflow.com/questions/62856963/pthread-sigmask-not-work-in-multithreaded-program
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    struct thread_args *args;
    int timeout;
    args = (struct thread_args *) thread_args;
    timeout = args->timeout;
    int client_to_proxy_socket = *(args->pclient);
    
    if (sem_post(&thread_data_sem) != 0) {
        printf("thread_data semaphor wait function did not work!!");
        pthread_exit(NULL);
    }

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
    pthread_t current_thread_id = pthread_self();
    bzero(buf, BUFSIZE);
    bzero(url, 200);
    bzero(full_path, 400);
    bzero(file_type, 20);

    if (sem_wait(&cache_folder_sem) != 0) {
        printf("cache semaphor wait function did not work!!");
        pthread_exit(NULL);
    }
    n = recv(client_to_proxy_socket, buf, BUFSIZE, 0);
    if (verify_HTTP_Req_Header(buf, client_to_proxy_socket) !=0) {
        close(client_to_proxy_socket);
        sem_post(&cache_folder_sem);    
        return NULL;
    }
    portno = grab_port_num(buf);
    http_req_header_client = strdup(buf);  //Actually, buf is the client http request I think rather than the server response right now
    grab_host_by_name(buf, &req_host);
    //This semaphore useless given how I've implemented my cache semaphore. Need to do these better. Performance with this way of programming is trash.
    sem_wait(&blocklist_file_sem); 
    if (check_block_list(&req_host, client_to_proxy_socket) == -1){
        close(client_to_proxy_socket);
        sem_post(&blocklist_file_sem);
        sem_post(&cache_folder_sem);
        return NULL;
    }
    sem_post(&blocklist_file_sem);

    proxy_to_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_to_server_socket < 0) error("ERROR opening socket\n");
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    memcpy(&serveraddr.sin_addr.s_addr, req_host->h_addr_list[0], req_host->h_length);
    serveraddr.sin_port = htons((unsigned short)portno);

    if (connect(proxy_to_server_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr)) == -1){
        printf("There was a problem connecting to the actual server\n");
        close(proxy_to_server_socket);
        return NULL;
    }

    grab_url(buf,url);
    grab_file_type(file_type, url);
    sendall(proxy_to_server_socket, buf, BUFSIZE);
    bzero(buf, BUFSIZE); 
    md5_file_name = str2md5(url, strlen(url));
    sprintf(full_path, "./cache/%s", md5_file_name);
    
    if (access(full_path, F_OK) == 0){
        time_since_creation = get_time_since_creation(full_path);
        if (strstr(url, "?") != NULL) {
            remove(full_path);
            fp = fopen(full_path, "w");
            writeFileToCache(fp, buf, proxy_to_server_socket);

        } else if (time_since_creation < timeout){

        } else {
            remove(full_path);
            fp = fopen(full_path, "w");
            writeFileToCache(fp, buf, proxy_to_server_socket);
        }
    }else {
        fp = fopen(full_path, "w");
        if (fp == NULL) {
            printf("FP IS NULL\n");
        }
        writeFileToCache(fp, buf, proxy_to_server_socket);
    }

    bzero(buf, BUFSIZE); 
    build_http_response_for_client(http_req_header_client, buf, full_path);        
    fp = fopen(full_path, "r"); //Checking for file existense and readability happens in buildHTTPResponseHeader
    //sending http response header
    n = send(client_to_proxy_socket, buf, strlen(buf), 0);
    while (1){
        bytes_read = fread(buf, 1, strlen(buf), fp);
        n = sendall(client_to_proxy_socket, buf, BUFSIZE);
        if (n == -1) {
                break;
        }
        bzero(buf, BUFSIZE);
    } 
    searching_for_links(full_path, http_req_header_client, timeout, portno);
    close(proxy_to_server_socket);
    close(client_to_proxy_socket);
    bzero(buf, BUFSIZE);

    if (sem_post(&cache_folder_sem) != 0) {
        printf("cache semaphor post function did not work!!");
        pthread_exit(NULL);
    }
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
    bzero(buf, BUFSIZE);
 
    if (argc != 3) {
        fprintf(stderr, "You need to execute this file with two arguments, port number and timeout number (in seconds)\n");
        exit(EXIT_FAILURE);
    }
    if (sem_init(&cache_folder_sem, 0, 1) != 0) {
        printf("initializing cache semaphore did not work!!");
        return -1;
    }
    if (sem_init(&blocklist_file_sem, 0, 1) != 0) {
        printf("initializing blocklist semaphore did not work!!");
        return -1;
    }
    if (sem_init(&sockopt_sem, 0, 1) != 0) {
        printf("initializing sockopt semaphore did not work!!");
        return -1;
    }
    if (sem_init(&thread_data_sem, 0, 1) != 0) {
        printf("initializing sockopt semaphore did not work!!");
        return -1;
    }

    portno = atoi(argv[1]);
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) error("ERROR opening socket\n");
 
    signal(SIGINT, signalHandler);
    signal(SIGPIPE, SIG_IGN); //The individual threads did not ignore sigpipe from this
    optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)portno);
 
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) error("ERROR on binding\n");
    listen (listenfd, LISTENQ);
    clientlen = sizeof(clientaddr);
    mkdir("./glob_files", 0777);
     
    while (1) {
    struct timeval tv_rec;
    tv_rec.tv_sec = 2;  
    tv_rec.tv_usec = 0;
    struct timeval tv_send;
    tv_send.tv_sec = 1;  
    tv_send.tv_usec = 0;
    
    connfd = accept(listenfd, (struct sockaddr *) &clientaddr, &clientlen );
    if (connfd < 0) {
        continue;
    }
    if (sem_wait(&sockopt_sem) != 0) {
        printf("sockopt semaphor wait function did not work!!");
        pthread_exit(NULL);
    }
    if (setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_rec, sizeof(tv_rec)) == -1 ){
        printf("CONNFD, setsockopt (SO_RCVTIMEO) failed, socket value: %d\n", connfd);
        fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));

    }
    if (setsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv_send, sizeof(tv_send)) == -1) {
        printf("CONNFD, setsockopt (SO_SNDTIMEO) failed, socket value: %d\n", connfd);
        fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (sem_post(&sockopt_sem) != 0) {
        printf("sockopt semaphor wait function did not work!!");
        pthread_exit(NULL);
    }
    printf("\nconnection from %s, port %d\n", inet_ntop(AF_INET, &clientaddr.sin_addr, buf, sizeof(buf)), ntohs(clientaddr.sin_port) );
    if (sem_wait(&thread_data_sem) != 0) {
        printf("thread_data semaphor wait function did not work!!");
        pthread_exit(NULL);
    }
    struct thread_args thread_data;
    pthread_t t;
    thread_data.portno = portno; 
    thread_data.timeout = atoi(argv[2]);
    thread_data.pclient = malloc(sizeof(int)); 
   //  //CITATION: https://www.youtube.com/watch?v=Pg_4Jz8ZIH4
    *(thread_data.pclient) = connfd; 
   //  pthread_create(&t, NULL, handle_connection, pclient);
    pthread_create(&t, NULL, handle_connection, (void *) &thread_data);
    pthread_detach(t);
  }

  rmdir("./glob_files");
  return 0;
}

/*
Run with: lcrypto

cc -Wextra proxy_server.c -o proxy_server -lcrypto -lpthread

Tests: 
1) curl -v -x localhost:2000 http://httpforever.com
  i) Tested my proxy server on a commerical http website

2) Testing bad http requests (no double carriage return and wrong http version)
  i) nc localhost 2000 < no_carriage_return_http_req
  ii) For testing the a bad http request (no double carriage return)

  3) Testing Individual Files netsys. 
    i) curl -v -x localhost:2000 http://netsys.cs.colorado.edu/
        a) Success
    ii) curl -v -x localhost:2000  http://netsys.cs.colorado.edu/images/wine3.jpg     
        a) Success          
    iii) curl -v -x localhost:2000  http://netsys.cs.colorado.edu/images/apple_ex.png
        a) Success    
    iv) curl -v -x localhost:2000 http://netsys.cs.colorado.edu/images/exam.gif
        a) Success
    v) curl -v -x localhost:2000 http://netsys.cs.colorado.edu/files/text1.txt
        a) Success    
    vi) wget -e http_proxy=localhost:2000 http://netsys.cs.colorado.edu/
       a) Success
    vii) wget -e http_proxy=localhost:2000 http://netsys.cs.colorado.edu/files/text1.txt
       a) Success
    viii) aria2c --http-proxy=localhost:2000 http://netsys.cs.colorado.edu/
        a) Success

4) curl -d "num=2" -x localhost:2000 http://httpforever.com
    i) tested a method other than GET. Error handling worked correctly. 

5) Testing Blocklist feature
  i) curl -x localhost:2000 www.linkedin.com
    a) tested blocklist feature for alias *.linkedin.com
  ii) curl -x localhost:2000 www.yahoo.com
    a) tested blocklist feature for ip address 69.147.71.[0-2][0-9][0-9]


7) Testing mirroring (Keep-Alive) with WGET
   i) wget -m -e http_proxy=localhost:2000 http://netsys.cs.colorado.edu/
     a) Failure 


9) aria2c --http-proxy=localhost:2000 -i aria2c_test_file.txt
 

10) blocklist file looks like (no tabs): 
    *.google.com
    *.linkedin.com
    69.147.71.[0-2][0-9][0-9]

11) Pre-fetch links
  i) Works for relative path links (./)
  ii) Works for presumed full path links (images/apple.png, etc)

12) nc localhost 2000 < wrong_http_version_http_req

13) aria2c --http-proxy=localhost:2000 -x 13 -i aria2c_test_file.txt
--BEFORE SUBMITTING: Check AGAIN to Ensure all the built features work seamslessly

----Downloading the files 
-------- I should also check other urls on networksystem site besides index             SUCCESS
-------- I should try and download with aria2c                                          SUCCESS
--------- I need to check downloading multiple files (wget -m, aria2c file list)        FAIL (proxy-server not built for this, NEED TO CORRECT)

----sending back incorrect http responses (400, 404, 403) (Checked but triple check right before submitting)
--------- 400 Sent for no \r\n\r\n, no http 1.1 or 1.0, not GET verb                    SUCCESS
--------- 404 sent for hostname not found (ip address)                                  SUCCESS
--------- 403 Block List works                                                          SUCCESS 

*/


