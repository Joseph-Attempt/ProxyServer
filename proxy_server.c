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