/**
 * @File: aesdsocket.c
 *
 * @Author: Sai Charan Mandadi
 * @Date: 21 Feb 2024
 * @References: AESD Course Slides
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PORT         	"9000"
#define BUFF_MAX   	1024
const char *aesddata_file = "/var/tmp/aesdsocketdata";
#define FAILURE	(-1)
#define SUCCESS	(0)

int exit_condition_flag = 0;
int daemonize = 0;
int socketfd, Clientfd, filefd;
char* buf= NULL;

/**
 * @Function name: cleanup
 * @Brief: Performs all the cleanup and closing of file descriptors,
 * remove the file, close the log and exits
 * @Param: The exit code with which we want to exit
 */
void cleanup(int exit_code) 
{
	if (buf != NULL)
	{
		free(buf);
		buf = NULL;
	}
 	close(socketfd);
 	close(Clientfd);
 	close(filefd);
 	remove(aesddata_file);
 	closelog();
 	syslog(LOG_INFO, "Exiting...");
 	exit(exit_code);
}


/**
 * @Function name: signal_handler
 * @Brief: Signal handler for SIGINT nad SIGTERM
 * @Param: The signal number
 */
void signal_handler(int signo)
{
 	if ((signo == SIGINT) || (signo == SIGTERM))
 	{
 		exit_condition_flag = 1;
 		syslog(LOG_DEBUG, "Caught signal, exiting");
 	    	cleanup(SUCCESS);
 	}
}


/**
 * @Function name: daemonization_func
 * @Brief: Starts the program in the background
 * @Param: void
 */
void daemonization_func(void) 
{
    pid_t pid = fork();
    fflush(stdout);

    if (pid < 0) 
    {
        syslog(LOG_ERR, "ERROR: Unable to fork");
        cleanup(EXIT_FAILURE);
    }

    if (pid > 0) 
    {
    	syslog(LOG_INFO, "Parent calling exit");
        exit(SUCCESS);
    }
	
    syslog(LOG_INFO, "Child Process");
	
    pid_t sid = setsid();
    if (sid < 0) 
    {
        syslog(LOG_ERR, "ERROR: Unable to create new session");
        cleanup(FAILURE);
    }

    if ((chdir("/")) < 0) 
    {
        syslog(LOG_ERR, "ERROR: Unable to change the working directory");
        cleanup(FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    		
    int fd = open("/dev/null", O_WRONLY);
    if (fd == -1)
    {
        syslog(LOG_PERROR, "open:%s\n", strerror(errno));
        close(fd);
        cleanup(FAILURE);       
    }
    if (dup2(fd, STDIN_FILENO)  == -1)
    {
        syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
        close(fd);
        cleanup(FAILURE);    
    }
    if (dup2(fd, STDOUT_FILENO)  == -1)
    {
        syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
        close(fd);
        cleanup(FAILURE);    
    }
    if (dup2(fd, STDERR_FILENO)  == -1)
    {
        syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
        close(fd);
        cleanup(FAILURE);    
    }
    close(fd);	
}

/**
 * @Function name: reg_signal_handlers
 * @Brief: Function responsible for registering signal handlers
 * @Param: void
 */
void reg_signal_handlers(void)
{
	if (signal(SIGINT, signal_handler) == SIG_ERR)
	{
		syslog(LOG_ERR, "ERROR: Unable to register SIGINT signal handler");
	}
	if (signal(SIGTERM, signal_handler) == SIG_ERR)
	{
		syslog(LOG_ERR, "ERROR: Unable to register SIGTERM signal handler");
	}
	syslog(LOG_INFO, "SIGINT & SIGTERM registration successful");
}

int socket_connect(int socketfd, char* ip_addr)
{
       struct sockaddr_in client_addr;
       socklen_t client_addr_len = sizeof(client_addr);

	//accept the socket connection corresponding to client_addr
       int socket_fd = accept(socketfd, (struct sockaddr*)&client_addr, &client_addr_len);
       if (socket_fd == -1) 
       {
       	syslog(LOG_ERR, "socket accept fail: %m\n");
       	return -1;
       }
       syslog(LOG_INFO, "Connection accepted with Client fd: %d",socket_fd);
       
       //Converts ip address into string characters
       if (inet_ntop(AF_INET, &(client_addr.sin_addr), ip_addr, INET_ADDRSTRLEN) == NULL)
       {
       	syslog(LOG_ERR, "ERROR: Unable to get the IP address");	
       }
       syslog(LOG_INFO, "Accepted connection from %s", ip_addr);

       return socket_fd;
}

/**
 * @Function name: main
 * @Brief: main function with the socket application, recieves datd and sends back to client
 * @Param: argument count and argument inputs from the command line
 */
int main(int argc, char *argv[]) 
{
	buf = (char *)malloc(BUFF_MAX * sizeof(char));
	bool packet_complete = false;
	int recv_bytes = 0;
	int written_bytes = 0;
	
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	    	
	struct addrinfo *serverInfo = NULL;
	    
	openlog(NULL, 0, LOG_USER);
	
	//check if arguments are valid with -d
	if ((argc == 2) && (strcmp(argv[1], "-d") == 0))
	{
		daemonize = 1;
		syslog(LOG_INFO, "Starting as DAEMON Process");
	}
	
	//register signal handlers
	reg_signal_handlers();
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == -1) 
	{
		syslog(LOG_ERR, "ERROR: Unable to create socket");
		cleanup(FAILURE);
	} 
	syslog(LOG_INFO, "socket() : Socket Created with sockfd: %d",socketfd);   	
	    	
	if (getaddrinfo(NULL, PORT, &hints, &serverInfo) != 0)
	{
		syslog(LOG_ERR, "ERROR: Unable to get socket address with getaddrinfo");
		if (serverInfo != NULL)
		{
		    freeaddrinfo(serverInfo);
		}
		cleanup(FAILURE);
	}
	syslog(LOG_INFO, "getaddrinfo() : result server socket address");  	
	
	//Sets socket option to reuse socket address
	int reuse = 1;
	if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse, sizeof(int)) == -1) 
	{
	      	syslog(LOG_ERR, "ERROR: Unable to set reuse option with setsockopt");
	      	if (serverInfo != NULL)
	      	{
	      		freeaddrinfo(serverInfo);
	      	}
		cleanup(FAILURE);
	}
	syslog(LOG_INFO, "setsockopt() : Port reuse option");

	//binds the socket address to file descriptor
	if (bind(socketfd, serverInfo->ai_addr, serverInfo->ai_addrlen) != 0)
	{
	     	syslog(LOG_PERROR, "ERROR: Unable to bind socket and port");
	      	if (serverInfo != NULL)
	      	{
	      		freeaddrinfo(serverInfo);
	      	}
	      	cleanup(FAILURE);
	}
	syslog(LOG_INFO, "bind() : Bind socket and port");
	
    	if (serverInfo != NULL)
    	{
       	freeaddrinfo(serverInfo);
    	}
	
	//Start the daemon process if -d is specified
	if (daemonize) 
	{
		syslog(LOG_INFO, "Running as DAEMON Process");
       	daemonization_func();
    	}
	
	if (listen(socketfd, 10) == -1) 
	{
       	syslog(LOG_ERR, "ERROR: unable to listen");
       	cleanup(FAILURE);
    	}
	syslog(LOG_INFO, "listen() : listening for client");

    	
    	//Receives the data until a packet is completely received, write data into aesddata file location
	while(!exit_condition_flag)
	{
       	char ip_addr[INET_ADDRSTRLEN];
       	Clientfd = socket_connect(socketfd, ip_addr);
       	if (Clientfd == -1) 
       	{
       		continue;
       	}
       	
       	filefd = open(aesddata_file, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    		if (filefd == -1)
   		{
       		syslog(LOG_ERR, "ERROR: Unable to open file");
       		cleanup(FAILURE);
   		}
   	
       	do
       	{
       		memset(buf, 0, BUFF_MAX);
       		recv_bytes = recv(Clientfd, buf, BUFF_MAX, 0);
       		if (recv_bytes == -1)
       		{
           			syslog(LOG_ERR, "ERROR: unable to recieve data from client");
      				cleanup(FAILURE);
       		}

       		written_bytes = write(filefd, buf, recv_bytes);
       		if (written_bytes != recv_bytes)
       		{
         		        syslog(LOG_ERR, "ERROR: Unable to write into the file");
       			cleanup(FAILURE);
       		}

       		if (NULL != (memchr(buf, '\n', recv_bytes)))
       		{
           			packet_complete = true;
       		}
        		
       	}while(!packet_complete);
        	
       	packet_complete = false;

       	off_t offset = lseek(filefd, 0, SEEK_SET);
       	if (offset == -1)
       	{
       		syslog(LOG_ERR, "ERROR: lseek fail");
       		cleanup(FAILURE);
       	}

       	int read_bytes = 0;
       	int send_bytes = 0;
       	
       	//reads the data and re transmits to the client
		do
		{
		    memset(buf, 0, BUFF_MAX);
		    read_bytes = read(filefd, buf, BUFF_MAX);
		    if (read_bytes == -1)
		    {
		    	syslog(LOG_ERR, "ERROR: Unable to read from the file");
			cleanup(FAILURE);
		    }
		    		
		    if (read_bytes > 0)
		    {
		    	send_bytes = send(Clientfd, buf, read_bytes, 0);
		    	if (send_bytes != read_bytes)
		    	{
		    		syslog(LOG_ERR, "ERROR: Unable to send data to client");
				cleanup(FAILURE);
		        }
		    }
		}while(read_bytes > 0);
        	
        	//close the file and log corresponding debug information
		close(filefd);
	     	if (close(Clientfd) == 0)
		{
			syslog(LOG_INFO, "Closed connection from %s", ip_addr);
		}
        
	}
}
