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
#include <pthread.h>
#include "queue.h"
#include <time.h>

#define PORT         	"9000"
#define BUFF_MAX   	1024
const char *aesddata_file = "/var/tmp/aesdsocketdata";
#define FAILURE	(-1)
#define SUCCESS	(0)
#define DELAY		(10)

int exit_condition_flag = 0;
int daemonize = 0;
int Clientfd = -1;
int filefd = -1;
char* buf= NULL;

char *ip_address='\0';
char ip_addr[INET_ADDRSTRLEN];

typedef struct socket_node
{
    pthread_t thread_id;
    pthread_mutex_t *log_mutex;
    bool thread_status;
    int fd_client;
    SLIST_ENTRY(socket_node) next_node;
}socket_data_t;

/**
 * @Function name: cleanup
 * @Brief: Performs all the cleanup and closing of file descriptors,
 * remove the file, close the log and exits
 * @Param: The exit code with which we want to exit
 */
void cleanup(int socketfd) 
{
	if (buf != NULL)
	{
		free(buf);
		buf = NULL;
	}
 	
 	// Close open sockets
 	if (socketfd >= 0) 
 	{
 		close(socketfd);
 		syslog(LOG_INFO, "Closed socketfd: %d", socketfd);
 	}

 	// Delete the file
 	remove(aesddata_file);
	
 	// Close syslog
 	syslog(LOG_INFO, "Exiting...");
 	closelog();
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
 	}
}


/**
 * @Function name: daemonization_func
 * @Brief: Starts the program in the background
 * @Param: void
 */
int daemonization_func(void) 
{
    fflush(stdout);
    
    pid_t pid = fork();

    if (pid < 0) 
    {
	syslog(LOG_ERR, "ERROR: Unable to fork");
	return FAILURE;
    }

    if (pid > 0) 
    {
    	syslog(LOG_INFO, "Parent calling exit");
	exit(SUCCESS);
    }
    
    syslog(LOG_INFO, "Inside Child Process instance");
	
    pid_t sid = setsid();
    if (sid < 0) 
    {
	syslog(LOG_ERR, "ERROR: Unable to create new session");
	return FAILURE;
    }

    if ((chdir("/")) < 0) 
    {
	syslog(LOG_ERR, "ERROR: Unable to change the working directory");
	return FAILURE;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    		
    int fd = open("/dev/null", O_WRONLY);
    if (fd == -1)
    {
	syslog(LOG_PERROR, "open:%s\n", strerror(errno));
	close(fd);
	return FAILURE;      
    }
    if (dup2(fd, STDIN_FILENO)  == -1)
    {
	syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
	close(fd);
	return FAILURE; 
    }
    if (dup2(fd, STDOUT_FILENO)  == -1)
    {
	syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
	close(fd);
	return FAILURE;
    }
    if (dup2(fd, STDERR_FILENO)  == -1)
    {
	syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
	close(fd);
	return FAILURE;  
    }
    close(fd);

    return SUCCESS;
    
}

/**
 * @Function name: reg_signal_handlers
 * @Brief: Function responsible for registering signal handlers
 * @Param: void
 */
void reg_signal_handlers(void)
{
    	// Register signal handlers for SIGINT and SIGTERM
    	struct sigaction signal_actions;
    	sigemptyset(&signal_actions.sa_mask);
    	signal_actions.sa_flags = 0;
    	signal_actions.sa_handler = signal_handler;

	if (sigaction(SIGINT, &signal_actions, NULL) != SUCCESS)
	{
		syslog(LOG_ERR, "ERROR: Unable to register SIGINT signal handler");
	}
	if (sigaction(SIGTERM, &signal_actions, NULL) != SUCCESS)
	{
		syslog(LOG_ERR, "ERROR: Unable to register SIGTERM signal handler");
	}
	syslog(LOG_INFO, "SIGINT & SIGTERM registration successful");
}

/**
 * @Function name: socket_connect
 * @Brief: socket_connect function connects to the input socket and updates the ip_addr
 * @Param: socketfd: socket file descriptor, ip_addr: ip address of the connected socket
 */
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
       ip_address = ip_addr;

       return socket_fd;
}

/**
 * @Function name: updatetime_thread
 * @Brief: updatetime_thread function updates the corresponding time stamp using mutex
 * @Param: socket_node: structure
 */
void *updatetime_thread(void *socket_node)
{	
    	if (socket_node == NULL)
    	{
    	    	return NULL;
    	}
    	socket_data_t *node = (socket_data_t *)socket_node;
    	node->thread_status = false;
    	struct timespec time_period;
    	int status;
	time_t curr_time;
	struct tm *tm_time;
	char timer_buff[BUFF_MAX] = {'\0'};
	int log_time_fd=-1;
	int bytes_written = 0;
    
    	while (!exit_condition_flag)
    	{
        	if (clock_gettime(CLOCK_MONOTONIC, &time_period) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to get time");
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;
        	}
        	time_period.tv_sec += DELAY;
        
        	if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &time_period, NULL) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to sleep for 10 sec"); 
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;   
        	}

        	curr_time = time(NULL);
        	if (curr_time == FAILURE)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to get current time");
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit; 
        	}

        	tm_time = localtime(&curr_time);
        	if (tm_time == NULL)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to fill tm struct");
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;
        	}
        	
        	if (strftime(timer_buff, sizeof(timer_buff), "timestamp: %Y, %m, %d, %H, %M, %S\n", tm_time) == 0)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to convert tm into string");
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;   
        	}	
        
        	log_time_fd = open(aesddata_file, O_CREAT|O_RDWR|O_APPEND, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
        	if (log_time_fd == FAILURE)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to create/open %s file", aesddata_file);
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;
        	}       
        	if (pthread_mutex_lock(node->log_mutex) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to acquire mutex (updatetime_thread)");
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;
        	}
        	// Writing the timestamp
        	bytes_written = write(log_time_fd, timer_buff, strlen(timer_buff));
        	if (bytes_written != strlen(timer_buff))
        	{
            		syslog(LOG_ERR, "ERROR: Failed to log timestamp to %s", aesddata_file);
            		pthread_mutex_unlock(node->log_mutex);
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;
        	}
        	if (pthread_mutex_unlock(node->log_mutex) != SUCCESS)
        	{
            		syslog(LOG_ERR, "ERROR: Failed to unlock mutex (updatetime_thread)");
            		status = FAILURE;
            		close(log_time_fd);
            		goto exit;
        	}
		status = SUCCESS;
        	close(log_time_fd);
    	}

     exit:
     	if (status == FAILURE) 
    	{
    		node->thread_status = false;
	} 
	else 
	{
    		node->thread_status = true;
	}
     	return socket_node;
}

/**
 * @Function name: updatedata_thread
 * @Brief: updatedata_thread function with the socket application, updates data using mutex into a file
 * @Param: socket_node: structure
 */
void *updatedata_thread(void *socket_node)
{
    	int recv_bytes = 0;
    	char buffer[BUFF_MAX] = {'\0'};
    	bool packet_complete = false;
    	int file_fd = -1;
    	socket_data_t* node = NULL;

    	if (socket_node == NULL)
    	{
    	    return NULL;
    	}
    	else
    	{
    	    node = (socket_data_t *)socket_node;
    	    node->thread_status = false;
    	    file_fd = open(aesddata_file, O_CREAT|O_RDWR|O_APPEND, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
    	    if (file_fd == FAILURE)
    	    {
    	        syslog(LOG_ERR, "ERROR: Failed to create/open file");
    	        node->thread_status = false;
    	        goto thread_exit;
    	    }

    	    int bytes_written = 0;
    	    int new_len = BUFF_MAX;
    	    int total_bytes_recv = 0;
    	    char *final_buffer = (char *)malloc(sizeof(char));
    	    memset(final_buffer, 0, sizeof(char));
    	    if(final_buffer == NULL)
    	    {
    	    	  node->thread_status = false;
    	         goto thread_exit;
    	    }
    	    // Receive data till new line is found
    	    do
    	    {
    	        memset(buffer, 0, BUFF_MAX);
    	        recv_bytes = recv(node->fd_client, buffer, BUFF_MAX, 0);
    	        if (recv_bytes == FAILURE)
    	        {
    	            syslog(LOG_ERR, "ERROR: Failed to recieve byte from client");
    	            node->thread_status = false;
    	            goto thread_exit;
    	        }
    	        else if (recv_bytes > 0)
    	        {
    	            new_len += 1;
    	            char *tmp_buf = realloc(final_buffer, new_len);
		    if (!tmp_buf)
		    {
		        syslog(LOG_ERR, "Realloc failure");
	    	        node->thread_status = false;
	    	        goto thread_exit;
		    }

		    // Move contents of most recent recv into final buffer
		    final_buffer = tmp_buf;
		    total_bytes_recv += recv_bytes;
		    strcat(final_buffer, buffer);
    	        }

    	        // Check if new line
    	        if ((memchr(buffer, '\n', recv_bytes)) != NULL)
    	        {
    	            packet_complete = true;
    	        }
    	    }while(!packet_complete);
    	    
    	    if (pthread_mutex_lock(node->log_mutex) != SUCCESS)
    	    {
		syslog(LOG_ERR, "ERROR: Failed to acquire mutex (data_thread)");
		node->thread_status = false;
		goto thread_exit;
	    }
		
	    bytes_written = write(file_fd, final_buffer, total_bytes_recv);
	    if (bytes_written != recv_bytes)
	    {
		syslog(LOG_ERR, "ERROR: Failed to write data");
		node->thread_status = false;
		pthread_mutex_unlock(node->log_mutex);
		goto thread_exit;
	    }
	    if (pthread_mutex_unlock(node->log_mutex) != SUCCESS)
	    {
	    	syslog(LOG_ERR, "ERROR: Failed to unlock mutex (data_thread)");
		node->thread_status = false;
		goto thread_exit;
	    }

    	    // Set file pos to begining of file
    	    off_t offset = lseek(file_fd, 0, SEEK_SET);
    	    if (-1 == offset)
    	    {
    	        syslog(LOG_ERR, "ERROR: Failed to SET file offset");
    	        node->thread_status = false;
    	        goto thread_exit;
    	    }

    	    int send_bytes = 0;
    	    int bytes_read = 0;

    	    do
    	    {
    	        memset(buffer, 0, BUFF_MAX);
    	        bytes_read = read(file_fd, buffer, BUFF_MAX);
    	        if (bytes_read == -1)
    	        {
    	            	syslog(LOG_ERR, "ERROR: Failed to read from %s file", aesddata_file);
   		    	node->thread_status = false;
              		goto thread_exit;
            	}

            	syslog(LOG_INFO, "read succesful : %d bytes read", bytes_read);
            			
            	if (bytes_read)
            	{
        		// Send file data back to the client
            	    	send_bytes = send(node->fd_client, buffer, bytes_read, 0);
                	if (send_bytes != bytes_read)
                	{
                    		syslog(LOG_ERR, "ERROR: Failed to Sending received data");
                    		node->thread_status = false;
                    		goto thread_exit;
                	}
                	node->thread_status = true;
            	}
            }while (send_bytes != bytes_read);

            if(final_buffer != NULL)
            {
            	free(final_buffer);
            	final_buffer = NULL;
            }
    	}

	thread_exit:
		if (file_fd != -1)
    		{
        		close(file_fd);
    		}
    		if (close(node->fd_client) != SUCCESS)
    		{
    		    	syslog(LOG_INFO, "Unable to close connection from %s", ip_address);
    		}

    	syslog(LOG_INFO, "Closed connection from %s", ip_address);
    	return socket_node;
}


/**
 * @Function name: main
 * @Brief: main function with the socket application, recieves datd and sends back to client
 * @Param: argument count and argument inputs from the command line
 */
int main(int argc, char *argv[]) 
{
	buf = (char *)malloc(BUFF_MAX * sizeof(char));
	pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
	socket_data_t *data_ptr = NULL;
    	socket_data_t *data_ptr_temp = NULL;
    	int status = SUCCESS;
	
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
	
	SLIST_HEAD(socket_head, socket_node) head;
    	SLIST_INIT(&head);
    	
	int socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == -1) 
	{
		syslog(LOG_ERR, "ERROR: Unable to create socket");
		status = FAILURE;
		goto exit;
	} 
	syslog(LOG_INFO, "socket() : Socket Created with sockfd: %d",socketfd);   	
	    	
	if (getaddrinfo(NULL, PORT, &hints, &serverInfo) != 0)
	{
		syslog(LOG_ERR, "ERROR: Unable to get socket address with getaddrinfo");
		if (serverInfo != NULL)
		{
		    freeaddrinfo(serverInfo);
		}
		status = FAILURE;
		goto exit;
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
		status = FAILURE;
		goto exit;
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
	      	status = FAILURE;
	      	goto exit;
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
       	if (daemonization_func() != 0)
       	{
       		syslog(LOG_ERR, "ERROR: Failed to run as a daemon");
        		status = FAILURE;
        		goto exit;
       	}
    	}
	
	if (listen(socketfd, 10) == -1) 
	{
       	syslog(LOG_ERR, "ERROR: unable to listen");
       	status = FAILURE;
       	goto exit;
    	}
	syslog(LOG_INFO, "listen() : listening for client");
	
	// Node for timestamp thread
    	data_ptr = (socket_data_t *)malloc(sizeof(socket_data_t));
    	if (data_ptr == NULL)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to malloc");
        	status = FAILURE;
        	goto exit;
    	}
	
	data_ptr->thread_status = false;
    	data_ptr->log_mutex = &thread_mutex;

    	// Thread for timestamp
    	if (pthread_create(&data_ptr->thread_id, NULL, updatetime_thread, data_ptr) != SUCCESS)
    	{
        	syslog(LOG_ERR, "ERROR: Failed to Create timer thread");
        	free(data_ptr);
        	data_ptr = NULL;
        	status = FAILURE;
        	goto exit;
    	} 
    	SLIST_INSERT_HEAD(&head, data_ptr, next_node);

    	
    	//Receives the data until a packet is completely received, write data into aesddata file location
	while(!exit_condition_flag)
	{
       	Clientfd = socket_connect(socketfd, ip_addr);
       	if (Clientfd == -1) 
       	{
       		continue;
       	}
       	else
       	{
       		// Creating socket node for each connection
	    		data_ptr = (socket_data_t *)malloc(sizeof(socket_data_t));
	    		if (data_ptr == NULL)
	    		{
				syslog(LOG_ERR, "ERROR: Failed to malloc");
				status = FAILURE;
				goto exit;
	    		}
	    		
	    		data_ptr->fd_client = Clientfd;
	    		data_ptr->thread_status = false;
	    		data_ptr->log_mutex = &thread_mutex;
	    		// Create thread for each connection
	    		if (SUCCESS != pthread_create(&data_ptr->thread_id, NULL, updatedata_thread, data_ptr))
	    		{
				syslog(LOG_ERR, "ERROR: Failed to create connection thread");
				free(data_ptr);
				data_ptr = NULL;
				status = FAILURE;
				goto exit;
	    		} 
	    		SLIST_INSERT_HEAD(&head, data_ptr, next_node);	
       	}
       	
       	// If thread exited, join thread and remove from linkedlist
       	data_ptr = NULL;
        	SLIST_FOREACH_SAFE(data_ptr, &head, next_node, data_ptr_temp)
        	{
            		if (data_ptr->thread_status == true)
            		{
                		syslog(LOG_INFO, "1 Joined thread id: %ld", data_ptr->thread_id);
                		pthread_join(data_ptr->thread_id, NULL);
                		SLIST_REMOVE(&head, data_ptr, socket_node, next_node);
                		free(data_ptr);
                		data_ptr = NULL;
            		}
        	} 
	}

	exit:
    		cleanup(socketfd);
    		pthread_mutex_destroy(&thread_mutex);
    		while (!SLIST_EMPTY(&head))
    		{
        		data_ptr = SLIST_FIRST(&head);
        		SLIST_REMOVE_HEAD(&head, next_node);
        		pthread_join(data_ptr->thread_id, NULL);
        		free(data_ptr);
        		data_ptr = NULL;
    		}

    return status;
}
