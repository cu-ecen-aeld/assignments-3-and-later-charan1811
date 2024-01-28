/***************************************************************************************************************
File Name	: writer.c
Description	: This file contains code to insert string into a file.
Author		: Sai Charan Mandadi
****************************************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define ARGS_COUNT 3
#define NULL_VAL -1

/***************************************************************************************************************
Description	: display_usage_info()
Prints the information about usage of applications and its arguments
Return type	: Void
Arguments	: Void
****************************************************************************************************************/
void display_usage_info(void)
{
	printf("USAGE: ./writer <Path to File> <String>\n");
}

/***************************************************************************************************************
Description     : open_file(const char*)
Function used to open a file by taking file path as its argument and returns file descriptor.
Return type     : int
Arguments       : const char*
****************************************************************************************************************/
int open_file(const char* file_path)
{
	int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);

	return fd;
}

/***************************************************************************************************************
Description     : close_file(int)
Function used to close a file by taking file descriptor as its argument.
Return type     : void
Arguments       : int
****************************************************************************************************************/
void close_file(int fd)
{
	close(fd);
}

/***************************************************************************************************************
Description     : main(int, char*)
This function is responsible for setting up syslog to log debug information and writes the input string into a file.
Return type     : int
Arguments       : (int, char*)
****************************************************************************************************************/
int main(int argc, char* argv[])
{
//Sets up sys log using name and modes
	openlog("AESD_WRITER", LOG_PID, LOG_USER);

//Verifies if the argument count is valid
	if (argc != ARGS_COUNT)
	{
		syslog(LOG_ERR, "Invalid number of arguments");
		display_usage_info();
		closelog();
		return 1;
	}

//Stores file path from the first argument
	const char* file_path = argv[1];
	ssize_t bytes_count;
//Stores the input string from the second argument
	char* ip_str = argv[2];
	ssize_t ip_str_size = strlen(ip_str);

//Open's the input file and verifies the return status
	int fd = open_file(file_path);
	if (fd == NULL_VAL)
	{
		syslog(LOG_ERR, "Unable to open the file %s \n\r", file_path);
		closelog();
		return 1;
	}

//Write and verify if the entire input stream has been succesfully written into the file
	bytes_count = write(fd, ip_str, ip_str_size);

	if ((bytes_count == NULL_VAL) || (bytes_count == 0))
	{
		syslog(LOG_ERR, "ERROR: %d writing into the file %s, Input String: %s \n\r", errno, file_path, ip_str);
		close_file(fd);
		closelog();
		return 1;
	}
	else if (bytes_count != ip_str_size)
	{
		syslog(LOG_ERR, "ERROR: PARTIAL WRITE: %d writing into the file %s, Input String: %s \n\r", errno, file_path, ip_str);
                close_file(fd);
                closelog();
                return 1;
	}

//Logs information after successful write
	syslog(LOG_DEBUG, "Finished writing into the file %s, Input String: %s \n\r", file_path, ip_str);

	close_file(fd);
	closelog();

	return 0;
}
