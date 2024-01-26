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

void display_usage_info()
{
	printf("USAGE: ./writer <Path to File> <String>\n");
}

int open_file(const char* file_path)
{
	int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);

	return fd;
}

void close_file(int fd)
{
	close(fd);
}

int main(int argc, char* argv[])
{
	openlog(NULL, LOG_PID, LOG_USER);

	if (argc != ARGS_COUNT)
	{
		syslog(LOG_ERR, "Invalid number of arguments");
		display_usage_info();
		closelog();
		return 1;
	}

	const char* file_path = argv[1];
	ssize_t bytes_count;
	char* ip_str = argv[2];
	ssize_t ip_str_size = strlen(ip_str);

	int fd = open_file(file_path);
	if (fd == NULL_VAL)
	{
		syslog(LOG_ERR, "Unable to open the file %s \n\r", file_path);
		close_file(fd);
		closelog();
		return 1;
	}

	bytes_count = write(fd, ip_str, ip_str_size);

	if ((bytes_count == NULL_VAL) || (bytes_count == 0))
	{
		syslog(LOG_ERR, "ERROR: %d writing into the file %s, Input String: %s \n\r", errno, file_path, ip_str);
		close_file(fd);
		closelog();
		return 1;
	}

	syslog(LOG_DEBUG, "Finished writing into the file %s, Input String: %s \n\r", file_path, ip_str);

	close_file(fd);
	closelog();

	return 0;
}
