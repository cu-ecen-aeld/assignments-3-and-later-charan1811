#include <stdio.h>
#include <syslog.h>

#define ARGS_COUNT 3

void display_usage_info()
{
	printf("USAGE: ./writer <Path to File> <String>\n");
}

int main(int argc, char* argv[])
{
	openlog(NULL, LOG_PID, LOG_USER);

	if (argc != ARGS_COUNT)
	{
		syslog(LOG_ERR, "Invalid number of arguments");
		display_usage_info();
	}
	const char* file_path = argv[1];
	FILE *fd = fopen(file_path, "w");
	if (fd == NULL)
	{
		syslog(LOG_ERR, "Unable to open the file %s \n\r", file_path);
	}
	else
	{
		syslog(LOG_DEBUG, "File exists %s \n\r", file_path);
	}

	fclose(fd);
	closelog();

	return 0;
}
