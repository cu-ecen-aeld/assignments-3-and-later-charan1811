#include "systemcalls.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
	int status;
	status = system(cmd);
//Check if the system call is successful and return false on failure
	if ((status == -1))
	{
		return false;
	}
//Check exit status of the cmd and return false on failure
	if (!WIFEXITED(status))
	{
		return false;
	}


    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
    pid_t pid;
    int status;

    pid = fork();
//check the fork return status and return false on failure
    if (pid == -1)
    {
	    return false;
    }
//check for child process and exec in the child instance with the input command
    else if (pid == 0)
    {
	    execv(command[0], command);
	    exit(1);
    }
//waits for child process to exit and returns false on failure
    if (waitpid(pid, &status, 0) == -1)
    {
	    perror("wait PID");
	    return false;
    }
//check if the child has exited normally and return false if not
    else if (!(WIFEXITED(status)))
    {
	    return false;
    }
//check for the status after the child process has exited normally
    else
    {
	    if(WEXITSTATUS(status))
	    {
		    return false;
	    }
    }

    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/

    int status;
    pid_t pid;

    int fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
//Open a output file to redirect the messages
    if (fd == -1)
    {
	    perror("OPEN");
	    return false;
    }
//Create a child process and assign a new file descriptor for the output file in the child process
    switch (pid = fork())
    {
	    case 0: if (dup2(fd, 1) < 0)
		    {
			    perror("DUP2");
			    return false;
		    }
		    close(fd);
		    execv(command[0], command);
		    exit(1);
            case -1: perror("FORK");
                     return false;
	    default: close(fd);
    }
//Wait on the child process to exit and return the corresponding status
    if (waitpid(pid, &status, 0) == -1)
    {
            perror("wait PID");
            return false;
    }
    else if (!(WIFEXITED(status)))
    {
            return false;
    }
    else
    {
            if(WEXITSTATUS(status))
            {
                    return false;
            }
    }

    va_end(args);

    return true;
}
