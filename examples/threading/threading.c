#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
    //convert the input into seconds
    int wait_obtain_sec = (thread_func_args->wait_obtain_ms)/1000;
    int wait_release_sec = (thread_func_args->wait_release_ms)/1000;
    
    //sleep for requested amount of time
    sleep(wait_obtain_sec);
    
    //lock the mutex
    int ret = pthread_mutex_lock(thread_func_args->m_mutex);
    
    //if unable to acquire the lock exit the thread
    if(ret != 0)
    {
    	ERROR_LOG("Failed to aquire lock\n\r");
    	pthread_exit(thread_param);
    }

    DEBUG_LOG("Acquired lock\n\r");
    
    //sleep for wait_release_sec and unlock the mutex
    sleep(wait_release_sec);
    
    if(pthread_mutex_unlock(thread_func_args->m_mutex))
    {
    	ERROR_LOG("Failed to unlock\n\r");
    	pthread_exit(thread_param);
    }

    //update the completion status and exit the thread
    thread_func_args->thread_complete_success = true;
    pthread_exit(thread_param);
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
     //Use default attributes
     pthread_attr_t* attr = NULL;
     
     //create the structure for thread_data and assign the values
     struct thread_data *t_data = (struct thread_data *)malloc(sizeof(struct thread_data));
     t_data->m_mutex = mutex;
     t_data->wait_obtain_ms = wait_to_obtain_ms;
     t_data->wait_release_ms = wait_to_release_ms;
     t_data->thread_complete_success = false;
     
     //create a thread using threadfunc
     int ret = pthread_create(thread, attr, threadfunc, (void *)t_data);
     
     //verify if the thread has created successfully and return true
     if (ret == 0)
     {
     	return true;
     }
     
     //On failure release resources and log the failure
     pthread_mutex_destroy(t_data->m_mutex);
     free(t_data);
     ERROR_LOG("Failed to create new thread\n\r");
     perror("ERROR: Unable to create a new thread!");
     return false;
}

