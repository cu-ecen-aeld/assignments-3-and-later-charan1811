/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Sai Charan Mandadi"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    filp->private_data = NULL;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t entry_offset = 0;
    struct aesd_buffer_entry *entry = NULL;
    ssize_t read_bytes = 0;
    struct aesd_dev *dev_aesd = NULL;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    if ( (filp == NULL) || (buf == NULL))
    {
        PDEBUG("(AESD_READ)ERROR: invalid arguments");
        return -EINVAL;
    }
    /**
     * TODO: handle read
     */
    dev_aesd = filp->private_data;

    if (!dev_aesd)
    {
        PDEBUG("Unable to get private data of aesd_dev");
        return -EPERM;
    }

    if (mutex_lock_interruptible(&dev_aesd->lock))
    {
        PDEBUG("ERROR: mutex_lock_interruptible acquiring lock");
        return -ERESTARTSYS;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev_aesd->buffer,*f_pos, &entry_offset);
    if(entry == NULL)
    {
    	mutex_unlock(&dev_aesd->lock);
    	return read_bytes;
    }

    read_bytes = (entry->size - entry_offset);
    if (read_bytes > count)
    {
   	read_bytes = count;
    }

    retval = copy_to_user(buf, (entry->buffptr + entry_offset), read_bytes);
    if (retval != 0)
    {
	PDEBUG("ERROR:copy_to_user retval=%zu", retval);
	mutex_unlock(&dev_aesd->lock);
	return -EFAULT;
    }

/* copy_to_user returns '0' on success or number of bytes not copied */
    retval = (read_bytes - retval);
    *f_pos += retval;
    
    mutex_unlock(&dev_aesd->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    //ssize_t retval = -ENOMEM;
    ssize_t retval = 0;
    const char *free_buffptr = NULL;
    struct aesd_dev *dev_aesd = NULL;

    if ( (NULL == filp) || (NULL == buf))
    {
        PDEBUG("ERROR: aesd_read invalid arguments");
        return -EINVAL;
    }
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    dev_aesd = filp->private_data;
    if (mutex_lock_interruptible(&dev_aesd->lock))
    {
        PDEBUG("ERROR: mutex_lock_interruptible acquiring lock");
        return -ERESTARTSYS;
    }

    dev_aesd->entry.buffptr = krealloc(dev_aesd->entry.buffptr, (dev_aesd->entry.size + count),
                                  GFP_KERNEL);
    if (NULL == dev_aesd->entry.buffptr)
    {
        PDEBUG("(AESD_WRITE)ERROR: Unable to re allocate memory");
        retval = -ENOMEM;
        goto exit;
    }

    retval = copy_from_user((void *)(dev_aesd->entry.buffptr + dev_aesd->entry.size), buf, count);
    if (0 != retval)
    {
        PDEBUG("ERROR:Unable to copy from user retval=%zu", retval);
        goto exit;
    }

    /* copy_to_user returns '0' on success or number of bytes not copied */
    retval = (count - retval);
    dev_aesd->entry.size += retval;

    /* add to circular buffer if command is terminated by new line */
    if (dev_aesd->entry.buffptr[dev_aesd->entry.size-1] == '\n')
    {
        free_buffptr = aesd_circular_buffer_add_entry(&dev_aesd->buffer, &dev_aesd->entry);
        /* free overwritten entry buffptr */
        if (NULL != free_buffptr)
        {
            kfree(free_buffptr);
            free_buffptr = NULL;
        }
        /* reset working entry */
        dev_aesd->entry.buffptr = NULL;
        dev_aesd->entry.size = 0;
    }

exit:
    mutex_unlock(&dev_aesd->lock);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    if ((NULL == filp))
    {
        PDEBUG("ERROR: aesd_read invalid arguments");
        return -EINVAL;
    }
    
    struct aesd_dev *dev_aesd = NULL;
    loff_t buff_size = 0;
    uint8_t buff_index = 0;
    struct aesd_buffer_entry *buff_start = NULL;
    loff_t new_offset = 0;
    loff_t retval = 0;

    dev_aesd = filp->private_data;
    
    if (!dev_aesd)
    {
        PDEBUG("ERROR: private data access");
        return -EPERM;
    }
    
    if (mutex_lock_interruptible(&dev_aesd->lock))
    {
        PDEBUG("ERROR: mutex_lock_interruptible acquiring lock");
        return -ERESTARTSYS;
    }
    
    AESD_CIRCULAR_BUFFER_FOREACH(buff_start, &dev_aesd->buffer, buff_index)
    {
       buff_size += buff_start->size;
    }
    
    new_offset = fixed_size_llseek(filp, offset, whence, buff_size);
    
    if(new_offset < 0)
    {
    	retval = -EINVAL;
    }
    else
    {
    	filp->f_pos = new_offset;
    	retval = new_offset;
    }
    
    mutex_unlock(&dev_aesd->lock);
    
    return retval;   
}


static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    if (filp == NULL)
    {
        PDEBUG("ERROR: Input file pointer is NULL");
        return -EINVAL;
    }
    
    struct aesd_dev *dev_aesd = NULL;
    long ret_val = 0;
    uint8_t buff_size = 0;
    struct aesd_buffer_entry *buff_start = NULL;

    dev_aesd = filp->private_data;

    if (mutex_lock_interruptible(&dev_aesd->lock) != 0)
    {
        PDEBUG("ERROR: Unable to acquire mutex lock");
        return -ERESTARTSYS;
    }
    
    AESD_CIRCULAR_BUFFER_FOREACH(buff_start, &aesd_device.buffer, buff_size)
    {
    }

    if ( (write_cmd > buff_size) || (write_cmd > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) ||
         (write_cmd_offset >= dev_aesd->buffer.entry[write_cmd].size) )
    {
        ret_val = -EINVAL;
        goto end;
    }

    unsigned int index = 0;
    for(index = 0; index < write_cmd; index++)
    {
        filp->f_pos += dev_aesd->buffer.entry[index].size;
    }

    filp->f_pos += write_cmd_offset;

end:
    mutex_unlock(&dev_aesd->lock);
    return ret_val;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    if (!filp)
    {
        return -EINVAL;
    }

    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC)
    {
        return -ENOTTY;
    }
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
    {
 	return -ENOTTY;
    }
    
    long ret_val =0;

	switch(cmd)
	{
		case AESDCHAR_IOCSEEKTO:
		{
		    struct aesd_seekto seekto;
		    if(copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
		    {
		        ret_val = -EFAULT;
		    }
		    else
		    {
		        ret_val = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
		    }
		    break;
		}

		default:  
		    	return -ENOTTY;
    }
    
    return ret_val;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);

    if( result )
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    uint8_t index = 0;
    struct aesd_buffer_entry *entry = NULL;

    AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.buffer, index)
    {
        if (NULL != entry->buffptr)
        {
            kfree(entry->buffptr);
            entry->buffptr = NULL;
        }
    }
    
    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
