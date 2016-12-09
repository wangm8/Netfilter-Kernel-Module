#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include<linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

int len, temp;

static char *msg = 0;


static ssize_t
read_proc (struct file *filp, char __user * buf, size_t count, loff_t * offp)
{
  if (count > temp)
    {
      count = temp;
    }
  temp = temp - count;
  copy_to_user (buf, msg, count);
  if (count == 0)
    temp = len;
  return count;
}

static ssize_t
write_proc (struct file *filp, const char __user * buf, size_t count,
	    loff_t * offp)
{

  if (msg == 0 || count > 100)
    {
      printk (KERN_INFO " either msg is 0 or count >100\n");
    }

  // you have to move data from user space to kernel buffer
  copy_from_user (msg, buf, count);
  len = count;
  temp = len;
  return count;
}

static const struct file_operations proc_fops = {
  .owner = THIS_MODULE,
  .read = read_proc,
  .write = write_proc,
};

void
create_new_proc_entry (void)
{
  proc_create ("userlist", 0666, NULL, &proc_fops);


  msg = kmalloc (100 * sizeof (char), GFP_KERNEL);
  if (msg == 0)
    {
      printk (KERN_INFO "why is msg 0 \n");
    }
}


int
proc_init (void)
{
  create_new_proc_entry ();
  return 0;
}

void
proc_cleanup (void)
{
  remove_proc_entry ("userlist", NULL);
}

MODULE_LICENSE ("GPL");
module_init (proc_init);
module_exit (proc_cleanup);