

#define __KERNEL__
#define MODULE
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/inet.h>

#include <linux/proc_fs.h>
#include<linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>



int ipindex=0; // index to write next ip address
int in_index = 0, out_index= 0; // index for iniplist and outiplist
char *allip;


char *iniplist[50]; // array holding incomming ip address to block
char *outiplist[50]; // array holding outgoing ip address to block

static char *msg = 0;


static struct nf_hook_ops nfho_in, nfho_out;   //net filter hook option struct
struct sk_buff *sock_buff;


void printinfo(void) {

	int i;

	printk("\n");
	if (in_index == 0) {
		printk("Not blocking any incoming network packet\n");
	}
	else{
		printk("Now blocking all network packet from following ip addresses:\n");

		
		for (i=0; i < in_index; i++) {
			printk("%s\n",iniplist[i]);
		}
	}
	printk("\n");

	if (out_index == 0) {
		printk("Not blocking any outgoing network packet\n");
	}else{
		printk("Now blocking all network packet going to following ip addresses:\n");
		for (i=0; i < out_index; i++) {
			printk("%s\n",outiplist[i]);
		}
		printk("\n");
	}	
}


static ssize_t read_proc (struct file *filp, char __user * buf, size_t count, loff_t * offp)
{

  	copy_to_user (buf, msg, count);
  	return count;
}

static ssize_t write_proc (struct file *filp, const char __user * buf, size_t count,
	    loff_t * offp)
{

 	//if (msg == 0 || count > 100)
 	//  {
 	//    printk (KERN_INFO " either msg is 0 or count >100\n");
 	//  }

 	// you have to move data from user space to kernel buffer
  	copy_from_user (msg, buf, count);
  	if (copy_from_user (&allip[ipindex], buf, count)) {
		return -EFAULT;
  	}

  	// for debug purpose
  	// printk(KERN_INFO "read data:\n%s\n",msg);
  	// printk(KERN_INFO "count is %d\n", count);
  

	if(msg[0] == 'p') {
		printinfo();
	}

  	if(msg[0] == 'r'){
    		in_index=0;
    		out_index=0;
    		ipindex=0;		
		printk("All ip addresses in the list are removed\n");
    		return count;
  	}

  	if (msg[0] == '0'|| msg[0] == '2') { 
    		iniplist[in_index] = kmalloc((count-2)*sizeof(char) , GFP_KERNEL);
    		allip[ipindex+count-1] = 0;
    		strcpy(iniplist[in_index], &allip[ipindex+2]);
		printk("Adding ip address %s to incomming target list\n", iniplist[in_index]);
		in_index += 1;
  	}
  

  	if (msg[0] == '1'|| msg[0] == '2') {
    		outiplist[out_index] = kmalloc((count-2)*sizeof(char) , GFP_KERNEL);
    		allip[ipindex+count-1] = 0;
    		strcpy(outiplist[out_index], &allip[ipindex+2]);
		printk("Adding ip address %s to outgoing target list\n", outiplist[out_index]);
    		out_index += 1;
  	}
  
  	// for debug purpose
  	// printk(KERN_INFO "current allip: %s\n", allip);
  	// printk(KERN_INFO "current ipindex: %d\n", ipindex);
  	// printk(KERN_INFO "current inip: %s\n", iniplist[in_index-1]);
  	// printk(KERN_INFO "current outip: %s\n", outiplist[out_index-1]);

  
  	ipindex += count;
  	return count;
}


static const struct file_operations proc_fops = {
  	.owner = THIS_MODULE,
  	.read = read_proc,
  	.write = write_proc,
};


 
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, 
			const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;            //ip header struct

        sock_buff = skb;
        if(!sock_buff) { return NF_ACCEPT;}
 
 
        ip_header = ip_hdr(sock_buff);    //grab network header using accessor

	char source[50];
	snprintf(source, 50, "%pI4", &ip_header->saddr);

	// for debug purpose
	// printk(KERN_INFO "got source address: %s\n", source); 
	// printk(KERN_INFO "got destination address: %s\n", destination); 
	
	// for debug purpose
	// printk("length of source: %d\n", strlen(source));
    	// printk("iniplist[0] length: %d\n", strlen(iniplist[0]));
	

	// if the source address and destination address is in the proc file, drop it;
	int i;
        for(i =0; i < in_index;i++){
          if(strcmp(source,iniplist[i])==0){
            printk("Drop incoming packet from %s\n",source);
            return NF_DROP;
          }
        }
        
        
        return NF_ACCEPT;
}


unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, 
			const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;            //ip header struct

        sock_buff = skb;
        if(!sock_buff) { return NF_ACCEPT;}
 
 
        ip_header = ip_hdr(sock_buff);    //grab network header using accessor

	char destination[50];
	snprintf(destination, 50, "%pI4", &ip_header->daddr);

	// for debug purpose
	// printk(KERN_INFO "got source address: %s\n", source); 
	// printk(KERN_INFO "got destination address: %s\n", destination); 
	
	// for debug purpose
	// printk("length of source: %d\n", strlen(source));
    	// printk("iniplist[0] length: %d\n", strlen(iniplist[0]));
	

	// if the source address and destination address is in the proc file, drop it;
	int i;
        
        for(i=0; i< out_index;i++){
          if(strcmp(destination,outiplist[i])==0){
            printk("Drop outgoing packet to %s\n",destination);
            return NF_DROP;
          }
        }             
        return NF_ACCEPT;
}


void create_new_proc_entry (void)
{
  	proc_create ("userlist", 0666, NULL, &proc_fops);
  	msg = kmalloc (100 * sizeof (char), GFP_KERNEL);
  	if (msg == 0)
    	{
      		printk (KERN_INFO "why is msg 0 \n");
    	}	
}



int init_module()
{
	
	create_new_proc_entry ();
	printk(KERN_INFO "-----Proc entry created-----");

	// register hook for incoming traffic
        nfho_in.hook = hook_func_in;
        nfho_in.hooknum = NF_INET_LOCAL_IN;
        nfho_in.pf = PF_INET;
        nfho_in.priority = NF_IP_PRI_FIRST;

	// register hook for outgoing traffic
	nfho_out.hook = hook_func_out;
        nfho_out.hooknum = NF_INET_LOCAL_OUT;
        nfho_out.pf = PF_INET;
        nfho_out.priority = NF_IP_PRI_FIRST;

        nf_register_hook(&nfho_in);
        nf_register_hook(&nfho_out);

	printk(KERN_INFO "-----Netfilter starts-----");	


	// malloc space for allip
	allip = (char *)kmalloc(1000*sizeof(char), GFP_KERNEL);
	
	
        return 0;
}
 
void cleanup_module()
{
	printk(KERN_INFO "-----Proc entry removed-----");	
	remove_proc_entry ("userlist", NULL);
	printk(KERN_INFO "-----Netfilter stops-----");	
        nf_unregister_hook(&nfho_in);     
	nf_unregister_hook(&nfho_out);   
	kfree(allip);
}
 

MODULE_AUTHOR("Ziqi Yang");
MODULE_LICENSE("GPL");
