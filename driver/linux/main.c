#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>

#define DRIVER_NAME "arakne_probe"
#define DEVICE_NAME "arakne"
#define CLASS_NAME  "arakne_ctl"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arakne");
MODULE_DESCRIPTION("Arakne Forensic Kernel Probe");
MODULE_VERSION("1.0");

static int    majorNumber;
static struct class*  arakneClass  = NULL;
static struct device* arakneDevice = NULL;

// --- Kprobe Structure for sys_execve ---
static struct kprobe kp = {
    .symbol_name = "__x64_sys_execve", // For x86_64 kernels. adjust for arm64
    // .pre_handler = handler_pre,
};

// Simple Pre-handler to log execution
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    // In a real scenario, we would parse the filename argument from userspace
    // char *filename_ptr = (char *)regs->di; // 1st arg in x64 ABI
    
    // printk(KERN_INFO "Arakne: Execve intercepted!\n");
    return 0;
}

// --- Char Device Prototypes ---
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

static int __init arakne_init(void) {
    printk(KERN_INFO "Arakne: Initializing Kernel Probe...\n");

    // 1. Register Device
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0) {
        printk(KERN_ALERT "Arakne: Failed to register a major number\n");
        return majorNumber;
    }

    // 2. Register Class & Device
    arakneClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(arakneClass)) {
        unregister_chrdev(majorNumber, DEVICE_NAME);
        return PTR_ERR(arakneClass);
    }
    
    arakneDevice = device_create(arakneClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(arakneDevice)) {
        class_destroy(arakneClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        return PTR_ERR(arakneDevice);
    }

    // 3. Enable Kprobe
    kp.pre_handler = handler_pre;
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ALERT "Arakne: register_kprobe failed, returned %d\n", ret);
        // We don't fail load here, allow utility to work without hooks
    } else {
        printk(KERN_INFO "Arakne: Probe registered at %p\n", kp.addr);
    }

    printk(KERN_INFO "Arakne: LKM Loaded. /dev/%s created.\n", DEVICE_NAME);
    return 0;
}

static void __exit arakne_exit(void) {
    unregister_kprobe(&kp);
    device_destroy(arakneClass, MKDEV(majorNumber, 0));
    class_unregister(arakneClass);
    class_destroy(arakneClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_INFO "Arakne: LKM Unloaded.\n");
}

static int dev_open(struct inode *inodep, struct file *filep) {
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
   // Implementation: Return hidden PID list
   return 0;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep) {
   return 0;
}

module_init(arakne_init);
module_exit(arakne_exit);
