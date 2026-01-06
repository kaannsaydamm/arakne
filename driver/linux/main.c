#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

#define DRIVER_NAME "arakne_probe"
#define DEVICE_NAME "arakne"
#define CLASS_NAME  "arakne_ctl"

// IOCTL Codes (must match Go user-space)
#define ARAKNE_IOCTL_MAGIC 'A'
#define IOCTL_ARAKNE_PING           _IO(ARAKNE_IOCTL_MAGIC, 0)
#define IOCTL_ARAKNE_KILL_PID       _IOW(ARAKNE_IOCTL_MAGIC, 1, int)
#define IOCTL_ARAKNE_NUKE_MODE      _IO(ARAKNE_IOCTL_MAGIC, 2)
#define IOCTL_ARAKNE_NET_ISOLATE    _IOW(ARAKNE_IOCTL_MAGIC, 3, int)
#define IOCTL_ARAKNE_SELF_DEFENSE   _IOW(ARAKNE_IOCTL_MAGIC, 4, int)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arakne");
MODULE_DESCRIPTION("Arakne God Mode Linux Kernel Module");
MODULE_VERSION("2.0");

static int    majorNumber;
static struct class*  arakneClass  = NULL;
static struct device* arakneDevice = NULL;

// Global State
static bool g_NukeMode = false;
static bool g_NetworkIsolate = false;
static pid_t g_ProtectedPID = 0;

// --- Kprobe Structure for sys_execve ---
static struct kprobe kp = {
    .symbol_name = "__x64_sys_execve",
};

// Pre-handler: Log and optionally block execution
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (g_NukeMode) {
        // In Nuke Mode, we could block non-whitelisted executions
        // For now, just log
        printk(KERN_INFO "Arakne: [NUKE] Execve intercepted\n");
    }
    return 0; // Return 0 to continue, -1 to block (requires kretprobe trick)
}

// --- Netfilter Hook for Network Isolation ---
static struct nf_hook_ops nfho_out;

static unsigned int nf_hook_out(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    if (g_NetworkIsolate) {
        // Block all outbound traffic
        return NF_DROP;
    }
    return NF_ACCEPT;
}

// --- Char Device Prototypes ---
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static long    dev_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
   .unlocked_ioctl = dev_ioctl,
};

static int __init arakne_init(void) {
    int ret;
    printk(KERN_INFO "Arakne: Initializing God Mode Kernel Module v2.0\n");

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
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ALERT "Arakne: register_kprobe failed, returned %d\n", ret);
    } else {
        printk(KERN_INFO "Arakne: Probe registered at %pS\n", kp.addr);
    }

    // 4. Register Netfilter Hook
    nfho_out.hook = nf_hook_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    
    ret = nf_register_net_hook(&init_net, &nfho_out);
    if (ret < 0) {
        printk(KERN_ALERT "Arakne: nf_register_net_hook failed: %d\n", ret);
    } else {
        printk(KERN_INFO "Arakne: Netfilter hook registered\n");
    }

    printk(KERN_INFO "Arakne: LKM Loaded. /dev/%s created.\n", DEVICE_NAME);
    return 0;
}

static void __exit arakne_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho_out);
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
   // Return status info
   char msg[64];
   int msgLen = snprintf(msg, sizeof(msg), "Nuke:%d Net:%d PID:%d\n", 
                         g_NukeMode, g_NetworkIsolate, g_ProtectedPID);
   if (*offset >= msgLen) return 0;
   if (copy_to_user(buffer, msg, msgLen)) return -EFAULT;
   *offset += msgLen;
   return msgLen;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
   return len;
}

static long dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    int val;
    
    switch (cmd) {
        case IOCTL_ARAKNE_PING:
            printk(KERN_INFO "Arakne: PONG!\n");
            return 0;
            
        case IOCTL_ARAKNE_KILL_PID:
            if (copy_from_user(&val, (int __user *)arg, sizeof(val)))
                return -EFAULT;
            printk(KERN_INFO "Arakne: Kill request for PID %d\n", val);
            // Note: Killing from kernel requires sending SIGKILL
            // kill_pid(find_vpid(val), SIGKILL, 1);
            return 0;
            
        case IOCTL_ARAKNE_NUKE_MODE:
            g_NukeMode = !g_NukeMode;
            printk(KERN_INFO "Arakne: Nuke Mode = %s\n", g_NukeMode ? "ON" : "OFF");
            return 0;
            
        case IOCTL_ARAKNE_NET_ISOLATE:
            if (copy_from_user(&val, (int __user *)arg, sizeof(val)))
                return -EFAULT;
            g_NetworkIsolate = (val != 0);
            printk(KERN_INFO "Arakne: Network Isolate = %s\n", g_NetworkIsolate ? "ON" : "OFF");
            return 0;
            
        case IOCTL_ARAKNE_SELF_DEFENSE:
            if (copy_from_user(&val, (int __user *)arg, sizeof(val)))
                return -EFAULT;
            g_ProtectedPID = val;
            printk(KERN_INFO "Arakne: Protected PID = %d\n", g_ProtectedPID);
            return 0;
            
        default:
            return -EINVAL;
    }
}

static int dev_release(struct inode *inodep, struct file *filep) {
   return 0;
}

module_init(arakne_init);
module_exit(arakne_exit);
