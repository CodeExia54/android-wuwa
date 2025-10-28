#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include "wuwa_common.h"
#include "wuwa_d0_mm_fault.h"
#include "wuwa_kallsyms.h"
#include "wuwa_protocol.h"
#include "wuwa_safe_signal.h"
#include "wuwa_sock.h"
#include "wuwa_utils.h"
#include "hijack_arm64.h"
#include <linux/fdtable.h>      /* Open file table structure: files_struct structure */
#include <linux/proc_ns.h>	

static struct kprobe kpp;
bool isPHook = false;

#include <linux/dirent.h>	/* struct dirent refers to directory entry. */

struct linux_dirent {
        unsigned long   d_ino;		/* inode number */
        unsigned long   d_off;		/* offset to the next dirent */
        unsigned short  d_reclen;	/* length of this record */
        char            d_name[1];	/* filename */
};

// To store the address of the found sys_call_table
static unsigned long *__sys_call_table;

// Defining a custom function type to store original syscalls
typedef asmlinkage long (*tt_syscall)(const struct pt_regs *);

static tt_syscall orig_getdents64;
static tt_syscall orig_kill;

unsigned long *get_syscall_table(void)
{
	unsigned long *syscall_table;
	syscall_table = (unsigned long*)kallsyms_lookup_name_ex("sys_call_table");
	return syscall_table;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    uint64_t v4;
    // int v5;
	if ((uint32_t)(regs->regs[1]) == 61) { // getdents64
		// wuwa_info("dents called");
		int fd = *(int*)(regs->user_regs.regs[0]);
		struct linux_dirent *dirent = *(struct linux_dirent **) (regs->user_regs.regs[0] + 8);

		unsigned short proc = 0;
	    unsigned long offset = 0;
	    struct linux_dirent64 *dir, *kdirent, *prev = NULL;

	    //For storing the directory inode value
	    struct inode *d_inode;
		int ret = 0;
		int err = 0;
		    
		kdirent = kzalloc(ret, GFP_KERNEL);

	    if (kdirent == NULL)
		    return;

	    // Copying directory name (or pid name) from userspace to kernel space
	    err = copy_from_user(kdirent, dirent, ret);
	    if (err)
			goto out;

		// Storing the inode value of the required directory(or pid) 
	    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

	    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		    proc = 1;

		while (offset < ret)
	    {
		    dir = (void *)kdirent + offset;

		    if ((proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10))))
		    {
			    if (dir == kdirent)
			    {
				    ret -= dir->d_reclen;
				    memmove(dir, (void *)dir + dir->d_reclen, ret);
					wuwa_info("skipped");
				    continue;
			    }
			    prev->d_reclen += dir->d_reclen;
				wuwa_info("skipped again");
		    }
		    else
		    {
			    prev = dir;
		    }
		    offset += dir->d_reclen;
	    }
	
	    // Copying directory name (or pid name) from kernel space to user space, after changing
	    err = copy_to_user(dirent, kdirent, ret);
	
	    if (err)
	    {
	        goto out;
	    }
		
	out:
	    kfree(kdirent);
	    return;
	}
	return;
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    uint64_t v4;
    // int v5;
	
    if ((uint32_t)(regs->regs[1]) == 167 /* syscall 29 on AArch64 */) {
        v4 = regs->user_regs.regs[0];
		// wuwa_info("prctl called");
        // Handle memory read request
        if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x6969) {
			wuwa_info("p with 6969 called");
			/*
            int status = give_root();
			if(status == 0)
				wuwa_info("root given");
			else
				wuwa_info("root not given");
			*/
        }
    }
	return 0;
}

static int __init wuwa_init(void) {
    int ret;
    wuwa_info("helo!\n");

    kpp.symbol_name = "invoke_syscall";
    kpp.pre_handler = handler_pre; 
	kpp.post_handler = handler_post;

    ret = register_kprobe(&kpp);
	if(ret < 0) {	
		isPHook = false;
	    wuwa_err("wuwa: driverX: Failed to register kprobe: %d (%s)\n", ret, kpp.symbol_name);
	    return ret;
	 } else {
		isPHook = true;
        wuwa_info("p probe success");
	}
/*
	__sys_call_table = get_syscall_table();
	if (!__sys_call_table) {
		wuwa_err("syscall table find error");
		return -1;
	}
	
	orig_getdents64 = (tt_syscall)__sys_call_table[__NR_getdents64];
	wuwa_info("dents found on %lx", orig_getdents64);
*/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    ret = disable_kprobe_blacklist();
    if (ret) {
        wuwa_err("disable_kprobe_blacklist failed: %d\n", ret);
        return ret;
    }
#endif

    ret = init_arch();
    if (ret) {
        wuwa_err("init_arch failed: %d\n", ret);
        return ret;
    }

    ret = wuwa_proto_init();
    if (ret) {
        wuwa_err("wuwa_socket_init failed: %d\n", ret);
        goto out;
    }

#if defined(BUILD_HIDE_SIGNAL)
    ret = wuwa_safe_signal_init();
    if (ret) {
        wuwa_err("wuwa_safe_signal_init failed: %d\n", ret);
        goto clean_sig;
    }

    ret = init_d0_mm_fault();
    if (ret) {
        wuwa_err("init_d0_mm_fault failed: %d\n", ret);
        goto clean_d0;
    }
#endif


#if defined(HIDE_SELF_MODULE)
    hide_module();
#endif

#if defined(BUILD_NO_CFI)
    wuwa_info("NO_CFI is enabled, patched: %d\n", cfi_bypass());
#endif

    return 0;

#if defined(BUILD_HIDE_SIGNAL)
clean_d0:
    wuwa_safe_signal_cleanup();

clean_sig:
    wuwa_proto_cleanup();
#endif


out:
    return ret;
}

static void __exit wuwa_exit(void) {
    wuwa_info("bye!\n");
    wuwa_proto_cleanup();
	if(isPHook) 
		unregister_kprobe(&kpp);
#if defined(BUILD_HIDE_SIGNAL)
    wuwa_safe_signal_cleanup();
    cleanup_d0_mm_fault();
#endif
}

module_init(wuwa_init);
module_exit(wuwa_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/android-wuwa");
MODULE_VERSION("1.0.4");

MODULE_IMPORT_NS(DMA_BUF);
