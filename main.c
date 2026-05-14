#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "checks.h"

#define SECMON_PROC_NAME "secmon_report"

static int secmon_show(struct seq_file *report, void *unused)
{
    seq_puts(report, "=== SECMON ROOTKIT DETECTOR REPORT ===\n\n");

    seq_puts(report, "[1] Hidden process check\n");
    hidden_process_check(report);
    seq_puts(report, "\n");

    seq_puts(report, "[2] Kernel module check\n");
    module_check(report);
    seq_puts(report, "\n");

    seq_puts(report, "[3] Syscall table / syscall hook check\n");
    syscall_check(report);
    seq_puts(report, "\n");

    // seq_puts(report, "[3] Autoload / persistence check\n");
    // autoload_check(report);
    // seq_puts(report, "\n");

    // seq_puts(report, "[5] Network backdoor check\n");
    // network_check(report);
    // seq_puts(report, "\n");

    seq_puts(report, "=== END OF REPORT ===\n");

    return 0;
}

static int secmon_open(struct inode *inode, struct file *file)
{
    return single_open(file, secmon_show, NULL);
}

static const struct proc_ops secmon_proc_ops = {
    .proc_open = secmon_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init secmon_init(void)
{
    struct proc_dir_entry *proc_entry;

    proc_entry = proc_create(SECMON_PROC_NAME, 0444, NULL, &secmon_proc_ops);
    if (!proc_entry) {
        pr_err("secmon: failed to create /proc/%s\n", SECMON_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("secmon: loaded, read /proc/%s\n", SECMON_PROC_NAME);
    return 0;
}

static void __exit secmon_exit(void)
{
    remove_proc_entry(SECMON_PROC_NAME, NULL);
    pr_info("secmon: unloaded\n");
}

module_init(secmon_init);
module_exit(secmon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maksim Plotnikov");
MODULE_DESCRIPTION("Simple Linux rootkit detector");
