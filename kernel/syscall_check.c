#include "checks.h"

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include <asm/unistd.h>

#ifdef CONFIG_X86_64
#include <asm/msr.h>
#endif

static unsigned long syscall_table_addr;
static unsigned long kernel_text_start;
static unsigned long kernel_text_end;

module_param(syscall_table_addr, ulong, 0444);
MODULE_PARM_DESC(syscall_table_addr, "Address of sys_call_table");

module_param(kernel_text_start, ulong, 0444);
MODULE_PARM_DESC(kernel_text_start, "Address of _stext");

module_param(kernel_text_end, ulong, 0444);
MODULE_PARM_DESC(kernel_text_end, "Address of _etext");

static bool read_kernel_ulong(unsigned long address, unsigned long *value)
{
    return copy_from_kernel_nofault(
        value,
        (void *)address,
        sizeof(*value)
    ) == 0;
}

static bool kernel_text_range_is_available(void)
{
    return kernel_text_start != 0 &&
           kernel_text_end != 0 &&
           kernel_text_start < kernel_text_end;
}

static bool address_is_inside_kernel_text(unsigned long address)
{
    if (!kernel_text_range_is_available()) {
        return false;
    }

    return address >= kernel_text_start && address < kernel_text_end;
}

static void check_kernel_text_address(
    struct seq_file *report,
    const char *name,
    unsigned long address,
    int *suspicious_count
)
{
    seq_printf(report, "%s address: %px\n", name, (void *)address);

    if (address == 0) {
        ++(*suspicious_count);

        seq_printf(
            report,
            "SUSPICIOUS: %s address is zero\n",
            name
        );

        return;
    }

    if (!kernel_text_range_is_available()) {
        seq_printf(
            report,
            "INFO: kernel text range is not available, cannot validate %s\n",
            name
        );

        return;
    }

    if (!address_is_inside_kernel_text(address)) {
        ++(*suspicious_count);

        seq_printf(
            report,
            "SUSPICIOUS: %s address is outside kernel text range\n",
            name
        );

        return;
    }

    seq_printf(report, "OK: %s address is inside kernel text range\n", name);
}

static void check_syscall_entry_points(struct seq_file *report, int *suspicious_count)
{
    seq_puts(report, "Checking syscall entry points...\n");

#ifdef CONFIG_X86_64
    {
        unsigned long lstar_address;
        unsigned long cstar_address;

        rdmsrl(MSR_LSTAR, lstar_address);
        rdmsrl(MSR_CSTAR, cstar_address);

        check_kernel_text_address(
            report,
            "MSR_LSTAR syscall entry",
            lstar_address,
            suspicious_count
        );

        check_kernel_text_address(
            report,
            "MSR_CSTAR compat syscall entry",
            cstar_address,
            suspicious_count
        );
    }
#else
    seq_puts(report, "INFO: x86_64 MSR syscall check is not available on this architecture\n");
#endif
}

static void check_syscall_handler_address(
    struct seq_file *report,
    int syscall_number,
    unsigned long handler_address,
    int *suspicious_count
)
{
    if (handler_address == 0) {
        ++(*suspicious_count);

        seq_printf(
            report,
            "SUSPICIOUS: syscall[%d] handler is NULL\n",
            syscall_number
        );

        return;
    }

    if (!kernel_text_range_is_available()) {
        return;
    }

    if (address_is_inside_kernel_text(handler_address)) {
        return;
    }

    ++(*suspicious_count);

    seq_printf(
        report,
        "SUSPICIOUS: syscall[%d] handler points outside kernel text range: %px\n",
        syscall_number,
        (void *)handler_address
    );
}

static void check_syscall_table(struct seq_file *report, int *suspicious_count)
{
    int syscall_number;
    int unreadable_count = 0;

    seq_puts(report, "Checking sys_call_table entries...\n");

    if (syscall_table_addr == 0) {
        seq_puts(report, "INFO: syscall_table_addr is not set\n");
        seq_puts(report, "INFO: syscall table check skipped\n");
        return;
    }

    if (!kernel_text_range_is_available()) {
        seq_puts(report, "INFO: kernel text range is not set\n");
        seq_puts(report, "INFO: syscall handler address validation will be limited\n");
    } else {
        seq_printf(
            report,
            "kernel text range: [%px, %px)\n",
            (void *)kernel_text_start,
            (void *)kernel_text_end
        );
    }

    seq_printf(
        report,
        "sys_call_table address: %px\n",
        (void *)syscall_table_addr
    );

    seq_printf(report, "syscall count: %d\n", __NR_syscalls);

    for (syscall_number = 0; syscall_number < __NR_syscalls; ++syscall_number) {
        unsigned long table_entry_address;
        unsigned long handler_address;

        table_entry_address =
            syscall_table_addr + syscall_number * sizeof(unsigned long);

        if (!read_kernel_ulong(table_entry_address, &handler_address)) {
            ++unreadable_count;

            seq_printf(
                report,
                "SUSPICIOUS: syscall[%d] table entry is unreadable at %px\n",
                syscall_number,
                (void *)table_entry_address
            );

            continue;
        }

        check_syscall_handler_address(
            report,
            syscall_number,
            handler_address,
            suspicious_count
        );
    }

    if (unreadable_count > 0) {
        seq_printf(
            report,
            "WARNING: unreadable syscall table entries: %d\n",
            unreadable_count
        );
    }
}

void syscall_check(struct seq_file *report)
{
    int suspicious_count = 0;

    check_syscall_entry_points(report, &suspicious_count);
    seq_puts(report, "\n");

    check_syscall_table(report, &suspicious_count);

    if (suspicious_count == 0) {
        seq_puts(report, "OK: no suspicious syscall signs found\n");
    } else {
        seq_printf(
            report,
            "WARNING: suspicious syscall signs found: %d\n",
            suspicious_count
        );
    }
}
