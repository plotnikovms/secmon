#include "checks.h"

#include <linux/seq_file.h>

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#include <asm/special_insns.h>
#include <asm/processor-flags.h>
#endif

void kernel_protection_check(struct seq_file *report)
{
    int suspicious_count = 0;

    seq_puts(report, "Checking kernel write protection...\n");

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
    unsigned long cr0_value;
    bool write_protect_enabled;

    cr0_value = read_cr0();
    write_protect_enabled = (cr0_value & X86_CR0_WP) != 0;

    if (!write_protect_enabled) {
        suspicious_count++;

        seq_puts(
            report,
            "SUSPICIOUS: CR0.WP is disabled, kernel read-only pages may be writable\n"
        );
    }
#else
    seq_puts(report, "INFO: CR0.WP check is available only on x86/x86_64\n");
#endif

    if (suspicious_count == 0) {
        seq_puts(report, "OK: no suspicious kernel protection signs found\n");
    } else {
        seq_printf(
            report,
            "WARNING: suspicious kernel protection signs found: %d\n",
            suspicious_count
        );
    }
}
