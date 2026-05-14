#include "checks.h"

#include <linux/module.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/string.h>


static bool module_name_is_valid(const char *name) {
    if (!name || name[0] == '\0') {
        return false;
    }

    for (int index = 0; index < MODULE_NAME_LEN && name[index] != '\0'; ++index) {
        char symbol = name[index];

        if (!((symbol >= 'a' && symbol <= 'z') ||
              (symbol >= 'A' && symbol <= 'Z') ||
              (symbol >= '0' && symbol <= '9') ||
              symbol == '_' ||
              symbol == '-')) {
            return false;
        }
    }

    return true;
}

static bool sys_module_entry_exists(const char *module_name) {
    char path_name[MODULE_NAME_LEN];
    struct path path;
    int result;

    snprintf(path_name, sizeof(path_name), "/sys/module/%s", module_name);

    result = kern_path(path_name, LOOKUP_DIRECTORY, &path);
    if (result == 0) {
        path_put(&path);
        return true;
    }

    return false;
}

static const char *module_state_to_string(enum module_state state) {
    switch (state) {
    case MODULE_STATE_LIVE:
        return "LIVE";

    case MODULE_STATE_COMING:
        return "COMING";

    case MODULE_STATE_GOING:
        return "GOING";

    case MODULE_STATE_UNFORMED:
        return "UNFORMED";

    default:
        return "UNKNOWN";
    }
}

void module_check(struct seq_file *report) {
    struct module *module;
    int visible_module_count = 0;
    int suspicious_count = 0;
    int skipped_entries = 0;

    seq_puts(report, "Scanning kernel module list...\n");

    rcu_read_lock();

    list_for_each_entry_rcu(module, &THIS_MODULE->list, list) {
        char module_name[MODULE_NAME_LEN];
        enum module_state state;
        bool has_sysfs_entry;

        strscpy(module_name, module->name, sizeof(module_name));

        if (!module_name_is_valid(module_name)) {
            skipped_entries++;
            continue;
        }

        state = READ_ONCE(module->state);
        has_sysfs_entry = sys_module_entry_exists(module_name);

        ++visible_module_count;

        if (!has_sysfs_entry) {
            ++suspicious_count;

            seq_printf(
                report,
                "SUSPICIOUS: module=%s exists in kernel module list, but /sys/module/%s is missing\n",
                module_name,
                module_name
            );
        }

        if (state == MODULE_STATE_UNFORMED) {
            ++suspicious_count;

            seq_printf(
                report,
                "SUSPICIOUS: module=%s has unusual state=%s\n",
                module_name,
                module_state_to_string(state)
            );
        }
    }

    rcu_read_unlock();

    seq_printf(report, "Visible modules in kernel module list: %d\n", visible_module_count);

    if (skipped_entries > 1) {
        seq_printf(report, "Skipped list entries: %d\n", skipped_entries);
    }

    if (suspicious_count == 0) {
        seq_puts(report, "OK: no suspicious module inconsistencies found\n");
    } else {
        seq_printf(report, "WARNING: suspicious module inconsistencies found: %d\n", suspicious_count);
    }
}
