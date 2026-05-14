#include "checks.h"

#include <linux/bitmap.h>
#include <linux/gfp.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/threads.h>

static bool proc_pid_exists(int pid) {
    char path_name[32];
    struct path path;
    int result;

    snprintf(path_name, sizeof(path_name), "/proc/%d", pid);

    result = kern_path(path_name, LOOKUP_DIRECTORY, &path);
    if (result == 0) {
        path_put(&path);
        return true;
    }

    return false;
}

void hidden_process_check(struct seq_file *report) {
    unsigned long *task_list_pids;
    unsigned long *pid_table_pids;
    unsigned long *proc_pids;

    struct task_struct *process;
    struct task_struct *thread;

    int pid;
    int task_list_count = 0;
    int pid_table_count = 0;
    int proc_count = 0;

    int suspicious_count = 0;

    task_list_pids = bitmap_zalloc(PID_MAX_LIMIT + 1, GFP_KERNEL);
    if (!task_list_pids) {
        seq_puts(report, "ERROR: failed to allocate task list PID bitmap\n");
        return;
    }

    pid_table_pids = bitmap_zalloc(PID_MAX_LIMIT + 1, GFP_KERNEL);
    if (!pid_table_pids) {
        seq_puts(report, "ERROR: failed to allocate PID table bitmap\n");
        bitmap_free(task_list_pids);
        return;
    }

    proc_pids = bitmap_zalloc(PID_MAX_LIMIT + 1, GFP_KERNEL);
    if (!proc_pids) {
        seq_puts(report, "ERROR: failed to allocate /proc PID bitmap\n");
        bitmap_free(pid_table_pids);
        bitmap_free(task_list_pids);
        return;
    }

    rcu_read_lock();

    for_each_process_thread(process, thread) {
        pid = task_pid_nr(thread);

        if (pid > 0 && pid <= PID_MAX_LIMIT) {
            set_bit(pid, task_list_pids);
            task_list_count++;
        }
    }

    rcu_read_unlock();

    for (pid = 1; pid <= PID_MAX_LIMIT; pid++) {
        struct pid *pid_struct;
        struct task_struct *task;

        pid_struct = find_get_pid(pid);
        if (pid_struct) {
            rcu_read_lock();

            task = pid_task(pid_struct, PIDTYPE_PID);

            if (task) {
                set_bit(pid, pid_table_pids);
                pid_table_count++;
            }

            rcu_read_unlock();

            put_pid(pid_struct);
        }

        if (proc_pid_exists(pid)) {
            set_bit(pid, proc_pids);
            proc_count++;
        }
    }

    seq_printf(report, "Processes from task list: %d\n", task_list_count);
    seq_printf(report, "Processes from PID table: %d\n", pid_table_count);
    seq_printf(report, "Processes from /proc: %d\n", proc_count);

    seq_puts(report, "Comparing process sources...\n");

    for (pid = 1; pid <= PID_MAX_LIMIT; pid++) {
        bool in_task_list = test_bit(pid, task_list_pids);
        bool in_pid_table = test_bit(pid, pid_table_pids);
        bool in_proc = test_bit(pid, proc_pids);

        if (in_task_list == in_pid_table && in_pid_table == in_proc) {
            continue;
        }

        suspicious_count++;

        seq_printf(
            report,
            "SUSPICIOUS: PID %d mismatch: task_list=%d, pid_table=%d, proc=%d\n",
            pid,
            in_task_list ? 1 : 0,
            in_pid_table ? 1 : 0,
            in_proc ? 1 : 0
        );

        if (!in_proc && in_task_list && in_pid_table) {
            seq_puts(report, "  reason: process exists in kernel, but is hidden from /proc\n");
        } else if (!in_task_list && in_pid_table) {
            seq_puts(report, "  reason: process exists in PID table, but is missing from task list\n");
        } else if (in_proc && !in_pid_table) {
            seq_puts(report, "  reason: /proc entry exists, but PID table has no such process\n");
        } else if (in_task_list && !in_pid_table) {
            seq_puts(report, "  reason: process exists in task list, but is missing from PID table\n");
        } else {
            seq_puts(report, "  reason: inconsistent process visibility\n");
        }

    }

    if (suspicious_count == 0) {
        seq_puts(report, "OK: no hidden process signs found\n");
    } else {
        seq_printf(report, "WARNING: suspicious PID mismatches found: %d\n", suspicious_count);
        seq_puts(report, "NOTE: process creation/exit races are possible, rerun the check to confirm\n");
    }

    bitmap_free(proc_pids);
    bitmap_free(pid_table_pids);
    bitmap_free(task_list_pids);
}
