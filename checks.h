#ifndef CHECKS_H
#define CHECKS_H

#include <linux/seq_file.h>

void hidden_process_check(struct seq_file *report);
void module_check(struct seq_file *report);
void syscall_check(struct seq_file *report);
void autoload_check(struct seq_file *report);
void network_check(struct seq_file *report);

#endif
