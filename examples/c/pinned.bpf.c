// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Probe entry to kernel function 'do_unlinkat'
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat_entry, int dfd, struct filename *name)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("ENTER do_unlinkat: pid = %d, pathname = %s\n", pid, name->name);
    return 0;
}

// Probe exit to kernel function 'do_unlinkat'
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("EXIT do_unlinkat: pid = %d, pathname = %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}

// Probe entry to syscall 'unlinkat'
SEC("fentry/__x64_sys_unlinkat")
int BPF_PROG(unlinkat_syscall_entry, const struct pt_regs *regs)
{   pid_t pid;
    char pathname[100];

    // These are easy to get via bpf helpers
    pid = bpf_get_current_pid_tgid() >> 32;

    // To get syscall params, we need to extract them from pt_regs
    // Unlink syscall:
    //    int unlinkat(int dirfd, const char *pathname, int flags);
    // So we use 'PT_REGS_PARM2' to get the second paramater, i.e. 'pathname'
    bpf_probe_read(&pathname, sizeof(pathname), (void*)PT_REGS_PARM2(regs));

    bpf_printk("ENTER unlinkat syscall: pid = %d, pathname = %s\n", pid, pathname);

    return 0;
}

// Probe exit to syscall 'unlinkat'
SEC("fexit/__x64_sys_unlinkat")
int BPF_PROG(unlinkat_syscall_exit, const struct pt_regs *regs, long ret)
{   pid_t pid;
    char pathname[100];

    // These are easy to get via bpf helpers
    pid = bpf_get_current_pid_tgid() >> 32;

    // To get syscall params, we need to extract them from pt_regs
    // Unlink syscall:
    //    int unlinkat(int dirfd, const char *pathname, int flags);
    // So we use 'PT_REGS_PARM2' to get the second paramater, i.e. 'pathname'
    bpf_probe_read(&pathname, sizeof(pathname), (void*)PT_REGS_PARM2(regs));

    bpf_printk("EXIT unlinkat syscall: pid = %d, pathname = %s, ret = %ld\n", pid, pathname, ret);

    return 0;
}
