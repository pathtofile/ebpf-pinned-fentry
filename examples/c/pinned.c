// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "pinned.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

// Paths to pin
const char* pin_prog_01 = "/sys/fs/bpf/pinned/do_unlinkat_entry_prog";
const char* pin_prog_02 = "/sys/fs/bpf/pinned/do_unlinkat_exit_prog";
const char* pin_prog_03 = "/sys/fs/bpf/pinned/unlink_syscall_entry_prog";
const char* pin_prog_04 = "/sys/fs/bpf/pinned/unlink_syscall_exit_prog";

const char* pin_link_01 = "/sys/fs/bpf/pinned/do_unlinkat_entry_link";
const char* pin_link_02 = "/sys/fs/bpf/pinned/do_unlinkat_exit_link";
const char* pin_link_03 = "/sys/fs/bpf/pinned/unlinkat_syscall_entry_link";
const char* pin_link_04 = "/sys/fs/bpf/pinned/unlinkat_syscall_exit_link";

int remove_file_if_exists(const char *path)
{
    int err = 0;

    if (access(path, F_OK) == 0) {
        err = remove(path);
        if (err != 0) {
            fprintf(stdout, "could not remove old pin: %d", err);
            return err;
        }
    }

    return err;
}

int cleanup_pins() {
    if (remove_file_if_exists(pin_prog_01))
        return 1;
    if (remove_file_if_exists(pin_prog_02))
        return 1;
    if (remove_file_if_exists(pin_prog_03))
        return 1;
    if (remove_file_if_exists(pin_prog_04))
        return 1;
    if (remove_file_if_exists(pin_link_01))
        return 1;
    if (remove_file_if_exists(pin_link_02))
        return 1;
    if (remove_file_if_exists(pin_link_03))
        return 1;
    if (remove_file_if_exists(pin_link_04))
        return 1;
    return 0;
}

int pin_program(struct bpf_program *prog, const char* path)
{
    int err;
    err = bpf_program__pin(prog, path);
        if (err) {
            fprintf(stdout, "could not pin %s: %d\n", path, err);
            return err;
        }
    return err;
}

int pin_link(struct bpf_link *link, const char* path)
{
    int err;
    err = bpf_link__pin(link, path);
        if (err) {
            fprintf(stdout, "could not pin %s: %d\n", path, err);
            return err;
        }
    return err;
}

int main(int argc, char **argv)
{
    struct pinned_bpf *skel;
    int err;

    // Set up libbpf errors and debug info callback 
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything 
    bump_memlock_rlimit();

    // Check bpf filesystem is mounted
    if (access("/sys/fs/bpf", F_OK) != 0) {
        fprintf(stderr, "Make sure bpf filesystem mounted by running:\n");
        fprintf(stderr, "    sudo mount bpffs -t bpf /sys/fs/bpf\n");
        return 1;
    }

    // Cleanup any previous run
    if (cleanup_pins())
        return 1;

    // Open load and verify BPF application 
    skel = pinned_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Attach tracepoint handler 
    err = pinned_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Pin programs
    err = pin_program(skel->progs.do_unlinkat_entry, pin_prog_01);
    if (err)
        goto cleanup;
    err = pin_program(skel->progs.do_unlinkat_exit, pin_prog_02);
    if (err)
        goto cleanup;
    err = pin_program(skel->progs.unlinkat_syscall_entry, pin_prog_03);
    if (err)
        goto cleanup;
    err = pin_program(skel->progs.unlinkat_syscall_exit, pin_prog_04);
    if (err)
        goto cleanup;

    // Pin Links as well
    err = pin_link(skel->links.do_unlinkat_entry, pin_link_01);
    if (err)
        goto cleanup;
    err = pin_link(skel->links.do_unlinkat_exit, pin_link_02);
    if (err)
        goto cleanup;
    err = pin_link(skel->links.unlinkat_syscall_entry, pin_link_03);
    if (err)
        goto cleanup;
    err = pin_link(skel->links.unlinkat_syscall_exit, pin_link_04);
    if (err)
        goto cleanup;

    printf("----------------------------------\n");
    printf("----------------------------------\n");
    printf("Successfully started!\n");
    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");
    printf("Files are pinned in folder /sys/fs/bpf/pinned\n");
    printf("To stop programs, run 'sudo rm -r /sys/fs/bpf/pinned'\n");

cleanup:
    pinned_bpf__destroy(skel);
    if (err != 0) {
        cleanup_pins();
    }

    return -err;
}
