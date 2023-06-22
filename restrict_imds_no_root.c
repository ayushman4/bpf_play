#include "restrict_imds_no_root.skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stdout, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static volatile sig_atomic_t stop;

void sig_int(int signo)
{
    stop = signo;
}

int bpf_trace_pipe(int out)
{
    // todo > find mount -> use mnt/trace_pipe (making strong assumptions atm)

    int inp = STDERR_FILENO;
    inp = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
    if (inp < 0)
    {
        return inp;
    }

    while (!stop)
    {
        static char buf[4096];
        ssize_t ret;

        ret = read(inp, buf, sizeof(buf));
        if (ret > 0 && write(out, buf, ret) == ret)
        {
            continue;
        }
    }

    close(inp);
    return 0;
}

int main(int argc, char **argv)
{
    struct restrict_imds_no_root_bpf *skel = NULL;
    int err = 0;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Can't handle Ctrl-C: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Open load and verify BPF application */
    skel = restrict_imds_no_root_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    fprintf(stdout, "BPF skeleton ok\n");

    /* Attach tracepoint handler */
    err = restrict_imds_no_root_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    err = bpf_trace_pipe(STDERR_FILENO);

cleanup:
    restrict_imds_no_root_bpf__destroy(skel);
    return -err;
}
