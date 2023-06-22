#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2
#define CAP_SYS_ADMIN 21
#define CAP_TO_INDEX(x)     ((x) >> 5)        
#define CAP_TO_MASK(x)      (1U << ((x) & 31))


const unsigned long blockme = 4272553641; // 254.169.254.169
// Blocks IPV4 calls to IMDS IP and blocks all IPv4 calls unless you are root
// curls -vvv https://google.com will fail unless you are root and any calls to 169.254.169.254 will fail

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{   
    struct task_struct *task;
    kernel_cap_t caps;
    task = bpf_get_current_task_btf();
    caps = BPF_CORE_READ(task,cred,cap_effective);
    if (ret != 0)
    {
        return ret;
    }
    if (address->sa_family != AF_INET)
    {
        return 0;
    }
    
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    unsigned long dest = addr->sin_addr.s_addr;
    if (dest == blockme)
    {

        return -EPERM;
    }
    else if (caps.cap[CAP_TO_INDEX(CAP_SYS_ADMIN)] & CAP_TO_MASK(CAP_SYS_ADMIN))
    {
            return 0;
    }

    return -EPERM;
}
