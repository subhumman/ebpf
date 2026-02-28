#include "common.h"

/*
Helper function to send event to Ring Buffer.
Separated to avoid duplicating code in every handler.
 */
static __always_inline void send_event(struct event *e) {
    /*
    bpf_ringbuf_output copies data from eBPF stack to Ringbuf map.
    BPF_RINGBUF_BUSY — if buffer is full, do not block kernel, drop event.
    This is critical for system performance.
     */
    bpf_ringbuf_output(&events_ringbuf, e, sizeof(*e), 0);
}

/* Handler for openat syscall (file opening). */
/* SEC tells the verifier what type of program we are writing. */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event e = {};
    
    /* Get PID and TID (Thread ID) */
    /* Upper 32 bits - PID, lower 32 bits - TID */
    __u64 id = bpf_get_current_pid_tgid();
    e.pid = id >> 32;
    
    /* Get user UID */
    e.uid = bpf_get_current_uid_gid();
    
    /* Time in nanoseconds */
    e.timestamp = bpf_ktime_get_ns();
    e.type = EVENT_FILE_OPEN;

    /*
    MOST IMPORTANT PART TO UNDERSTAND:
    ctx->args[1] is a pointer to filename string in user memory.
    We CANNOT just assign e.filename = (char*)ctx->args[1].
    Kernel and User have different address spaces.
    Need to use bpf_probe_read_user_str for safe copying.
     */
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename);

    /* Filter: can ignore system processes (pid < 100) */
    if (e.pid < 100) {
        return 0;
    }

    send_event(&e);
    return 0;
}

/*
Handler for connect syscall (network connections).
Here it is harder: need to read sockaddr structure from user memory.
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event e = {};
    __u64 id = bpf_get_current_pid_tgid();
    e.pid = id >> 32;
    e.uid = bpf_get_current_uid_gid();
    e.timestamp = bpf_ktime_get_ns();
    e.type = EVENT_NETWORK_CONNECT;

    /* args[1] is a pointer to struct sockaddr * */
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    
    /*
    Pointer safety check.
    If pointer is null or invalid, bpf_probe_read_user will return error.
    We simplify example, but in production need to check return code.
     */
    
    /* Read address family (AF_INET = 2) */
    short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    /* Process only IPv4 for simplicity */
    if (family == 2) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        
        /* Read port (network byte order, need to convert in userspace or here) */
        bpf_probe_read_user(&e.dest_port, sizeof(e.dest_port), &addr_in->sin_port);
        
        /* Read IP address */
        bpf_probe_read_user(&e.dest_ip, sizeof(e.dest_ip), &addr_in->sin_addr.s_addr);
        
        send_event(&e);
    }

    return 0;
}