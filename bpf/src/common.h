#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include "bpf_helpers.h"

/* 
max file path lenght
in ebpf cannot be used malloc
defined buffer now 
*/

#define MAX_FILENAME_LEN 256
/* 
Event types for classification in the user space.
Rust agent will use this for serialization.
*/
enum event_type{
    EVENT_FILE_OPEN = 1,
    EVENT_NETWORK_CONNECT = 2,
};
/*
The event structure that will be copied from the Core to the Userspace.
__attribute__((packed)) is important so that the compiler does not add extra padding,
otherwise Rust will not be able to read the structure correctly.
*/
struct event{
    __u32 pid;              // process id
    __u32 uid;              // user id
    __u64 timestamp;        // (nanosecs)
    enum event_type type;   // event type
    char filename[MAX_FILENAME_LEN];
    __u32 dest_ip;          // desination ip
    __u16 dest_port;        // destination port
};
/* 
Declare the map (map) as extern.
The actual definition of the map will be in main.c.
This allows handlers.c to see the map without duplicating the definition.
 */
extern struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entires, 256 * 1024); // 256kb buffer
} events_ringbuf SEC(".maps");

#endif __COMMON_H