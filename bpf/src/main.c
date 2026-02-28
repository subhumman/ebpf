#include "common.h"
#include "bpf_core_read.h"
/*
license. without gpl helper funcs will be ignored
check linux secure
*/
char LICENSE[] SEC("license") = "GPL";
/*
events map
BPF_MAP_TYPE_RINGBUFF
*/
event_ringbuf;

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entires, 1);
} config_map SEC(".maps");

#include "handlers.c"