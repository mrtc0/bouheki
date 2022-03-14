#include "common_structs.h"
#include "vmlinux.h"
#include <linux/errno.h>

#define NAME_MAX 255

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct file_path {
    unsigned char path[NAME_MAX];
};

struct callback_ctx {
    unsigned char *source_path;
    bool found;
};

struct mount_audit_event {
    u64 cgroup;
    u32 pid;
    int ret;
    // char nodename[NEW_UTS_LEN + 1];
    char task[TASK_COMM_LEN];
    char parent_task[TASK_COMM_LEN];
    unsigned char source_path[NAME_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} mount_events SEC(".maps");
BPF_HASH(mount_denied_source_list, u32, struct file_path, 256);

static u64 cb_check_path(struct bpf_map *map, u32 *key,
                            struct file_path *map_path, struct callback_ctx *ctx)
{
    size_t size = strlen(map_path->path, NAME_MAX);
    bpf_printk("mount! map_path=%s, source_path=%s", map_path->path, ctx->source_path);
    if (strcmp(map_path->path, ctx->source_path, size) == 0) {
        ctx->found = 1;
    }

    return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(restricted_mount, const char *dev_name, const struct path *path,
                const char *type, unsigned long flags, void *data, int ret_prev)
{
    int ret = -1;
    struct task_struct *current_task;
    struct mount_audit_event event = {};

    current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);

    event.cgroup = bpf_get_current_cgroup_id();
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&event.task, sizeof(event.task));
    bpf_probe_read_kernel_str(&event.parent_task, sizeof(event.parent_task), &parent_task->comm);
    bpf_probe_read_kernel_str(&event.source_path, sizeof(event.source_path), dev_name);

    struct callback_ctx cb = { .source_path = event.source_path, .found = false };
    bpf_for_each_map_elem(&mount_denied_source_list, cb_check_path, &cb, 0);
    if (cb.found) {
        bpf_printk("Mount Denied: %s", cb.source_path);
        ret = -EPERM;
        goto out;
    }

    ret = 0;

out:
    return ret;
}