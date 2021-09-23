#include <linux/errno.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

BPF_RING_BUF(audit_events, AUDIT_EVENTS_RING_SIZE);
BPF_HASH(b_config, u32, struct bouheki_config, 256);

BPF_HASH(allowed_commands, struct allowed_command_key, u32, 256);
BPF_HASH(deny_commands, struct deny_command_key, u32, 256);

BPF_HASH(allowed_uids, struct allowed_uid_key, u32, 256);
BPF_HASH(deny_uids, struct deny_uid_key, u32, 256);

BPF_HASH(allowed_gids, struct allowed_gid_key, u32, 256);
BPF_HASH(deny_gids, struct deny_gid_key, u32, 256);

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct ip4_trie_key);
	__type(value, char);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} denylist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct ip4_trie_key);
	__type(value, char);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist SEC(".maps");

static inline void report_ip4_block(void *ctx, u64 cg, enum action action, enum network_op op, struct socket *sock, const struct sockaddr_in *daddr) {
	struct audit_event_blocked_ipv4 ev;

	struct task_struct *current_task;
	struct uts_namespace *uts_ns;
	struct nsproxy *nsproxy;
	current_task = (struct task_struct *)bpf_get_current_task();

	bpf_core_read(&nsproxy, sizeof(nsproxy), &current_task->nsproxy);
	bpf_core_read(&uts_ns, sizeof(uts_ns), &nsproxy->uts_ns);

	__builtin_memset(&ev, 0, sizeof(ev));
	bpf_core_read(&ev.hdr.nodename, sizeof(ev.hdr.nodename), &uts_ns->name.nodename);

	ev.hdr.cgroup = cg;
	ev.hdr.pid = (u32) (bpf_get_current_pid_tgid() >> 32);
	ev.hdr.type = BLOCKED_IPV4;
	bpf_get_current_comm(&ev.hdr.task, sizeof(ev.hdr.task));

	ev.dport = __builtin_bswap16(daddr->sin_port);
	ev.src = src_addr4(sock);
	ev.dst = BPF_CORE_READ(daddr, sin_addr);
	ev.operation = (u8)op;
	ev.action = (u8)action;

	bpf_ringbuf_output(&audit_events, &ev, sizeof(ev), 0);
}

// TODO: lsm/send_msg
SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
	int allow_connect = -EPERM;
	int allow_command = -EPERM;
	int allow_uid = -EPERM;

	// TODO: support IPv6
	if (address->sa_family != AF_INET)
    		return 0;
	
	u64 cg = bpf_get_current_cgroup_id();

	struct sockaddr_in *inet_addr = (struct sockaddr_in*)address;

	struct ip4_trie_key key = {
    		.prefixlen = 32,
    		.addr = inet_addr->sin_addr
	};

	struct allowed_command_key allowed_command;
	struct deny_command_key deny_command;
	struct allowed_uid_key allowed_uid;
	struct deny_uid_key deny_uid;
	struct allowed_gid_key allowed_gid;
	struct deny_gid_key deny_gid;

	bpf_get_current_comm(&allowed_command.comm, sizeof(allowed_command.comm));
	bpf_get_current_comm(&deny_command.comm, sizeof(deny_command.comm));

	allowed_uid.uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
	deny_uid.uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
	allowed_gid.gid = (unsigned)(bpf_get_current_uid_gid() >> 32);
	deny_gid.gid = (unsigned)(bpf_get_current_uid_gid() >> 32);

	u32 index = 0;

	struct bouheki_config *c = (struct bouheki_config *)bpf_map_lookup_elem(&b_config, &index);

	int has_allow_command = 0;
	int has_allow_uid = 0;

	if (c && c->has_allow_command) {
		has_allow_command = c->has_allow_command;
	}
	if (c && c->has_allow_uid) {
		has_allow_uid = c->has_allow_uid;
	}


	if (c && c->target == TARGET_CONTAINER) {
		if (!is_container()) {
			return 0;
		}
	}

	if (bpf_map_lookup_elem(&allowlist, &key)) {
		allow_connect = 0;
	}

	if (bpf_map_lookup_elem(&allowed_uids, &allowed_uid) || has_allow_uid == 0) {
		allow_uid = 0;
	}

	if (bpf_map_lookup_elem(&allowed_commands, &allowed_command) || has_allow_command == 0) {
		allow_command = 0;
	}

	if (bpf_map_lookup_elem(&deny_commands, &deny_command)) {
		allow_command = -EPERM;
	}

	if (bpf_map_lookup_elem(&deny_uids, &deny_uid)) {
		allow_uid = -EPERM;
	}

	if (bpf_map_lookup_elem(&denylist, &key)) {
		allow_connect = -EPERM;
	}

	if (bpf_map_lookup_elem(&denylist, &key) && bpf_map_lookup_elem(&allowed_commands, &allowed_command)) {
		allow_connect = 0;
	}

	if (bpf_map_lookup_elem(&denylist, &key) && bpf_map_lookup_elem(&allowed_uids, &allowed_uid)) {
		allow_connect = 0;
	}

	int can_access = -EPERM;
	if (allow_connect == 0 && allow_uid == 0 && allow_command == 0) {
		can_access = 0;
	}

	if (can_access != 0 && c && c->mode == MODE_BLOCK) {
		report_ip4_block((void*) ctx, cg, ACTION_BLOCK, OP_CONNECT, sock, inet_addr);
	}

	if (c && c->mode == MODE_MONITOR) {
		report_ip4_block((void*) ctx, cg, ACTION_MONITOR, OP_CONNECT, sock, inet_addr);
		return 0;
	}

	return can_access;
}