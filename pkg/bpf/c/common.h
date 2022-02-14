#include <linux/errno.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ALLOW_ACCESS 0

#define AF_INET 2
#define AUDIT_EVENTS_RING_SIZE (4 * 4096)
#define TASK_COMM_LEN 16
#define NEW_UTS_LEN 64
#define BPF_RING_BUF(name, size)        \
  struct                                \
  {                                     \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, size);          \
  } name SEC(".maps")

enum mode
{
  MODE_MONITOR,
  MODE_BLOCK
};

enum target
{
  TARGET_HOST,
  TARGET_CONTAINER
};

#define BPF_HASH(name, key_type, val_type, size) \
  struct                                         \
  {                                              \
    __uint(type, BPF_MAP_TYPE_HASH);             \
    __uint(max_entries, size);                   \
    __type(key, key_type);                       \
    __type(value, val_type);                     \
  } name SEC(".maps")

enum network_op
{
  OP_CONNECT,
  OP_SENDMSG
};

enum action
{
  ACTION_MONITOR,
  ACTION_BLOCK
};

enum audit_event_type
{
  BLOCKED_IPV4,
  BLOCKED_IPV6
};

struct audit_event_header
{
  u64 cgroup;
  u32 pid;
  enum audit_event_type type;
  char nodename[NEW_UTS_LEN + 1];
  char task[TASK_COMM_LEN];
  char parent_task[TASK_COMM_LEN];
};

struct audit_event_blocked_ipv4
{
  struct audit_event_header hdr;
  struct in_addr src;
  struct in_addr dst;
  u16 dport;
  u8 operation;
  u8 action;
  u8 sock_type;
};

struct bouheki_config
{
  enum mode mode;
  enum target target;
  int has_allow_command;
  int has_allow_uid;
};

struct ip4_trie_key
{
  u32 prefixlen;
  struct in_addr addr;
};

struct allowed_command_key
{
  char comm[TASK_COMM_LEN];
};

struct deny_command_key
{
  char comm[TASK_COMM_LEN];
};

struct allowed_uid_key
{
  u32 uid;
};

struct deny_uid_key
{
  u32 uid;
};

struct allowed_gid_key
{
  u32 gid;
};

struct deny_gid_key
{
  u32 gid;
};

static inline struct in_addr src_addr4(const struct socket *sock)
{
  struct in_addr addr;
  __builtin_memset(&addr, 0, sizeof(addr));

  addr.s_addr = BPF_CORE_READ(sock, sk, __sk_common.skc_rcv_saddr);
  return addr;
}

static inline int _is_host_mntns()
{
  struct task_struct *current_task;
  struct nsproxy *nsproxy;
  struct mnt_namespace *mnt_ns;
  unsigned int inum;

  current_task = (struct task_struct *)bpf_get_current_task();

  bpf_core_read(&nsproxy, sizeof(nsproxy), &current_task->nsproxy);
  bpf_core_read(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns);
  bpf_core_read(&inum, sizeof(inum), &mnt_ns->ns.inum);
  if (inum == 0xF0000000)
  {
    return true;
  }

  return false;
}

static inline int is_container()
{
  return !_is_host_mntns();
}