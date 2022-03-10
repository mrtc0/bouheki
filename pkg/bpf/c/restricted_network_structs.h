#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

enum audit_event_type {
  BLOCKED_IPV4,
  BLOCKED_IPV6
};

enum action
{
  ACTION_MONITOR,
  ACTION_BLOCK
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
struct allowed_command_key
{
  char comm[TASK_COMM_LEN];
};

struct denied_command_key
{
  char comm[TASK_COMM_LEN];
};

struct allowed_uid_key
{
  u32 uid;
};

struct denied_uid_key
{
  u32 uid;
};

struct allowed_gid_key
{
  u32 gid;
};

struct denied_gid_key
{
  u32 gid;
};

struct audit_event_ipv4
{
  struct audit_event_header hdr;
  struct in_addr src;
  struct in_addr dst;
  u16 dport;
  u8 operation;
  u8 action;
  u8 sock_type;
};

struct audit_event_ipv6
{
  struct audit_event_header hdr;
  struct in6_addr src;
  struct in6_addr dst;
  u16 dport;
  u8 operation;
  u8 action;
  u8 sock_type;
};

struct ipv4_trie_key
{
  u32 prefixlen;
  struct in_addr addr;
};

struct ipv6_trie_key
{
  u32 prefixlen;
  struct in6_addr addr;
};

union ip_trie_key {
  struct ipv4_trie_key v4;
  struct ipv6_trie_key v6;
};


static inline struct in_addr src_addr4(const struct socket *sock)
{
  struct in_addr addr;
  __builtin_memset(&addr, 0, sizeof(addr));

  addr.s_addr = BPF_CORE_READ(sock, sk, __sk_common.skc_rcv_saddr);
  return addr;
}

static inline struct in6_addr src_addr6(const struct socket *sock)
{
  struct in6_addr addr;
  __builtin_memset(&addr, 0, sizeof(addr));

  addr = BPF_CORE_READ(sock, sk, __sk_common.skc_v6_rcv_saddr);
  return addr;
}