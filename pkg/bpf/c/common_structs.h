#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ALLOW_ACCESS 0
#define AUDIT_EVENTS_RING_SIZE (4 * 4096)
#define TASK_COMM_LEN 16
#define NEW_UTS_LEN 64

#define BPF_RING_BUF(name, size)        \
  struct                                \
  {                                     \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, size);          \
  } name SEC(".maps")

#define BPF_HASH(name, key_type, val_type, size) \
  struct                                         \
  {                                              \
    __uint(type, BPF_MAP_TYPE_HASH);             \
    __uint(max_entries, size);                   \
    __type(key, key_type);                       \
    __type(value, val_type);                     \
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

enum lsm_hook_point
{
  CONNECT,
  SENDMSG // Not implemented yet.
};

static inline int _is_host_mntns()
{
  struct task_struct *current_task;
  struct nsproxy *nsproxy;
  struct mnt_namespace *mnt_ns;
  unsigned int inum;

  current_task = (struct task_struct *)bpf_get_current_task();

  BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
  BPF_CORE_READ_INTO(&mnt_ns, nsproxy, mnt_ns);
  BPF_CORE_READ_INTO(&inum, mnt_ns, ns.inum);
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

static inline int strcmp(const unsigned char *a, const unsigned char *b, size_t len)
{
  unsigned char c1, c2;
  size_t i;

  for (i=0; i<len; i++) {
    c1 = (unsigned char)a[i];
    c2 = (unsigned char)b[i];

    if (c1 != c2 || c1 == '\0' || c2 == '\0') {
      return 1;
    }
  }

  return 0;
}

static __always_inline int strlen(const unsigned char *s, size_t max_len)
{
	size_t i;

	for (i = 0; i < max_len; i++) {
		if (s[i] == '\0')
			return i;
	}

	return i;
}
