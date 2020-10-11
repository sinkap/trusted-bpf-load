// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2024 Google LLC.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE      32
#endif

#define MAX_SIG_SIZE 1024

#define MAGIC_SIZE 8
#define SIZEOF_STRUCT_FSVERITY_DIGEST 4  /* sizeof(struct fsverity_digest) */
char digest[MAGIC_SIZE + SIZEOF_STRUCT_FSVERITY_DIGEST + SHA256_DIGEST_SIZE];

char sig[MAX_SIG_SIZE];
__u32 sig_size;
__u32 user_keyring_serial;

char _license[] SEC("license") = "GPL";

struct bpf_trusted_loader_policy {
	u64 allowed_prog_type_mask;
	int signature_verified;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bpf_trusted_loader_policy);
} policy_map SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(trusted_bpf_inherit_policy, struct task_struct *task)
{
	struct bpf_trusted_loader_policy *parent_policy, *child_policy;

	parent_policy = bpf_task_storage_get(&policy_map,
				       bpf_get_current_task_btf(), 0, 0);
	if (!parent_policy)
		return 0;

	child_policy = bpf_task_storage_get(&policy_map,
				       bpf_get_current_task_btf(), 0,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);

	if (!child_policy)
		return 0;
	child_policy->signature_verified = parent_policy->signature_verified;
	child_policy->allowed_prog_type_mask = parent_policy->allowed_prog_type_mask;
	return 0;
}

static inline int verify_policy(struct bpf_prog *prog)
{
	struct bpf_trusted_loader_policy *policy;

	policy = bpf_task_storage_get(&policy_map,
				       bpf_get_current_task_btf(), 0, 0);
	if (!policy)
		return -EPERM;

	if (policy->signature_verified && policy->allowed_prog_type_mask & prog->type) {
		bpf_printk("program would be would be allowed\n");
			return 0;
	}

	return -EPERM;
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(trusted_bpf_check_policy, struct bpf_prog *prog)
{
	return verify_policy(prog);
}

SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(trusted_bpf_load_policy_at_exec, struct linux_binprm *bprm)
{
	struct bpf_dynptr digest_ptr, sig_ptr;
	struct bpf_key *trusted_keyring;
	struct bpf_trusted_loader_policy *policy;
	int ret;

	/* digest_ptr points to fsverity_digest */
	bpf_dynptr_from_mem(digest + MAGIC_SIZE, sizeof(digest) - MAGIC_SIZE, 0, &digest_ptr);

	ret = bpf_get_fsverity_digest(bprm->file, &digest_ptr);
	/* No verity, allow access */
	if (ret < 0)
		return;

	bpf_printk("read %d values of digest from fs-verity\n", bpf_dynptr_size(&digest_ptr));

	bpf_dynptr_from_mem(digest, sizeof(digest), 0, &digest_ptr);
	bpf_dynptr_from_mem(sig, sizeof(sig), 0, &sig_ptr);

	ret = bpf_get_file_xattr(bprm->file, "user.sig", &sig_ptr);
	/* No signature, reject access */
	if (ret < 0) {
		bpf_printk("error reading sigature from xattr\n");
		return;
	}

	bpf_printk("read %d values of signature from user.sig\n", bpf_dynptr_size(&sig_ptr));

	trusted_keyring = bpf_lookup_user_key(user_keyring_serial, 0);
	if (!trusted_keyring) {
		bpf_printk("error loading the keyring for verification\n");
		return;
	}

	policy = bpf_task_storage_get(&policy_map,
				       bpf_get_current_task_btf(), 0,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!policy)
		goto cleanup;

	ret = bpf_verify_pkcs7_signature(&digest_ptr, &sig_ptr, trusted_keyring);
	if (ret)
		goto cleanup;

	policy->signature_verified = 1;
	policy->allowed_prog_type_mask |= BPF_PROG_TYPE_LSM;
	policy->allowed_prog_type_mask |= BPF_PROG_TYPE_TRACING;

cleanup:
	bpf_key_put(trusted_keyring);
}
