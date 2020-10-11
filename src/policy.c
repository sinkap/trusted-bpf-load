// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */


// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/keyctl.h>
#include <linux/fsverity.h>
#include "policy.skel.h"

#ifndef __NR_request_key
#define __NR_request_key 249
#endif

#define __NR_keyctl 250

typedef union {
	uid_t uid;
	uid_t gid;
} kid_t;

enum setid_type {
	UID,
	GID
};
struct setid_rule {
	kid_t src_id;
	kid_t dst_id;

	enum setid_type stype;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct policy_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = policy_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	syscall(__NR_request_key, "keyring", "_uid.0", NULL, KEY_SPEC_SESSION_KEYRING);
	skel->bss->user_keyring_serial = syscall(__NR_request_key, "keyring",
						 "bpf_loader_policy_keyring", NULL,
						 KEY_SPEC_SESSION_KEYRING);
	memcpy(skel->bss->digest, "FSVerity", 8);

	err =  policy_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	bpf_object__pin(skel->obj, "/sys/fs/bpf/trusted_bpf_policy");
	bpf_link__pin(skel->links.trusted_bpf_check_policy, "/sys/fs/bpf/trusted_bpf_policy/link__trusted_bpf_check_policy");
	bpf_link__pin(skel->links.trusted_bpf_load_policy_at_exec, "/sys/fs/bpf/trusted_bpf_policy/link__trusted_bpf_load_policy_at_exec");
	bpf_link__pin(skel->links.trusted_bpf_inherit_policy, "/sys/fs/bpf/trusted_bpf_policy/link__trusted_bpf_inherit_policy");
	return 0;

cleanup:
	policy_bpf__destroy(skel);
	return -err;
}