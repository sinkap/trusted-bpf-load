SIGNING_KEY=~/trusted_load/signing_key.pem
SIGNING_KEY_BIN=~/trusted_load/signing_key.der
LOAD_SIGNATURE=~/load_signature
POLICY_LOADER=~/policy

function trust_loader()
{
	loader=$1

	if [[ ! -f "${loader}" ]]; then
		echo "Could not find the loader"
	fi

	fsverity sign --key ~/trusted_load/signing_key.pem ${loader} "${loader}.sig"
	${LOAD_SIGNATURE} "${loader}" "${loader}.sig"
	fsverity enable "${loader}"
}

function load_policy()
{
	key_id=$(cat ${SIGNING_KEY_BIN} | keyctl padd asymmetric bpf_loader_policy_key @s)
	keyring_id=$(keyctl newring bpf_loader_policy_keyring @s)
	keyctl link $key_id $keyring_id
	${POLICY_LOADER}
}