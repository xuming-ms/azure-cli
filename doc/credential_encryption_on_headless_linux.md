# Enabling libsecret encryption for Azure CLI on a headless Linux VM

How to make `az login` store credentials in the OS credential store (libsecret) instead of
falling back to plaintext, on an Ubuntu VM you only ever reach over SSH.

Verified on Ubuntu 24.04, Python 3.12, an `azdev setup` dev build of azure-cli 2.90.0. Resource and
host names below are examples from one such VM; substitute your own.

## Why it doesn't work out of the box

`az` never touches `login.keyring` directly. It calls whichever process owns the D-Bus name
`org.freedesktop.secrets` on the **session** bus. On a desktop the login session provides that
daemon and PAM unlocks it with your login password. Over SSH neither happens, which produces two
distinct failures:

| Symptom | Cause |
| --- | --- |
| `.json` written, plaintext warning printed | `import gi` fails inside `LibsecretPersistence`, so `build_persistence` records a fallback and uses `FilePersistence` |
| `az` hangs forever, no output | Secret Service auto-activates a **locked** keyring daemon; unlocking needs an interactive prompt that doesn't exist over SSH, and `Secret.password_*_sync` has no timeout |

Both are worth knowing apart: a missing `gi` degrades gracefully, a locked keyring does not.

## Prerequisites

```bash
sudo apt-get install -y gnome-keyring libsecret-1-0 libsecret-tools python3-gi gir1.2-secret-1 dbus-x11
```

If `az` runs from a virtualenv, that venv must be able to import the system `gi`. A plain
`python3 -m venv` cannot. Either create it with `--system-site-packages`, or add a path file:

```bash
echo /usr/lib/python3/dist-packages > ~/venv-az/lib/python3.12/site-packages/system-dist-packages.pth
python -c "import gi; gi.require_version('Secret','1'); from gi.repository import Secret; print('ok')"
```

## What not to do: `dbus-launch` per shell

The obvious workaround is a script that each shell sources:

```bash
export $(dbus-launch)
echo -n "$PASSWORD" | gnome-keyring-daemon --unlock --components=secrets
```

It works, but only in the shell that ran it. `DBUS_SESSION_BUS_ADDRESS` is not shared, so a second
SSH window falls back to the systemd user bus, auto-activates a cold locked daemon, and hangs — while
the first window keeps working. Sourcing the script again in the second window doesn't share the
daemon, it forks a second one against the same keyring files. Repeat a few times and you have a pile
of orphaned `dbus-daemon`/`gnome-keyring-daemon` pairs.

The fix is to put one unlocked daemon on the **systemd user bus**, which every session already finds:
`libdbus` falls back to `$XDG_RUNTIME_DIR/bus` when `DBUS_SESSION_BUS_ADDRESS` is unset. Because the
name is then already owned, D-Bus never auto-activates the locked one.

## Setup

### 1. Keep the user manager alive

```bash
sudo loginctl enable-linger $USER
```

Without lingering, `user@$UID.service` and its bus come and go with each login, so there is nothing
for the daemon to attach to at boot.

### 2. Store the keyring password in Key Vault

Skip to step 3 with a local file if you don't care — see [Where the password lives](#where-the-password-lives).

```bash
RG=rg-tokencache-test VM=vm-tokencache VAULT=kv-tokencache-test LOC=australiaeast

PRINCIPAL=$(az vm identity assign -g $RG -n $VM --query systemAssignedIdentity -o tsv)
az keyvault create -g $RG -n $VAULT -l $LOC --enable-rbac-authorization true --sku standard
VAULT_ID=$(az keyvault show -g $RG -n $VAULT --query id -o tsv)

az role assignment create --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
    --assignee-principal-type User --role "Key Vault Secrets Officer" --scope "$VAULT_ID"
az keyvault secret set --vault-name $VAULT --name keyring-pass --value '<password>'

# Scope the VM's read access to the single secret, not the whole vault.
az role assignment create --assignee-object-id "$PRINCIPAL" \
    --assignee-principal-type ServicePrincipal --role "Key Vault Secrets User" \
    --scope "$VAULT_ID/secrets/keyring-pass"
```

Role assignments take a few seconds to propagate; `az keyvault secret set` right after the grant may
return 403 on the first try.

### 3. Unlock script

`~/.local/bin/keyring-unlock.sh`, mode 700:

```bash
#!/bin/bash
# Unlock the login keyring with a password held in Key Vault, fetched via the VM managed identity.
set -euo pipefail

VAULT=kv-tokencache-test
SECRET=keyring-pass
IMDS="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net"

fetch() {
    local token
    token=$(curl -sf --max-time 10 -H Metadata:true "$IMDS" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
    curl -sf --max-time 10 -H "Authorization: Bearer $token" \
        "https://$VAULT.vault.azure.net/secrets/$SECRET?api-version=7.4" |
        python3 -c "import sys,json;print(json.load(sys.stdin)['value'],end='')"
}

# IMDS and DNS are not necessarily up yet when the user manager starts at boot.
for attempt in {1..30}; do
    if pass=$(fetch); then
        break
    fi
    sleep 5
done
[ -n "${pass:-}" ] || { echo "could not fetch $SECRET from $VAULT" >&2; exit 1; }

exec gnome-keyring-daemon --foreground --components=secrets --unlock < <(printf "%s" "$pass")
```

The password reaches the daemon through process substitution, so it exists only in memory. `exec`
makes the daemon the unit's main process, so systemd's `Restart=` tracks the right thing.

### 4. User service

`~/.config/systemd/user/keyring-secrets.service`:

```ini
[Unit]
Description=Unlocked gnome-keyring secrets service for headless SSH
Documentation=https://aka.ms/azure-cli-credential-encryption
Requires=dbus.socket
After=dbus.socket

[Service]
Type=simple
ExecStart=%h/.local/bin/keyring-unlock.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now keyring-secrets.service
```

A user unit cannot order itself after `network-online.target`, which is why the script retries
instead of declaring a dependency.

## Verifying

Open a **fresh** SSH session and source nothing:

```bash
timeout 20 secret-tool lookup probe probe; echo "exit=$?"
```

- `exit=1` — the service answered "not found". Correct.
- `exit=124` — still hanging on a locked daemon. Setup is not in effect.

Then the `az` path itself:

```bash
python - <<'EOF'
import azure.cli.core.auth.persistence as p
per = p.build_persistence("/tmp/probe", True, type="Token cache")
print(type(per).__name__, per.is_encrypted, p._encryption_fallback)
per.save('{"hello": 1}')
print(per.load())
EOF
```

Expect `LibsecretPersistence True False`. After a real `az login` you should see a **0-byte**
`~/.azure/msal_token_cache.sig` and no `.json` — the `.sig` is only a modification signal, the
payload lives in the keyring.

Reboot and repeat both checks. That is the only way to confirm linger and the IMDS retry actually
work; `systemctl --user restart` proves neither.

## Where the password lives

Any unattended unlock needs a machine-readable key, so this is about limiting who else can read it,
not about secrecy.

| | plaintext `~/.keyring-pass` | managed identity + Key Vault |
| --- | --- | --- |
| disk image or backup copied off the VM | exposed | safe |
| another local user | exposed (mode 600) | safe |
| audit trail | none | Key Vault logs |
| revoke without touching the VM | no | yes, remove the role assignment |
| root on the running VM | exposed | exposed |
| shell as the owning user | exposed | exposed |

The last two rows are identical because anyone running as that user can simply ask the
already-unlocked daemon for the secrets. Key Vault raises the floor, not the ceiling.

A TPM (`systemd-creds --with-key=tpm2`) is the one option that meaningfully improves on this, but it
needs a Gen2 VM with Trusted Launch — check with `systemd-creds has-tpm2`.

Two alternatives worth knowing and their costs:

- **`pam_gnome_keyring`** unlocks with your login password and stores nothing. It is not
  headless-incompatible, it is *key-auth*-incompatible: with SSH public keys there is no password in
  the PAM stack. Enabling `PasswordAuthentication yes` to get it is a net loss.
- **Empty-password keyring** auto-unlocks with no secret anywhere, but gnome-keyring then stores the
  collection unencrypted. `az` still reports `is_encrypted=True`, so an encryption test would pass
  while nothing is encrypted at rest. Avoid it for exactly that reason.

## Reproducing the fallback path

To get the plaintext warning back for testing, run `az` on a bus with no unlocked Secret Service:

```bash
DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent az login --use-device-code
```

Pointing at a dead bus makes libsecret fail fast; pointing at a bus with a *locked* daemon makes it
hang instead, which is the failure mode described at the top.

## Teardown

```bash
az group delete -n rg-tokencache-test
az keyvault purge -n kv-tokencache-test   # soft-delete is on by default; needed to reuse the name
```
