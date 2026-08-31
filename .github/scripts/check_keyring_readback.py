#!/usr/bin/env python
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""Assert that a later command authenticates from the encrypted store, and only from it.

check_keyring_encryption.py reads the payload back through the same code that wrote it, which
proves the write worked but not that the CLI can use it. This runs a real command in a fresh
process instead, then empties the libsecret payload and runs it again: if the second run still
succeeds, something outside the keyring was serving the credential and the first result meant
nothing.
"""

import os
import subprocess
import sys

from azure.cli.core._environment import get_config_dir
from azure.cli.core.auth.persistence import (build_persistence, file_extension_plaintext,
                                             file_extension_signal)

# A scope the sign-in itself did not fetch a token for, so answering it needs the stored
# credential rather than the access token that login happened to leave behind.
SCOPE = 'https://graph.microsoft.com/.default'

PERSISTENCES = [('msal_token_cache', 'Token cache'), ('service_principal_entries', 'Secret store')]


def get_access_token(az):
    return subprocess.run([az, 'account', 'get-access-token', '--scope', SCOPE, '-o', 'none'],
                          capture_output=True, text=True, check=False)


def plaintext_files():
    config_dir = get_config_dir()
    return [name for name, _ in PERSISTENCES
            if os.path.isfile(os.path.join(config_dir, name + file_extension_plaintext))]


def empty_the_keyring():
    config_dir = get_config_dir()
    for name, type_ in PERSISTENCES:
        build_persistence(os.path.join(config_dir, name), True, type=type_).save('{}')


def main(az):
    failures = []
    config_dir = get_config_dir()

    for name, _ in PERSISTENCES:
        if not os.path.isfile(os.path.join(config_dir, name + file_extension_signal)):
            failures.append(f'{name}{file_extension_signal} is missing before the command ran')
    if plaintext_files():
        failures.append(f'plaintext files exist before the command ran: {plaintext_files()}')

    first = get_access_token(az)
    if first.returncode != 0:
        failures.append('a command could not authenticate from the encrypted store')
        print('--- stderr ---')
        print(first.stderr[-2000:])
    if plaintext_files():
        failures.append(f'the command wrote plaintext files: {plaintext_files()}')

    # The negative control. Without it, a plaintext file or an in-memory fallback could have
    # served the token above and this check would still pass.
    empty_the_keyring()
    second = get_access_token(az)
    if second.returncode == 0:
        failures.append('the command still worked with the keyring emptied, so it was not the '
                        'keyring that held the credential')

    for failure in failures:
        print(f'::error::{failure}')
    if failures:
        return 1

    print('a fresh process authenticated from libsecret, and stopped working once it was emptied')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
