# Copyright 2015 Bebop Technologies
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import contextlib
import io
import json
import os
import shutil
import stat
import tempfile
from datetime import datetime
from pwd import struct_passwd
from spwd import struct_spwd

import iam_acctmgr


PUB_KEYS = {
    'don': [
        'ssh-rsa AAAAB...9v8qch'
    ],
    'quixote': [
        'ssh-rsa AAAAC...lai6ha',
        'ssh-rsa AAAAD...d0ufix'
    ]
}


@contextlib.contextmanager
def tempdir():
    workdir = tempfile.mkdtemp()
    try:
        yield workdir
    finally:
        shutil.rmtree(workdir)


def read(path):
    with open(path) as path_fd:
        return path_fd.read()


def test_authorized_keys_command():
    with tempfile.NamedTemporaryFile() as fd:
        fd.write(json.dumps(PUB_KEYS).encode('utf-8'))
        fd.flush()

        test_result_1 = io.StringIO()
        iam_acctmgr.authorized_keys_command(
                username='don',
                pub_keys_file=fd.name,
                out_fd=test_result_1)
        test_result_1.seek(0)
        assert('ssh-rsa AAAAB...9v8qch\n' == test_result_1.read())

        test_result_2 = io.StringIO()
        iam_acctmgr.authorized_keys_command(
                username='quixote',
                pub_keys_file=fd.name,
                out_fd=test_result_2)
        test_result_2.seek(0)
        expected = 'ssh-rsa AAAAC...lai6ha\nssh-rsa AAAAD...d0ufix\n'
        assert(expected == test_result_2.read())

        # Goes to stdout - eaten by py.test
        iam_acctmgr.authorized_keys_command(
                username='don', pub_keys_file=fd.name)

        try:
            iam_acctmgr.authorized_keys_command(
                    username='noexist', pub_keys_file=fd.name)
            raise Exception('Should not reach this point')
        except KeyError:
            pass


def test_filter_keys():
    unfiltered = PUB_KEYS.copy()
    unfiltered['root'] = ['k2']
    unfiltered['nokey'] = []
    unfiltered['invalid@example.com'] = ['k3', 'k4']
    unfiltered['-Invalid'] = ['k5']

    assert iam_acctmgr.filter_keys(unfiltered, {'root', 'admin'}) == PUB_KEYS


def test_process():
    prior = [
        struct_passwd(('A', 'x', 10000, 10000, '', '/home/A', '/bin/bash')),
        struct_passwd(('B', 'x', 10001, 10001, '', '/home/B', '/bin/bash')),
        struct_passwd(('C', 'x', 10099, 10099, '', '/home/C', '/bin/bash')),
    ]

    sprior = [
        struct_spwd(('A', '*', 16593, 0, 99999, 7, -1, -1, -1)),
        struct_spwd(('B', '*', 16503, 0, 99999, 7, -1, -1, -1)),
        struct_spwd(('C', '*', 16513, 0, 99999, 7, -1, -1, -1)),
    ]

    user_pks = {
        'john': [
            'ssh-rsa AAAAC...aliuh7',
            'ssh-rsa AAAAC...qo874y',
        ],
        'C': [
            'ssh-rsa AAAAC...7a6cs1',
        ]
    }

    passwd, shadow, sudo = iam_acctmgr.process(user_pks, prior, sprior)

    days_since_epoch = str(
        (datetime.utcnow() - iam_acctmgr.EPOCH).days
    ).encode('utf-8')

    assert passwd == [
            b'A:x:10000:10000::/home/A:/bin/bash',
            b'B:x:10001:10001::/home/B:/bin/bash',
            b'C:x:10099:10099::/home/C:/bin/bash',
            b'john:x:10002:10002:IAM-USER:/home/john:/bin/bash',
    ]

    assert shadow == [
            b'A:*:16593:0:99999:7:::',
            b'B:*:16503:0:99999:7:::',
            b'C:*:16513:0:99999:7:::',
            b'john:*:' + days_since_epoch + b':0:99999:7:::'
    ]

    assert sudo[0].decode('utf-8').startswith('# ')
    assert sudo[1:] == [
            b'C ALL=(ALL) NOPASSWD:ALL',
            b'john ALL=(ALL) NOPASSWD:ALL',
    ]


def test_write():
    with tempdir() as workdir:
        target = os.path.join(workdir, 'target')
        iam_acctmgr.write([
            b'Hello World',
            b'arglebargle'
        ], target, '0400')
        target_stat = os.stat(target)

        assert bool(target_stat.st_mode & stat.S_IRUSR)
        for mask in (stat.S_IWUSR, stat.S_IXUSR,
                stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
                stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH):
            assert not bool(target_stat.st_mode & mask)

        with open(target) as tfd:
            assert b'Hello World\narglebargle\n' == tfd.read().encode('utf-8')


def test_make_config_sshd():
    expected = (
        'Port 22\n'
        'Protocol 2\n\n'
        'AuthorizedKeysCommandUser root\n'
        'AuthorizedKeysCommand /path/to/bin/iam_acctmgr_keys\n'
    )

    with tempdir() as workdir:
        sshd_config = os.path.join(workdir, 'sshd_config')
        with open(sshd_config, 'w') as sshd_fd:
            sshd_fd.write('Port 22\nProtocol 2')

        iam_acctmgr.make_config_sshd(sshd_config, '/path/to/bin')
        assert expected == read(sshd_config)

        # Make sure it's idempotent and short circuits if the keys are already there.
        iam_acctmgr.make_config_sshd(sshd_config, '/path/to/bin')
        assert expected == read(sshd_config)


def test_make_config_pam():
    prior = (
        '# Some comment\n\n'
        'account requisite pam_deny.so\n'
        'account requisite pam_permit.so'
    )

    expected = prior + (
        '\n\n'
        'session required pam_mkhomedir.so skel=/etc/skel/ umask=0022\n'
    )

    with tempdir() as workdir:
        pam_config = os.path.join(workdir, 'common-account')
        with open(pam_config, 'w') as sshd_fd:
            sshd_fd.write(prior)
        iam_acctmgr.make_config_pam(pam_config)
        assert expected == read(pam_config)

        # Assert idempotency
        iam_acctmgr.make_config_pam(pam_config)
        assert expected == read(pam_config)


def test_config_nsswitch():
    prior = (
        'passwd:         compat\n'
        'group:          compat\n'
        'shadow:         compat\n'
        'gshadow:        files\n'
        '\n'
        'hosts:          files dns\n'
        'networks:       files\n'
        '\n'
        'protocols:      db files\n'
        'services:       db files\n'
        'ethers:         db files\n'
        'rpc:            db files\n'
        '\n'
        'netgroup:       nisssert expected == read(pam_config)\n'
    )
    expected = (
        'passwd:         compat extrausers\n'
        'group:          compat\n'
        'shadow:         compat extrausers\n'
        'gshadow:        files\n'
        '\n'
        'hosts:          files dns\n'
        'networks:       files\n'
        '\n'
        'protocols:      db files\n'
        'services:       db files\n'
        'ethers:         db files\n'
        'rpc:            db files\n'
        '\n'
        'netgroup:       nisssert expected == read(pam_config)\n'
    )

    with tempdir() as workdir:
        nss_config = os.path.join(workdir, 'nsswitch.conf')
        with open(nss_config, 'w') as nss_fd:
            nss_fd.write(prior)
        iam_acctmgr.make_config_nsswitch(nss_config)
        assert expected == read(nss_config)

        # Assert idempotency
        iam_acctmgr.make_config_nsswitch(nss_config)
        assert expected == read(nss_config)
