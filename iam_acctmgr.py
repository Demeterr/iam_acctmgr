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
'Integrate AWS IAM with the PAM, Name Service Switch, and SSH'
from __future__ import print_function
import argparse
import datetime
import json
import logging
import os
import pwd
import re
import spwd
import subprocess
import sys
import tempfile
import time
import traceback

import botocore.session


# Requires botocore>=1.0 but Jessie is on an ancient version
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=798015


LOG = logging.getLogger('iam_acctmgr')
EPOCH = datetime.datetime.utcfromtimestamp(0)
IAM_POLLING_INTERVAL = int(os.getenv('IAM_ACCTMGR_POLL_INTERVAL', 60))
MIN_USER_UID = int(os.getenv('IAM_ACCTMGR_MIN_USER_UID', 10000))
MAX_USER_UID = int(os.getenv('IAM_ACCTMGR_MAX_USER_UID', 19999))
IAM_PUB_KEY_FILE = '/etc/iam-pub-ssh-keys'
IAM_GROUP = os.getenv('IAM_ACCTMGR_GROUP')

EXTRAUSERS_PASSWD = '/var/lib/extrausers/passwd'
EXTRAUSERS_SHADOW = '/var/lib/extrausers/shadow'
SUDOERS_CONFIG = '/etc/sudoers.d/90-aws-iam-admin'


assert MAX_USER_UID > MIN_USER_UID


# UID Policies:
#
# Debian: https://www.debian.org/doc/manuals/system-administrator/ch-sysadmin-users.html


def is_iam_user(user):
    'Is the UID of a ``pwd.struct_passwd`` within the range of IAM users?'
    return user.pw_uid >= MIN_USER_UID and user.pw_uid <= MAX_USER_UID


def authorized_keys_command(username=None,
                            pub_keys_file=IAM_PUB_KEY_FILE,
                            out_fd=None):
    '''Print the SSH public keys associated with a username.

    This function reads from a file with a JSON payload generated from
    ``fetch_keys()``.

    See AuthorizedKeysCommand section of the OpenSSH manual.
    '''
    username = username or sys.argv[1]
    out_fd = out_fd or sys.stdout
    with open(pub_keys_file) as keyfd:
        keys = json.loads(keyfd.read())
        for key in keys[username]:
            print(key.strip(), file=out_fd)


def fetch_keys(group_name):
    '''Fetch SSH keys associated with all *active* users of an IAM group.

    This relies on a new SSH Public Key metadata feature recently added to AWS
    IAM.  Note that the AWS documentation currently only mentions this feature
    in the context of their CodeCommit product but the API naming itself has no
    such context.  See:

    https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetSSHPublicKey.html
    https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListSSHPublicKeys.html

    :type group_name: str
    :param group_name: The IAM group from which to create the extra users.
    '''
    session = botocore.session.get_session()
    iam = session.create_client('iam')
    try:
        members = iam.get_group(GroupName='admin')
    except:
        LOG.error('Error trying to retrieve IAM group %s', group_name)
        raise

    result = {}
    for user in members['Users']:
        username = user['UserName']
        result[username] = []
        for key in iam.list_ssh_public_keys(UserName=username)['SSHPublicKeys']:
            if 'Active' != key['Status']:
                continue
            ssh_pub = iam.get_ssh_public_key(
                UserName=username,
                SSHPublicKeyId=key['SSHPublicKeyId'],
                Encoding='SSH')['SSHPublicKey']['SSHPublicKeyBody']
            result[username].append(ssh_pub)

        # Ensure stable ordering
        result[username].sort()

    return result


def filter_keys(user_pks, system_names):
    'Filter out invalid user(name)s'
    result = {}

    # Only accept posix compliant usernames.
    # https://serverfault.com/questions/73084/
    name_regex = re.compile(r'^[_.A-Za-z0-9][-_.A-Za-z0-9]*$')

    for username, pks in user_pks.items():
        if name_regex.match(username) is None:
            LOG.warning('Skipping invalid user name %s', username)
            continue

        if username in system_names:
            LOG.warning('Skipping IAM user %s due to matching system user',
                        username)
            continue
        if len(pks) < 1:
            LOG.warning('Skipping IAM user %s with no public keys',
                        username)
            continue

        result[username] = pks

    return result


def passwd_to_line(struct):
    'Map an instance of ``pwd.struct_passwd`` to a byte-string.'
    return ':'.join(str(x) for x in struct).encode('utf-8')


def shadow_to_line(struct):
    'Map an instance of ``spwd.struct_spwd`` to a byte-string.'
    return ':'.join('' if isinstance(x, int) and x < 0 else str(x)
                    for x in struct).encode('utf-8')


def process(user_pks, pwall, spwall):
    '''Generate the passwd, shadow, and sudo fragments for IAM users.

    :param user_pks: Mapping of username (``str``) to public keys (``list`` of
                     ``str``) retrieved from IAM.
    :type user_pks: dict

    :param pwall: A list of ``pwd.struct_passwd`` including all password
                  entries found by NSS. Should include those users identified
                  by libnss-extrausers.
    :type pwall: list
    '''
    username_index = dict(
        (user.pw_name, user) for user in pwall if is_iam_user(user))
    susername_index = dict(
        (user[0], user) for user in spwall
        if user[0] in username_index)
    uid_index = dict((int(user.pw_uid), user) for user in pwall)
    next_uid = MIN_USER_UID

    passwd, shadow, sudo = [], [], []

    # Users that have been removed from IAM will keep their UIDs around in the
    # event that user IDs have.  In practice, I don't anticipate this behavior
    # to be problematic since there is an abundance of UIDs available in the
    # default configuration UID range for all but the largest admin user pools.
    for old_username in set(username_index.keys()) - set(user_pks.keys()):
        passwd.append(username_index[old_username])
        shadow.append(susername_index[old_username])

    for username in user_pks.keys():
        # Find the next gap in user IDs
        while next_uid in uid_index:
            next_uid += 1
        if next_uid > MAX_USER_UID:
            LOG.error("User limit reached!  Skipping user %s", username)
            break

        sudo.append('{} ALL=(ALL) NOPASSWD:ALL'.format(username))

        if username in username_index:
            passwd.append(username_index[username])
            shadow.append(susername_index[username])
        else:
            passwd.append(pwd.struct_passwd((
                username,
                'x',
                next_uid,
                next_uid,
                'IAM-USER',
                '/home/{}'.format(username),
                '/bin/bash',
            )))

            shadow.append(spwd.struct_spwd((
                username,
                '*',
                (datetime.datetime.utcnow() - EPOCH).days,
                0,
                99999,
                7,
                -1,
                -1,
                -1,
            )))
            next_uid += 1

    sudo.sort()
    sudo.insert(0, '# Created by {} on {}'.format(
        __file__,
        datetime.datetime.utcnow().ctime()))

    return (
        sorted(passwd_to_line(x) for x in passwd),
        sorted(shadow_to_line(x) for x in shadow),
        [x.encode('utf-8') for x in sudo]
    )


def write(lines, target, permissions='0644'):
    '''Write a sequence of byte strings to a file as individual lines.

    This function first stages the file in a temporary directory.
    '''
    with tempfile.NamedTemporaryFile(delete=False) as staging:
        for line in lines:
            staging.write(line)
            staging.write(b'\n')
    subprocess.check_call(
        ('install', '-T', '-m', permissions, staging.name, target))


def service():
    'Poll IAM and update all necessary system configuration files.'
    logging.basicConfig(level=logging.INFO)

    iam_group = IAM_GROUP
    if len(sys.argv) > 1:
        iam_group = sys.argv[1]
    assert iam_group is not None, 'IAM_ACCTMGR_GROUP env variable is not set'

    prior = None
    while True:
        try:
            pwall, spwall = pwd.getpwall(), spwd.getspall()
            system_names = set(
                user.pw_name for user in pwall if not is_iam_user(user))
            user_pks = filter_keys(fetch_keys(iam_group), system_names)
            if prior == user_pks:
                # No change - short circuit
                time.sleep(IAM_POLLING_INTERVAL)
                continue
            else:
                prior = user_pks
            LOG.info('Processing user accounts: %s', user_pks)

            extra_passwd, extra_shadow, extra_sudo = process(
                user_pks, pwall, spwall)

            write(extra_passwd, EXTRAUSERS_PASSWD)
            write(extra_shadow, EXTRAUSERS_SHADOW, '0600')
            write(extra_sudo, SUDOERS_CONFIG, '0400')

            with open(IAM_PUB_KEY_FILE, 'w') as keyfd:
                json.dump(user_pks, keyfd)
        # pylint: disable=broad-except
        except Exception:
            LOG.error(traceback.format_exc())
        # pylint: enable=broad-except
        time.sleep(IAM_POLLING_INTERVAL)


def configure_system(argv=None):
    '''Modify the SSHD, NSS, and PAM configurations as necessary for remote
    authentication and authorization.

    Note this does *not* introduce a systemd service for iam_acctmgr.
    '''
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Configure iam_acctmgr')
    parser.add_argument('binpath',
                        help='The path to the bin directory '
                             'containing iam_acctmgr executables.')
    parser.add_argument('--sshd', default=None,
                        help='SSHD config file')
    parser.add_argument('--pam', default=None,
                        help='PAM config file')
    parser.add_argument('--nsswitch', default=None,
                        help='NSS config file')

    args = parser.parse_args(argv or sys.argv[1:])

    if not os.path.exists(os.path.join(args.binpath, 'iam_acctmgr')):
        LOG.error('Could not find iam_acctmgr executable.')
        sys.exit(1)
    if not os.path.exists(os.path.join(args.binpath, 'iam_acctmgr_keys')):
        LOG.error('Could not find iam_acctmgr_keys executable.')
        sys.exit(1)

    if args.sshd is not None:
        make_config_sshd(args.sshd, args.binpath)

    if args.pam is not None:
        make_config_pam(args.pam)

    if args.nsswitch is not None:
        make_config_nsswitch(args.nsswitch)


def make_config_sshd(sshd_config_path, binpath):
    '''Modify the system\'s SSHD configuration to authenticate user IAM keys.

    This function will bail if AuthorizedKeysCommand is already set in the
    specified SSH configuration.
    '''
    with open(sshd_config_path) as sshd_fd:
        config = sshd_fd.read()

    # Technically, if ...Command is set, ...CommandUser must be set otherwise
    # the config is invalid.
    if re.search(r'^\s*AuthorizedKeysCommand\s', config,
                 flags=re.MULTILINE) is not None:
        LOG.warning('SSHD config %s already has an AuthorizedKeysCommand '
                    'set.  Not changing SSH configuration', sshd_config_path)
    else:
        LOG.warning('Updating %s with AuthorizedKeysCommand[User] entries',
                    sshd_config_path)
        with open(sshd_config_path, 'a') as sshd_fd:
            sshd_fd.write('\n\nAuthorizedKeysCommandUser root\n')
            sshd_fd.write('AuthorizedKeysCommand {}\n'.format(
                os.path.join(binpath, 'iam_acctmgr_keys')))


def make_config_pam(pam_config_path):
    '''Modify PAM to create home directories on demand.

    This is optional but results in a better experience.
    '''
    with open(pam_config_path) as pam_fd:
        config = pam_fd.read()

    re_mkhome = re.compile(r'^\s*session\s+required\s+pam_mkhomedir.so\s',
                           flags=re.MULTILINE)
    if re_mkhome.search(config) is not None:
        LOG.warning('PAM config already includes pam_mkhomedir.so.  '
                    'Not action taken')
    else:
        LOG.warning('Updating %s to enable pam_mkhomedir.so', pam_config_path)
        with open(pam_config_path, 'a') as pam_fd:
            pam_fd.write('\n\nsession required pam_mkhomedir.so '
                         'skel=/etc/skel/ umask=0022\n')


def make_config_nsswitch(nsswitch_config_path):
    '''Modify the NSS configuration to use the libnss-extrausers database.
    '''
    result = []
    extrausers = 'extrausers'
    with open(nsswitch_config_path) as nss_fd:
        for line in nss_fd.readlines():
            parts = line.split('#', 1)
            if (parts[0].strip().startswith('passwd:')
                    or parts[0].strip().startswith('shadow:')):
                subparts = parts[0].split()
                if extrausers not in subparts:
                    result.append('{} {}'.format(
                        parts[0].rstrip(), extrausers).encode('utf-8'))
                    continue
            result.append(line.rstrip().encode('utf-8'))
    write(result, nsswitch_config_path)
