# encoding: utf-8

#
# Cookbook Name:: os-hardening
# Attributes:: default
#
# Copyright 2012, Dominik Richter
# Copyright 2014, Deutsche Telekom AG
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

# Define the packages based on operating system
case node['platform_family']
when 'rhel', 'fedora', 'amazon'
  default['os-hardening']['packages']['pam_ccreds'] = 'pam_ccreds'
  default['os-hardening']['packages']['pam_passwdqc'] = 'pam_passwdqc'
  default['os-hardening']['packages']['pam_cracklib'] = 'pam_cracklib'
  default['os-hardening']['packages']['pam_pwquality'] = 'libpwquality'
  default['os-hardening']['packages']['auditd'] = 'audit'
  default['os-hardening']['yum']['gpg_exclude'] = []

  if node['platform_version'].to_f < 7
    default['os-hardening']['auth']['pam']['passwdqc']['enable']  = true
    default['os-hardening']['auth']['pam']['pwquality']['enable']  = false
  else
    default['os-hardening']['auth']['pam']['passwdqc']['enable']  = false
    default['os-hardening']['auth']['pam']['pwquality']['enable']  = true
  end

when 'debian'
  default['os-hardening']['packages']['pam_ccreds'] = 'libpam-ccreds'
  default['os-hardening']['packages']['pam_passwdqc'] = 'libpam-passwdqc'
  default['os-hardening']['packages']['pam_cracklib'] = 'libpam-cracklib'
  default['os-hardening']['packages']['auditd'] = 'auditd'

when 'arch'
  default['os-hardening']['packages']['pam_ccreds'] = 'pam_ccreds'
  default['os-hardening']['packages']['pam_passwdqc'] = 'pam_passwdqc'
  default['os-hardening']['packages']['pam_cracklib'] = 'pam_cracklib'
  default['os-hardening']['packages']['auditd'] = 'audit'

else
  default['os-hardening']['packages']['pam_ccreds'] = 'pam_ccreds'
  default['os-hardening']['packages']['pam_passwdqc'] = 'pam_passwdqc'
  default['os-hardening']['packages']['pam_cracklib'] = 'pam_cracklib'
  default['os-hardening']['packages']['auditd'] = 'audit'
end

%w[packages limits login_defs minimize_access pam profile securetty].each do |cp|
  node.default['os-hardening']['components'][cp] = true
end

# rhel, centos autoconf configuration
default['os-hardening']['authconfig']['shadow']['enable'] = true
default['os-hardening']['authconfig']['md5']['enable'] = true

default['config_disclaimer']                         = '**Note:** This file was automatically created by dev-sec.io os-hardening configuration. If you use its automated setup, do not edit this file directly, but adjust the automation instead.'
default['os-hardening']['desktop']['enable']                          = false
default['os-hardening']['network']['forwarding']                      = false
default['os-hardening']['network']['ipv6']['enable']                   = false
default['os-hardening']['network']['arp']['restricted']                = true
default['os-hardening']['env']['extra_user_paths']                    = []
default['os-hardening']['env']['root_path']                           = '/'
default['os-hardening']['auth']['pw_max_age']                         = 60
default['os-hardening']['auth']['pw_min_age']                         = 7 # discourage password cycling
default['os-hardening']['auth']['pw_warn_age']                        = 7
default['os-hardening']['auth']['retries']                            = 5
default['os-hardening']['auth']['lockout_time']                       = 600 # 10min
default['os-hardening']['auth']['maildir']                            = '/var/mail'
default['os-hardening']['auth']['timeout']                            = 60
default['os-hardening']['auth']['allow_homeless']                     = false
default['os-hardening']['auth']['login_defs']['template_cookbook']    = 'os-hardening'
default['os-hardening']['auth']['pam']['passwdqc']['options']           = 'min=disabled,disabled,16,12,8'
default['os-hardening']['auth']['pam']['cracklib']['options']           = 'try_first_pass retry=3 type='
default['os-hardening']['auth']['pam']['pwquality']['options']          = 'try_first_pass retry=3 type='
default['os-hardening']['auth']['pam']['tally2']['template_cookbook']        = 'os-hardening'
default['os-hardening']['auth']['pam']['passwdqc']['template_cookbook']      = 'os-hardening'
default['os-hardening']['auth']['pam']['system-auth']['template_cookbook']   = 'os-hardening'
default['os-hardening']['auth']['root_ttys']                          = %w[console tty1 tty2 tty3 tty4 tty5 tty6]
default['os-hardening']['auth']['uid_min']                             = 1000
default['os-hardening']['auth']['uid_max']                             = 60000
default['os-hardening']['auth']['gid_min']                             = 1000
default['os-hardening']['auth']['gid_max']                             = 60000
default['os-hardening']['auth']['sys_uid_max']                         = 999
default['os-hardening']['auth']['sys_gid_max']                         = 999

# RH has a bit different defaults on some places
case node['platform_family']
when 'rhel', 'amazon'
  default['os-hardening']['env']['umask'] = '077'
  default['os-hardening']['auth']['sys_uid_min'] = 201
  default['os-hardening']['auth']['sys_gid_min'] = 201
else
  default['os-hardening']['env']['umask'] = '027'
  default['os-hardening']['auth']['sys_uid_min'] = 100
  default['os-hardening']['auth']['sys_gid_min'] = 100
end

# may contain: change_user
default['os-hardening']['security']['users']['allow']                  = []
default['os-hardening']['security']['kernel']['enable_module_loading'] = true
default['os-hardening']['security']['kernel']['disable_filesystems']   = %w[cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat]
default['os-hardening']['security']['kernel']['enable_sysrq']          = false
default['os-hardening']['security']['kernel']['enable_core_dump']      = false
default['os-hardening']['security']['suid_sgid']['enforce']            = true
# user-defined blacklist and whitelist
default['os-hardening']['security']['suid_sgid']['blacklist']          = []
default['os-hardening']['security']['suid_sgid']['whitelist']          = []
# if this is true, remove any suid/sgid bits from files that were not in the
# whitelist
default['os-hardening']['security']['suid_sgid']['remove_from_unknown'] = false
default['os-hardening']['security']['suid_sgid']['dry_run_on_unknown']  = false

# Allow interactive startup (rhel, centos)
default['os-hardening']['security']['init']['prompt']                   = true
# Require root password for single user mode. (rhel, centos)
default['os-hardening']['security']['init']['single']                   = false

# remove packages with known issues
default['os-hardening']['security']['packages']['clean']               = true
# list of packages with known issues
default['os-hardening']['security']['packages']['list']               = [
  'xinetd',
  'inetd',
  'ypserv',
  'telnet-server',
  'rsh-server'
]

# SELinux enforcing (enforcing, permissive, unmanaged)
default['os-hardening']['security']['selinux_mode']                      = 'unmanaged'

# SYSTEM CONFIGURATION
# ====================
# These are not meant to be modified by the user

# misc
default['os-hardening']['security']['kernel']['secure_sysrq']                 = 4 + 16 + 32 + 64 + 128

# suid and sgid blacklists and whitelists
# ---------------------------------------
# don't change values in the system_blacklist/whitelist
# adjust values for blacklist/whitelist instead, they can override system_blacklist/whitelist

# list of suid/sgid entries that must be removed
default['os-hardening']['security']['suid_sgid']['system_blacklist']          = [
  # blacklist as provided by NSA
  '/usr/bin/rcp', '/usr/bin/rlogin', '/usr/bin/rsh',
  # sshd must not use host-based authentication (see ssh cookbook)
  '/usr/libexec/openssh/ssh-keysign',
  '/usr/lib/openssh/ssh-keysign',
  # misc others
  '/sbin/netreport',                                            # not normally required for user
  '/usr/sbin/usernetctl',                                       # modify interfaces via functional accounts
  # connecting to ...
  '/usr/sbin/userisdnctl',                                      # no isdn...
  '/usr/sbin/pppd',                                             # no ppp / dsl ...
  # lockfile
  '/usr/bin/lockfile',
  '/usr/bin/mail-lock',
  '/usr/bin/mail-unlock',
  '/usr/bin/mail-touchlock',
  '/usr/bin/dotlockfile',
  # need more investigation, blacklist for now
  '/usr/bin/arping',
  '/usr/sbin/uuidd',
  '/usr/bin/mtr',                                               # investigate current state...
  '/usr/lib/evolution/camel-lock-helper-1.2',                   # investigate current state...
  '/usr/lib/pt_chown',                                          # pseudo-tty, needed?
  '/usr/lib/eject/dmcrypt-get-device',
  '/usr/lib/mc/cons.saver'                                      # midnight commander screensaver
]

# list of suid/sgid entries that can remain untouched
default['os-hardening']['security']['suid_sgid']['system_whitelist']          = [
  # whitelist as provided by NSA
  '/bin/mount', '/bin/ping', '/bin/su', '/bin/umount', '/sbin/pam_timestamp_check',
  '/sbin/unix_chkpwd', '/usr/bin/at', '/usr/bin/gpasswd', '/usr/bin/locate',
  '/usr/bin/newgrp', '/usr/bin/passwd', '/usr/bin/ssh-agent', '/usr/libexec/utempter/utempter', '/usr/sbin/lockdev',
  '/usr/sbin/sendmail.sendmail', '/usr/bin/expiry',
  # whitelist ipv6
  '/bin/ping6', '/usr/bin/traceroute6.iputils',
  # whitelist nfs
  '/sbin/mount.nfs', '/sbin/umount.nfs',
  # whitelist nfs4
  '/sbin/mount.nfs4', '/sbin/umount.nfs4',
  # whitelist cron
  '/usr/bin/crontab',
  # whitelist consolemssaging
  '/usr/bin/wall', '/usr/bin/write',
  # whitelist: only SGID with utmp group for multi-session access
  #            impact is limited; installation/usage has some remaining risk
  '/usr/bin/screen',
  # whitelist locate
  '/usr/bin/mlocate',
  # whitelist usermanagement
  '/usr/bin/chage', '/usr/bin/chfn', '/usr/bin/chsh',
  # whitelist fuse
  '/bin/fusermount',
  # whitelist pkexec
  '/usr/bin/pkexec',
  # whitelist sudo
  '/usr/bin/sudo', '/usr/bin/sudoedit',
  # whitelist postfix
  '/usr/sbin/postdrop', '/usr/sbin/postqueue',
  # whitelist apache
  '/usr/sbin/suexec',
  # whitelist squid
  '/usr/lib/squid/ncsa_auth', '/usr/lib/squid/pam_auth',
  # whitelist kerberos
  '/usr/kerberos/bin/ksu',
  # whitelist pam_caching
  '/usr/sbin/ccreds_validate',
  # whitelist Xorg
  '/usr/bin/Xorg',                                              # xorg
  '/usr/bin/X',                                                 # xorg
  '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',                # freedesktop ipc
  '/usr/lib/vte/gnome-pty-helper',                              # gnome
  '/usr/lib/libvte9/gnome-pty-helper',                          # gnome
  '/usr/lib/libvte-2.90-9/gnome-pty-helper'                     # gnome
]

# set default cpu vendor
default['os-hardening']['security']['cpu_vendor'] = 'intel'
