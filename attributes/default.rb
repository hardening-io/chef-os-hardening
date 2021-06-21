# frozen_string_literal: true

#
# Cookbook:: os-hardening
# Attributes:: default
#
# Copyright:: 2012, Dominik Richter
# Copyright:: 2014, Deutsche Telekom AG
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

# rubocop:disable Metrics/BlockLength

default['os-hardening'].tap do |os_hardening|
  # components of this cookbook
  %w(packages limits login_defs minimize_access pam profile securetty).each do |cp|
    os_hardening['components'][cp] = true
  end

  # Define the packages based on operating system
  os_hardening['packages'].tap do |packages|
    case node['platform_family']
    when 'rhel', 'fedora', 'amazon'
      packages['pam_ccreds'] = 'pam_ccreds'
      packages['pam_passwdqc'] = 'pam_passwdqc'
      packages['pam_cracklib'] = 'pam_cracklib'
      packages['pam_pwquality'] = 'libpwquality'
      packages['auditd'] = 'audit'
    when 'debian'
      packages['pam_ccreds'] = 'libpam-ccreds'
      packages['pam_passwdqc'] = 'libpam-passwdqc'
      packages['pam_cracklib'] = 'libpam-cracklib'
      packages['auditd'] = 'auditd'
    when 'arch'
      packages['pam_ccreds'] = 'pam_ccreds'
      packages['pam_passwdqc'] = 'pam_passwdqc'
      packages['pam_cracklib'] = 'pam_cracklib'
      packages['auditd'] = 'audit'
    else
      packages['pam_ccreds'] = 'pam_ccreds'
      packages['pam_passwdqc'] = 'pam_passwdqc'
      packages['pam_cracklib'] = 'pam_cracklib'
      packages['auditd'] = 'audit'
    end
  end

  # rhel, centos autoconf configuration
  os_hardening['authconfig']['shadow']['enable'] = true
  os_hardening['authconfig']['md5']['enable'] = true

  os_hardening['desktop']['enable'] = false
  os_hardening['network']['forwarding'] = false
  os_hardening['network']['ipv6']['enable'] = false
  os_hardening['network']['arp']['restricted'] = true

  os_hardening['env']['extra_user_paths'] = []
  os_hardening['env']['root_path'] = '/'

  os_hardening['auth'].tap do |auth|
    auth['pw_max_age'] = 60
    auth['pw_min_age'] = 7 # discourage password cycling
    auth['pw_warn_age'] = 7
    auth['retries'] = 5
    auth['lockout_time'] = 600 # 10min
    auth['maildir'] = '/var/mail'
    auth['timeout'] = 60
    auth['allow_homeless'] = false
    auth['login_defs']['template_cookbook'] = 'os-hardening'
    auth['root_ttys'] = %w(console tty1 tty2 tty3 tty4 tty5 tty6)
    auth['uid_min'] = 1000
    auth['uid_max'] = 60000
    auth['gid_min'] = 1000
    auth['gid_max'] = 60000
    auth['sys_uid_max'] = 999
    auth['sys_gid_max'] = 999

    # PAM settings
    auth['pam'].tap do |pam|
      if platform_family?('rhel', 'fedora', 'amazon')
        if node['platform_version'].to_f < 7
          pam['passwdqc']['enable'] = true
          pam['pwquality']['enable'] = false
        else
          pam['passwdqc']['enable'] = false
          pam['pwquality']['enable'] = true
        end
      end

      pam['passwdqc']['options'] = 'min=disabled,disabled,16,12,8'
      pam['cracklib']['options'] = 'try_first_pass retry=3 type='
      pam['pwquality']['options'] = 'try_first_pass retry=3 type='
      pam['unix']['options'] = 'shadow nullok try_first_pass use_authtok remember=5'
      pam['tally2']['template_cookbook'] = 'os-hardening'
      pam['passwdqc']['template_cookbook'] = 'os-hardening'
      pam['system-auth']['template_cookbook'] = 'os-hardening'
      pam['pam_systemd']['enable'] = node['os-hardening']['desktop']['enable']
    end
  end

  # RH has a bit different defaults on some places
  if platform_family?('rhel', 'amazon')
    os_hardening['env']['umask'] = '077'
    os_hardening['auth']['sys_uid_min'] = 201
    os_hardening['auth']['sys_gid_min'] = 201
  else
    os_hardening['env']['umask'] = '027'
    os_hardening['auth']['sys_uid_min'] = 100
    os_hardening['auth']['sys_gid_min'] = 100
  end

  os_hardening['security'].tap do |security|
    # may contain: change_user
    security['users']['allow'] = []
    security['kernel']['enable_module_loading'] = true
    security['kernel']['disable_filesystems'] = %w(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat)
    security['kernel']['enable_sysrq'] = false
    security['kernel']['enable_core_dump'] = false
    security['suid_sgid']['enforce'] = true
    # user-defined blacklist and whitelist
    security['suid_sgid']['blacklist'] = []
    security['suid_sgid']['whitelist'] = []
    # if this is true, remove any suid/sgid bits from files that were not in the
    # whitelist
    security['suid_sgid']['remove_from_unknown'] = false
    security['suid_sgid']['dry_run_on_unknown'] = false

    # Allow interactive startup (rhel, centos)
    security['init']['prompt'] = true
    # Require root password for single user mode. (rhel, centos)
    security['init']['single'] = false
    security['init']['daemon_umask'] = '027'

    # remove packages with known issues
    security['packages']['clean'] = true
    # list of packages with known issues
    security['packages']['list'] = %w(
      xinetd
      inetd
      ypserv
      telnet-server
      rsh-server
    )

    # SELinux enforcing (enforcing, permissive, unmanaged)
    security['selinux_mode'] = 'unmanaged'

    # SYSTEM CONFIGURATION
    # ====================
    # These are not meant to be modified by the user

    # misc
    security['kernel']['secure_sysrq'] = 4 + 16 + 32 + 64 + 128

    # suid and sgid blacklists and whitelists
    # ---------------------------------------
    # don't change values in the system_blacklist/whitelist
    # adjust values for blacklist/whitelist instead, they can override system_blacklist/whitelist

    # list of suid/sgid entries that must be removed
    security['suid_sgid']['system_blacklist'] = [
      # blacklist as provided by NSA
      '/usr/bin/rcp', '/usr/bin/rlogin', '/usr/bin/rsh',
      # sshd must not use host-based authentication (see ssh cookbook)
      '/usr/libexec/openssh/ssh-keysign',
      '/usr/lib/openssh/ssh-keysign',
      # misc others
      '/sbin/netreport', # not normally required for user
      '/usr/sbin/usernetctl', # modify interfaces via functional accounts
      # connecting to ...
      '/usr/sbin/userisdnctl', # no isdn...
      '/usr/sbin/pppd', # no ppp / dsl ...
      # lockfile
      '/usr/bin/lockfile',
      '/usr/bin/mail-lock',
      '/usr/bin/mail-unlock',
      '/usr/bin/mail-touchlock',
      '/usr/bin/dotlockfile',
      # need more investigation, blacklist for now
      '/usr/bin/arping',
      '/usr/sbin/uuidd',
      '/usr/bin/mtr', # investigate current state...
      '/usr/lib/evolution/camel-lock-helper-1.2', # investigate current state...
      '/usr/lib/pt_chown', # pseudo-tty, needed?
      '/usr/lib/eject/dmcrypt-get-device',
      '/usr/lib/mc/cons.saver' # midnight commander screensaver
    ]

    # list of suid/sgid entries that can remain untouched
    security['suid_sgid']['system_whitelist'] = [
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
      '/usr/bin/Xorg', # xorg
      '/usr/bin/X', # xorg
      '/usr/lib/dbus-1.0/dbus-daemon-launch-helper', # freedesktop ipc
      '/usr/lib/vte/gnome-pty-helper', # gnome
      '/usr/lib/libvte9/gnome-pty-helper', # gnome
      '/usr/lib/libvte-2.90-9/gnome-pty-helper' # gnome
    ]

    # set default cpu vendor
    security['cpu_vendor'] = 'intel'
  end
end
# rubocop:enable Metrics/BlockLength

# auditd config
default['os-hardening']['auditd']['flush'] = 'INCREMENTAL'
default['os-hardening']['auditd']['log_group'] = 'root'
default['os-hardening']['auditd']['priority_boost'] = '4'
default['os-hardening']['auditd']['freq'] = '20'
default['os-hardening']['auditd']['num_logs'] = '5'
default['os-hardening']['auditd']['disp_qos'] = 'lossy'
default['os-hardening']['auditd']['dispatcher'] = '/sbin/audispd'
default['os-hardening']['auditd']['name_format'] = 'NONE'
default['os-hardening']['auditd']['max_log_file'] = '6'
default['os-hardening']['auditd']['tcp_listen_queue'] = '5'
default['os-hardening']['auditd']['tcp_max_per_addr'] = '1'
default['os-hardening']['auditd']['tcp_client_max_idle'] = '0'
default['os-hardening']['auditd']['enable_krb5'] = 'no'
default['os-hardening']['auditd']['krb5_principal'] = 'auditd'
