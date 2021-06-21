# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: sysctl
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
#

::Chef::DSL::Recipe.send(:include, SysctlCookbook::SysctlHelpers::Param)

# cleanup of old sysctl related configurations. This can be removed at some point in the future
# https://github.com/dev-sec/chef-os-hardening/issues/166#issuecomment-322433264
# https://github.com/sous-chefs/sysctl/pull/61/files#diff-25e5d4a4446ae12a0d6f1162b6160375
old_sysctl_conf_file = '/etc/sysctl.conf'
if platform_family?('arch', 'debian', 'rhel', 'fedora', 'amazon', 'suse')
  old_sysctl_conf_file = if platform_family?('suse') && node['platform_version'].to_f < 12.0
                           '/etc/sysctl.conf'
                         else
                           '/etc/sysctl.d/99-chef-attributes.conf'
                         end
end

file 'cleanup of old sysctl settings' do
  path old_sysctl_conf_file
  action :delete
end

# default attributes
# We can not set this kind of defaults in the attribute files
# as we react on value of other attributes
# https://github.com/dev-sec/chef-ssh-hardening/issues/140#issuecomment-267779720

# Only enable IP traffic forwarding, if required.
node.default['sysctl']['params']['net']['ipv4']['ip_forward'] =
  node['os-hardening']['network']['forwarding'] ? 1 : 0
node.default['sysctl']['params']['net']['ipv6']['conf']['all']['forwarding'] =
  node['os-hardening']['network']['ipv6']['enable'] && node['os-hardening']['network']['forwarding'] ? 1 : 0

# Disable or Enable IPv6 as it is needed.
node.default['sysctl']['params']['net']['ipv6']['conf']['all']['disable_ipv6'] =
  node['os-hardening']['network']['ipv6']['enable'] ? 0 : 1

# Define different modes for sending replies in response to received ARP requests that resolve local target IP addresses:
#
# * **0** - (default): reply for any local target IP address, configured on
#           any interface
# * **1** - reply only if the target IP address is local address configured
#           on the incoming interface
# * **2** - reply only if the target IP address is local address configured
#           on the incoming interface and both with the sender's IP address are
#           part from same subnet on this interface
# * **3** - do not reply for local addresses configured with scope host, only
#           resolutions for global and link addresses are replied
# * **4-7** - reserved
# * **8** - do not reply for all local addresses
node.default['sysctl']['params']['net']['ipv4']['conf']['all']['arp_ignore'] =
  node['os-hardening']['network']['arp']['restricted'] ? 1 : 0

# Define different restriction levels for announcing the local source IP
# address from IP packets in ARP requests sent on interface:
#
# * **0** - (default) Use any local address, configured on any interface
# * **1** - Try to avoid local addresses that are not in the target's subnet
#           for this interface. This mode is useful when target hosts reachable
#           via this interface require the source IP address in ARP requests to
#           be part of their logical network configured on the receiving
#           interface. When we generate the request we will check all our
#           subnets that include the target IP and will preserve the source
#           address if it is from such subnet. If there is no such subnet we
#           select source address according to the rules for level 2.
# * **2** - Always use the best local address for this target. In this mode
#           we ignore the source address in the IP packet and try to select
#           local address that we prefer for talks with the target host. Such
#           local address is selected by looking for primary IP addresses on
#           all our subnets on the outgoing interface that include the target
#           IP address. If no suitable local address is found we select the
#           first local address we have on the outgoing interface or on all
#           other interfaces, with the hope we will receive reply for our
#           request and even sometimes no matter the source IP address we
#           announce.
#
node.default['sysctl']['params']['net']['ipv4']['conf']['all']['arp_announce'] =
  node['os-hardening']['network']['arp']['restricted'] ? 2 : 0

# This setting controls how the kernel behaves towards module changes at
# runtime. Setting to 1 will disable module loading at runtime.
# Setting it to 0 is actually never supported.
unless node['os-hardening']['security']['kernel']['enable_module_loading']
  node.default['sysctl']['params']['kernel']['modules_disabled'] = 1
end

# Magic Sysrq should be disabled, but can also be set to a safe value if so
# desired for physical machines. It can allow a safe reboot if the system hangs
# and is a 'cleaner' alternative to hitting the reset button.
# The following values are permitted:
#
# * **0**   - disable sysrq
# * **1**   - enable sysrq completely
# * **>1**  - bitmask of enabled sysrq functions:
# * **2**   - control of console logging level
# * **4**   - control of keyboard (SAK, unraw)
# * **8**   - debugging dumps of processes etc.
# * **16**  - sync command
# * **32**  - remount read-only
# * **64**  - signalling of processes (term, kill, oom-kill)
# * **128** - reboot/poweroff
# * **256** - nicing of all RT tasks
node.default['sysctl']['params']['kernel']['sysrq'] =
  node['os-hardening']['security']['kernel']['enable_sysrq'] ? node['os-hardening']['security']['kernel']['secure_sysrq'] : 0

# Prevent core dumps with SUID. These are usually only needed by developers and
# may contain sensitive information.
node.default['sysctl']['params']['fs']['suid_dumpable'] =
  node['os-hardening']['security']['kernel']['enable_core_dump'] ? 2 : 0

if node.attribute?('sysctl') && node['sysctl'].attribute?('params')
  coerce_attributes(node['sysctl']['params']).each do |x|
    k, v = x.split('=')
    sysctl k do
      value v
    end
  end
end

# try to determine the real cpu vendor
begin
  cpu_vendor = node['cpu']['0']['vendor_id']
               .sub(/^.*GenuineIntel.*$/, 'intel')
               .sub(/^.*AuthenticAMD.*$/, 'amd')
  node.default['os-hardening']['security']['cpu_vendor'] = cpu_vendor
rescue # rubocop:disable Style/RescueStandardError
  log 'WARNING: Could not properly determine the cpu vendor. Fallback to intel cpu.' do
    level :warn
  end
end

# protect sysctl.conf
file '/etc/sysctl.conf' do
  mode '0440'
  owner 'root'
  group 'root'
end

# NSA 2.2.4.1 Set Daemon umask
# do config for rhel-family
if platform_family?('rhel', 'fedora', 'amazon')
  template '/etc/sysconfig/init' do
    source 'rhel_sysconfig_init.erb'
    mode '0544'
    owner 'root'
    group 'root'
    variables(
      prompt: node['os-hardening']['security']['init']['prompt'],
      single: node['os-hardening']['security']['init']['single'],
      umask:  node['os-hardening']['security']['init']['daemon_umask']
    )
  end
end

# do initramfs config for ubuntu and debian
if platform_family?('debian')

  # rebuild initramfs with starting pack of modules,
  # if module loading at runtime is disabled
  unless node['os-hardening']['security']['kernel']['enable_module_loading']
    template '/etc/initramfs-tools/modules' do
      source 'modules.erb'
      mode '0440'
      owner 'root'
      group 'root'
      variables(
        x86_64:    !(node['kernel']['machine'] =~ /x86_64/).nil?,
        cpuVendor: node['os-hardening']['security']['cpu_vendor']
      )
    end

    execute 'update-initramfs' do
      command 'update-initramfs -u'
      action :run
    end
  end
end

# CIS requirement: disable unused filesystems
if node['os-hardening']['security']['kernel']['disable_filesystems'].empty?
  file '/etc/modprobe.d/dev-sec.conf' do
    action :delete
  end
else
  template '/etc/modprobe.d/dev-sec.conf' do
    source 'filesystem_blacklisting.erb'
    mode '0440'
    owner 'root'
    group 'root'
    variables filesystems: node['os-hardening']['security']['kernel']['disable_filesystems']
  end
end
