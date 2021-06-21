# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: default
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

# here we try to determine which components should be included.
# You can control the behaviour via setting the node['os-hardening']['components'][recipe_name]
# to true (to include it) or to false (to skip it) on the override level, e.g.
#
# override['os-hardening']['components']['sysctl'] = false
#

node.default['os-hardening']['components']['suid_sgid'] = node['os-hardening']['security']['suid_sgid']['enforce']

# components which are not suitable for containers
unless node['virtualization']['system'] =~ /^(lxc|docker)$/ && node['virtualization']['role'] == 'guest'
  node.default['os-hardening']['components']['sysctl'] = true
  node.default['os-hardening']['components']['auditd'] = true

  # selinux should be included only on RH based systems
  node.default['os-hardening']['components']['selinux'] =
    platform_family?('rhel', 'fedora')
end

# include all required components
node['os-hardening']['components'].each do |component, state|
  include_recipe "#{cookbook_name}::#{component}" if state
end
