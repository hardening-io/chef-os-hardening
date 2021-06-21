# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: selinux.rv
#
# Copyright:: 2017, Deutsche Telekom AG
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

# SELinux enforcing support

if platform_family?('rhel', 'fedora', 'amazon')
  unless node['os-hardening']['security']['selinux_mode'] == 'unmanaged'
    semode = case node['os-hardening']['security']['selinux_mode']
             when 'enforcing'
               'Enforcing'
             when 'permissive'
               'Permissive'
             else
               raise "Unsupported selinuxmode #{node['os-hardening']['security']['selinux_mode']}"
             end

    execute "Set selinux mode to #{semode}" do
      command "setenforce #{semode}"
      not_if "getenforce | grep -F #{semode}"
    end

    template '/etc/selinux/config' do
      source 'rhel_selinuxconfig.erb'
      mode '0644'
      owner 'root'
      group 'root'
      variables selinux_mode: node['os-hardening']['security']['selinux_mode']
    end
  end
else
  raise "Selinux recipe is not supported on the platform family #{node['platform_family']}"
end
