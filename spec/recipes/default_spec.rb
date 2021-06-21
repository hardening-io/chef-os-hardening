# frozen_string_literal: true

#
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

describe 'os-hardening::default' do
  # converge
  cached(:chef_run) do
    ChefSpec::ServerRunner.new do |node|
      # sysctl/attributes/default.rb will set the config dir
      # on rhel and debian, but apply requires it for notification
      # therefore we set it manually here
      node.normal['sysctl']['conf_dir'] = '/etc/sysctl.d'
      node.normal['cpu']['0']['vendor_id'] = 'GenuineIntel'
      node.normal['env']['extra_user_paths'] = []

      paths = %w(
        /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin
      ) + node['env']['extra_user_paths']
      paths.each do |folder|
        stub_command(
          "find #{folder}  -perm -go+w -type f | wc -l | egrep '^0$'"
        ).and_return(false)
      end
    end.converge(described_recipe)
  end

  subject { chef_run }

  # check that the recipes are executed
  it 'default should include os-hardening recipes by default' do
    is_expected.to include_recipe 'os-hardening::packages'
    is_expected.to include_recipe 'os-hardening::limits'
    is_expected.to include_recipe 'os-hardening::login_defs'
    is_expected.to include_recipe 'os-hardening::minimize_access'
    is_expected.to include_recipe 'os-hardening::pam'
    is_expected.to include_recipe 'os-hardening::profile'
    is_expected.to include_recipe 'os-hardening::securetty'
    is_expected.to include_recipe 'os-hardening::sysctl'
    is_expected.to include_recipe 'os-hardening::auditd'
  end
end
