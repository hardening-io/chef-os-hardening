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

describe 'os-hardening::login_defs' do
  cached(:chef_run) do
    ChefSpec::ServerRunner.new do |node|
      node.normal['os-hardening']['auth']['uid_min'] = 5000
      node.normal['os-hardening']['auth']['uid_max'] = 6000
      node.normal['os-hardening']['auth']['gid_min'] = 5000
      node.normal['os-hardening']['auth']['gid_max'] = 6000
    end.converge(described_recipe)
  end

  subject { chef_run }

  it 'creates /etc/login.defs' do
    is_expected.to create_template('/etc/login.defs').with(
      source:    'login.defs.erb',
      mode:      '0444',
      owner:     'root',
      group:     'root',
      variables: {
        additional_user_paths:    '',
        umask:                    '027',
        password_max_age:         60,
        password_min_age:         7,
        password_warn_age:        7,
        login_retries:            5,
        login_timeout:            60,
        chfn_restrict:            '',
        allow_login_without_home: false,
        uid_min:                  5000,
        uid_max:                  6000,
        gid_min:                  5000,
        gid_max:                  6000,
        sys_uid_min:              100,
        sys_uid_max:              999,
        sys_gid_min:              100,
        sys_gid_max:              999,
        mail_dir:                 '/var/mail',
      }
    )
  end

  it 'uses uid_min and gid_min in /etc/login.defs' do
    is_expected.to render_file('/etc/login.defs')
      .with_content(/^PASS_WARN_AGE\s+7$/)
      .with_content(/^UID_MIN\s+5000$/)
      .with_content(/^UID_MAX\s+6000$/)
      .with_content(/^GID_MIN\s+5000$/)
      .with_content(/^GID_MAX\s+6000$/)
  end
end
