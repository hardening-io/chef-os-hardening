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

describe 'os-hardening::minimize_access' do
  before do
    stub_command(
      "find /usr/local/sbin  -perm -go+w -type f | wc -l | egrep '^0$'"
    ).and_return(false)
    stub_command(
      "find /usr/local/bin  -perm -go+w -type f | wc -l | egrep '^0$'"
    ).and_return(false)
    stub_command(
      "find /usr/sbin  -perm -go+w -type f | wc -l | egrep '^0$'"
    ).and_return(false)
    stub_command(
      "find /usr/bin  -perm -go+w -type f | wc -l | egrep '^0$'"
    ).and_return(false)
    stub_command(
      "find /sbin  -perm -go+w -type f | wc -l | egrep '^0$'"
    ).and_return(false)
    stub_command(
      "find /bin  -perm -go+w -type f | wc -l | egrep '^0$'"
    ).and_return(false)
  end

  cached(:chef_run) do
    ChefSpec::ServerRunner.new.converge(described_recipe)
  end

  subject { chef_run }

  it 'remove write permission from /usr/local/sbin' do
    is_expected.to run_execute(
      'remove write permission from /usr/local/sbin'
    ).with(command: 'chmod go-w -R /usr/local/sbin')
  end

  it 'remove write permission from /usr/local/bin' do
    is_expected.to run_execute(
      'remove write permission from /usr/local/bin'
    ).with(command: 'chmod go-w -R /usr/local/bin')
  end

  it 'remove write permission from /usr/sbin' do
    is_expected.to run_execute('remove write permission from /usr/sbin').with(
      command: 'chmod go-w -R /usr/sbin'
    )
  end

  it 'remove write permission from /usr/bin' do
    is_expected.to run_execute('remove write permission from /usr/bin').with(
      command: 'chmod go-w -R /usr/bin'
    )
  end

  it 'remove write permission from /sbin' do
    is_expected.to run_execute('remove write permission from /sbin').with(
      command: 'chmod go-w -R /sbin'
    )
  end

  it 'remove write permission from /bin' do
    is_expected.to run_execute('remove write permission from /bin').with(
      command: 'chmod go-w -R /bin'
    )
  end

  it 'creates /etc/shadow' do
    is_expected.to create_file('/etc/shadow').with(
      user:  'root',
      group: 'shadow',
      mode:  '0640'
    )
  end

  it 'creates /etc/su' do
    is_expected.to create_file('/bin/su').with(
      user:  'root',
      group: 'root',
      mode:  '0750'
    )
  end
end
