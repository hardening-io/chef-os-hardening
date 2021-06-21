# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: minimize_access
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

# remove write permissions from path folders ($PATH) for all regular users
# this prevents changing any system-wide command from normal users
paths = %w(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin) + node['os-hardening']['env']['extra_user_paths']
paths.each do |folder|
  execute "remove write permission from #{folder}" do
    command "chmod go-w -R #{folder}"
    not_if "find #{folder}  -perm -go+w -type f | wc -l | egrep '^0$'"
  end
end

# limit access to shadow. On debian family group shadow should be able to read it
# (otherwise screensavers might break etc)
file '/etc/shadow' do
  owner 'root'
  case node['platform_family']
  when 'rhel', 'fedora', 'amazon'
    group 'root'
    mode '0000'
  when 'debian'
    group 'shadow'
    mode '0640'
  else
    group 'root'
    mode '0600'
  end
end

# su must only be accessible to user and group root
file '/bin/su' do
  owner 'root'
  group 'root'
  mode '0750'
  manage_symlink_source true
  not_if { node['os-hardening']['security']['users']['allow'].include?('change_user') }
end

# /var/log should restricted to root or syslog on ubuntu systems
directory '/var/log' do
  owner 'root'
  # ubuntu with containers does not have rsyslog installed and syslog group does not exist
  if platform?('ubuntu') && node['packages']['rsyslog']
    group 'syslog'
  else
    group 'root'
  end
end

# Cron files and folders should not be readable or writable by groups or others
file '/etc/crontab' do
  mode '0600'
  only_if { ::File.exist?('/etc/crontab') }
end

cron_directories = %w(/etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d)
cron_directories.each do |cron_path|
  next unless ::Dir.exist?(cron_path)

  directory cron_path.to_s do
    mode '0700'
  end
end
