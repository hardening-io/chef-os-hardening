# encoding: utf-8

#
# Cookbook Name: os-hardening
# Recipe: auditd.rb
#
# Copyright 2017, Artem Sidorenko
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

package node['os-hardening']['packages']['auditd']

service "auditd" do
  supports [:start, :stop, :restart, :reload, :status]
  if (node['platform_family'] == 'rhel' && node['platform_version'].to_f >= 7) ||
     (node['platform_family'] == 'fedora' && node['platform_version'].to_f >= 27)
    restart_command 'service auditd restart'
  end 
  action [ :enable ]
end

unless (node['os-hardening']['auditd']['flush'].match(/^INCREMENTAL|INCREMENTAL_ASYNC$/) || 
   node['os-hardening']['auditd']['flush'].empty?)
  Chef::Log.fatal('If specifying a value for auditd flush parameter, must be one of INCREMENTAL or INCREMENTAL_ASYNC')
  raise
end

template '/etc/audit/auditd.conf' do
  source 'auditd.conf.erb'
  mode '0400'
  owner 'root'
  group 'root'
  variables(
    flush: node['os-hardening']['auditd']['flush'],
    log_group: node['os-hardening']['auditd']['log_group'],
    priority_boost: node['os-hardening']['auditd']['priority_boost'],
    freq: node['os-hardening']['auditd']['freq'],
    num_logs: node['os-hardening']['auditd']['num_logs'],
    disp_qos: node['os-hardening']['auditd']['disp_qos'],
    dispatcher: node['os-hardening']['auditd']['dispatcher'],
    name_format: node['os-hardening']['auditd']['name_format'],
    max_log_file: node['os-hardening']['auditd']['max_log_file'],
    tcp_listen_queue: node['os-hardening']['auditd']['tcp_listen_queue'],
    tcp_max_per_addr: node['os-hardening']['auditd']['tcp_max_per_addr'],
    tcp_client_max_idle: node['os-hardening']['auditd']['tcp_client_max_idle'],
    enable_krb5: node['os-hardening']['auditd']['enable_krb5'],
    krb5_principal: node['os-hardening']['auditd']['krb5_principal']
    )
  notifies :restart, 'service[auditd]'
  action :create
end
