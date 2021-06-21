# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: login_defs.rb
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

template '/etc/login.defs' do
  source 'login.defs.erb'
  cookbook node['os-hardening']['auth']['login_defs']['template_cookbook']
  mode '0444'
  owner 'root'
  group 'root'
  variables(
    additional_user_paths:    node['os-hardening']['env']['extra_user_paths'].join(':'), # :/usr/local/games:/usr/games
    umask:                    node['os-hardening']['env']['umask'],
    password_max_age:         node['os-hardening']['auth']['pw_max_age'],
    password_min_age:         node['os-hardening']['auth']['pw_min_age'],
    password_warn_age:        node['os-hardening']['auth']['pw_warn_age'],
    login_retries:            node['os-hardening']['auth']['retries'],
    login_timeout:            node['os-hardening']['auth']['timeout'],
    chfn_restrict:            '', # "rwh"
    allow_login_without_home: node['os-hardening']['auth']['allow_homeless'],
    uid_min:                  node['os-hardening']['auth']['uid_min'],
    uid_max:                  node['os-hardening']['auth']['uid_max'],
    gid_min:                  node['os-hardening']['auth']['gid_min'],
    gid_max:                  node['os-hardening']['auth']['gid_max'],
    sys_uid_min:              node['os-hardening']['auth']['sys_uid_min'],
    sys_uid_max:              node['os-hardening']['auth']['sys_uid_max'],
    sys_gid_min:              node['os-hardening']['auth']['sys_gid_min'],
    sys_gid_max:              node['os-hardening']['auth']['sys_gid_max'],
    mail_dir:                 node['os-hardening']['auth']['maildir']
  )
end
