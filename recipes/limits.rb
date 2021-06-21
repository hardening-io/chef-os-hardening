# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: limits.rb
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

directory '/etc/security/limits.d' do
  owner 'root'
  group 'root'
  mode '0755'
  recursive true
end

template '/etc/security/limits.d/10.hardcore.conf' do
  source 'limits.conf.erb'
  mode '0440'
  owner 'root'
  group 'root'
  action :delete if node['os-hardening']['security']['kernel']['enable_core_dump']
end
