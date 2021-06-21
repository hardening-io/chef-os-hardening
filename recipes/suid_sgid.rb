# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: suid_sgid
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

# make user-defined blacklist/whitelist override our default lists
sb = node['os-hardening']['security']['suid_sgid']['system_blacklist']
sw = node['os-hardening']['security']['suid_sgid']['system_whitelist']
b = node['os-hardening']['security']['suid_sgid']['blacklist']
w = node['os-hardening']['security']['suid_sgid']['whitelist']

blacklist = (sb - w + b).uniq
whitelist = (sw - b + w).uniq

# root    = "/"
dry_run = node['os-hardening']['security']['suid_sgid']['dry_run_on_unknown']
root = node['os-hardening']['env']['root_path']

# walk the blacklist and remove suid and sgid bits from these items
ruby_block 'remove_suid_from_blacklists' do
  block do
    SuidSgid.remove_suid_sgid_from_blacklist(blacklist)
  end
end

# remove suid bits from unknown, if desired
ruby_block 'remove_suid_from_unknown' do
  block do
    SuidSgid.remove_suid_sgid_from_unknown(whitelist, root, dry_run)
  end
  only_if do
    node['os-hardening']['security']['suid_sgid']['remove_from_unknown'] ||
      node['os-hardening']['security']['suid_sgid']['dry_run_on_unknown']
  end
end
