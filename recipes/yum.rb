# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: pack_yum.rb
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

# NSA chapter: NSA 2.1.2.3.3
# verify package signatures
# search /etc/yum.conf gpgcheck=1
ruby_block 'check package signature in repo files' do
  block do
    # TODO: harmonize with latter function
    config_file = '/etc/yum.conf'
    GPGCheck.check(config_file)

    Dir.glob('/etc/yum.repos.d/*').each do |file|
      GPGCheck.check(file)
    end

    rhn_conf = '/etc/yum/pluginconf.d/rhnplugin.conf'
    File.file?(rhn_conf) do
      GPGCheck.check(rhn_conf)
    end
  end
  action :run
end

if node['os-hardening']['security']['packages']['clean']

  # remove unused repos
  %w(CentOS-Debuginfo CentOS-Media CentOS-Vault).each do |repo|
    yum_repository repo do
      action :remove
    end
  end

  # remove packages
  node['os-hardening']['security']['packages']['list'].each do |pkg|
    package pkg do
      action :purge
    end
  end

end
