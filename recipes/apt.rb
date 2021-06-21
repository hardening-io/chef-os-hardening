# frozen_string_literal: true

#
# Cookbook:: Name: os-hardening
# Recipe: apt.rb
#
# Copyright:: 2015, Hardening Framework Team
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

# apt-get and aptitude check package signatures by default.
# TODO: could check apt.conf to make sure this hasn't been disabled.

if node['os-hardening']['security']['packages']['clean']
  # remove packages and handle virtual packages correctly.
  # this is the same package list as used for the redhat distro family
  node['os-hardening']['security']['packages']['list'].each do |pkg|
    if !AptPackageExtras.virtual_package?(pkg)
      package pkg do
        action :purge
      end
    else
      AptPackageExtras.get_providing_packages(pkg).each do |provider|
        package provider do
          action :purge
        end
      end
    end
  end
end
