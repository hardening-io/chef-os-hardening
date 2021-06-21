# frozen_string_literal: true

#
# Cookbook:: os-hardening
# Library:: apt_package_extras
#
# Copyright:: 2008, Chef Software, Inc.
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

class Chef
  class Recipe
    class AptPackageExtras
      def self.virtual_package?(package_name)
        # This functionality is based on that in the apt package provider
        # See https://github.com/chef/chef/blob/master/lib/chef/provider/package/apt.rb
        # The provider functionality isn't easily exposed for consumption in other recipes

        policy = Mixlib::ShellOut.new("apt-cache policy '#{package_name}'")
        policy.run_command
        policy.error!

        policy.stdout.each_line do |line|
          case line
          when /^\s{2}Candidate: (.+)$/
            candidate_version = Regexp.last_match[1]
            if candidate_version == '(none)'
              # This may not be an appropriate assumption, but is the same as that used by the apt package provider
              Chef::Log.info("#{package_name} is a virtual package, no candidate version.")
              return true
            else
              Chef::Log.info("#{package_name} is not a virtual package, candidate version is #{candidate_version}.")
              return false
            end
          end
        end
      end

      def self.get_providing_packages(package_name)
        # This functionality is based on that in the apt package provider
        # See https://github.com/chef/chef/blob/master/lib/chef/provider/package/apt.rb
        # The provider functionality isn't easily exposed for consumption in other recipes

        unless virtual_package?(package_name)
          raise "#{package_name} is not a virtual package, cannot remove providing packages."
        end

        showpkg = Mixlib::ShellOut.new("apt-cache showpkg '#{package_name}'")
        showpkg.run_command
        showpkg.error!

        providers = {}

        # Disable rubocop warning to get a build
        showpkg.stdout.rpartition(/Reverse Provides: ?#{$/}/)[2].each_line do |line| # rubocop:disable Style/SpecialGlobalVars
          provider, version = line.split
          providers[provider] = version
          Chef::Log.info("Package #{provider} #{version} provides virtual package #{package_name}")
        end

        if providers.length <= 0
          Chef::Log.warn("There are no providing packages for virtual package #{package_name}.")
        end

        providers.keys
      end
    end
  end
end
