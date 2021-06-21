# frozen_string_literal: true

#
# Cookbook:: os-hardening
# Library:: suid_sgid
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

class Chef
  class Recipe
    class SuidSgid
      def self.remove_suid_sgid_from(file)
        unless File.exist?(file)
          Chef::Log.info "suid_sgid: Couldn't find file '#{file}'"
          return
        end

        chmod = Mixlib::ShellOut.new("chmod -s '#{file}'")
        chmod.run_command
        chmod.error!
      end

      def self.find_all_suid_sgid_files(start_at = '/')
        # "find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null"
        # don't limit to one filesystem, go nuts recursively: (ie without -xdev)
        findcmd = "find #{start_at} -path /proc -prune -o \\( -perm -4000 -o -perm -2000 \\) -type f -print 2>/dev/null"
        Chef::Log.info "suid_sgid: findcmd #{findcmd}"
        find = Mixlib::ShellOut.new(findcmd)
        find.run_command
        find.error!
        find.stdout.split("\n")
      end

      def self.remove_suid_sgid_from_blacklist(blacklist)
        blacklist
          .select { |file| File.exist?(file) }
          .each do |file|
            Chef::Log.info "suid_sgid: Blacklist SUID/SGID for '#{file}', removing bit..."
            remove_suid_sgid_from(file)
          end
      end

      def self.remove_suid_sgid_from_unknown(whitelist = [], root = '/', dry_run = false)
        all_suid_sgid_files = find_all_suid_sgid_files(root).reject do |file|
          in_whitelist = whitelist.include?(file)
          Chef::Log.info "suid_sgid: Whitelisted file '#{file}', not altering SUID/SGID bit" if in_whitelist && !dry_run
          in_whitelist
        end

        all_suid_sgid_files.each do |file|
          Chef::Log.info "suid_sgid: SUID/SGID on '#{file}'" + dry_run ? ' (dry_run)' : ', removing bit...'
          remove_suid_sgid_from(file) unless dry_run
        end
      end
    end
  end
end
