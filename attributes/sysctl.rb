# frozen_string_literal: true

#
# Cookbook:: os-hardening
# Attributes:: sysctl
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

# Enable RFC-recommended source validation feature. It should not be used for
# routers on complex networks, but is helpful for end hosts and routers serving
# small networks.
default['sysctl']['params']['net']['ipv4']['conf']['all']['rp_filter'] = 1
default['sysctl']['params']['net']['ipv4']['conf']['default']['rp_filter'] = 1

# Reduce the surface on SMURF attacks. Make sure to ignore ECHO broadcasts,
# which are only required in broad network analysis.
default['sysctl']['params']['net']['ipv4']['icmp_echo_ignore_broadcasts'] = 1

# There is no reason to accept bogus error responses from ICMP, so ignore them
# instead.
default['sysctl']['params']['net']['ipv4']['icmp_ignore_bogus_error_responses'] = 1

# Limit the amount of traffic the system uses for ICMP.
default['sysctl']['params']['net']['ipv4']['icmp_ratelimit'] = 100

# Adjust the ICMP ratelimit to include: ping, dst unreachable, source quench,
# time exceed, param problem, timestamp reply, information reply
default['sysctl']['params']['net']['ipv4']['icmp_ratemask'] = 88089

# Protect against wrapping sequence numbers at gigabit speeds:
default['sysctl']['params']['net']['ipv4']['tcp_timestamps'] = 0

# RFC 1337 fix F1
default['sysctl']['params']['net']['ipv4']['tcp_rfc1337'] = 1

# Syncookies is used to prevent SYN-flooding attacks.
default['sysctl']['params']['net']['ipv4']['tcp_syncookies'] = 1

default['sysctl']['params']['net']['ipv4']['conf']['all']['shared_media'] = 1
default['sysctl']['params']['net']['ipv4']['conf']['default']['shared_media'] = 1

# Accepting source route can lead to malicious networking behavior, so disable
# it if not needed.
default['sysctl']['params']['net']['ipv4']['conf']['all']['accept_source_route'] = 0
default['sysctl']['params']['net']['ipv4']['conf']['default']['accept_source_route'] = 0

# Accepting redirects can lead to malicious networking behavior, so disable
# it if not needed.
default['sysctl']['params']['net']['ipv4']['conf']['all']['accept_redirects'] = 0
default['sysctl']['params']['net']['ipv4']['conf']['default']['accept_redirects'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['all']['accept_redirects'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['accept_redirects'] = 0
default['sysctl']['params']['net']['ipv4']['conf']['all']['secure_redirects'] = 0
default['sysctl']['params']['net']['ipv4']['conf']['default']['secure_redirects'] = 0

# For non-routers: don't send redirects, these settings are 0
default['sysctl']['params']['net']['ipv4']['conf']['all']['send_redirects'] = 0
default['sysctl']['params']['net']['ipv4']['conf']['default']['send_redirects'] = 0

# log martian packets
default['sysctl']['params']['net']['ipv4']['conf']['all']['log_martians'] = 1
default['sysctl']['params']['net']['ipv4']['conf']['default']['log_martians'] = 1

# ipv6 config
# NSA 2.5.3.2.5 Limit Network-Transmitted Configuration
default['sysctl']['params']['net']['ipv6']['conf']['default']['router_solicitations'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['accept_ra_rtr_pref'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['accept_ra_pinfo'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['accept_ra_defrtr'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['autoconf'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['dad_transmits'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['max_addresses'] = 1

# Disable acceptance of router advertisements
#
# * **0**  - do not accept router advertisements
# * **1**  - accept router advertisements if forwarding is disabled
# * **2**  - accept router advertisements even if forwarding is enabled
default['sysctl']['params']['net']['ipv6']['conf']['all']['accept_ra'] = 0
default['sysctl']['params']['net']['ipv6']['conf']['default']['accept_ra'] = 0

# ExecShield protection against buffer overflows
if platform_family?('rhel', 'fedora')
  # on Oracle Linux with UEK it is not available; this helps address UEK on Oracle Linux 6
  is_oracle_uek = (platform?('oracle') && node['kernel']['release'] =~ /^4\..*uek/)

  # on RHEL 7 its enabled per default and can't be disabled
  if node['platform_version'].to_f < 7 && !is_oracle_uek
    default['sysctl']['params']['kernel']['exec-shield'] = 1
  end
end

# Virtual memory regions protection
default['sysctl']['params']['kernel']['randomize_va_space'] = 2
