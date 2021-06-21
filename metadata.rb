# frozen_string_literal: true

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

name 'os-hardening'
maintainer 'Artem Sidorenko'
maintainer_email 'artem@posteo.de'
license 'Apache-2.0'
description 'Installs and configures operating system hardening'
version '4.0.0'
source_url 'https://github.com/dev-sec/chef-os-hardening'
issues_url 'https://github.com/dev-sec/chef-os-hardening/issues'

chef_version '>= 14'

supports 'amazon'
supports 'ubuntu', '>= 16.04'
supports 'debian', '>= 9.0'
supports 'centos', '>= 6.0'
supports 'redhat', '>= 6.0'
supports 'oracle', '>= 6.4'
supports 'fedora', '>= 28.0'
supports 'suse'
supports 'opensuseleap', '>= 42.1'
