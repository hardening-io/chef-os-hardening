#
# Cookbook:: test
# Recipe:: default
#

# We use this test cookbook to initialize the test environment

if platform_family?('debian')
  # Run apt-get update if we are on debian, some images/boxes do not have full package lists
  execute 'apt update' do
    command 'apt-get update'
  end
end
