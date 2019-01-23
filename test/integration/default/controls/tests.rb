include_controls 'linux-baseline' do
  # skip entropy test, as our short living test VMs usually do not
  # have enough
  skip_control 'os-08'
end
