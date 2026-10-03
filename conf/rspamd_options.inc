# /etc/rspamd/local.d/options.inc
# Use the local unbound instead of /etc/resolv.conf (dnsmasq and its public upstreams)
dns {
  nameserver = ["127.0.0.1:5353"];
}

# With redis configured, the longest chain of symbol timeouts is 9s. The stock
# task_timeout of 8s cuts it off and rspamd scores the mail on partial results
task_timeout = 10s;
