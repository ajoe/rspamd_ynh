#!/bin/bash

#=================================================
# COMMON VARIABLES AND CUSTOM HELPERS
#=================================================

# Write the DKIM whitelist of the own domains from the comma separated setting
# dkim_whitelist_domains, or remove it when no domain is set
_add_dkim_whitelist_conf() {
    if [[ -z "${dkim_whitelist_domains:-}" ]]; then
        ynh_safe_rm "/etc/rspamd/local.d/whitelist.conf"
        return
    fi
    dkim_whitelist_domains_list=$(echo "$dkim_whitelist_domains" | tr ',' '\n' | sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d' -e 's/.*/"&"/' | paste -sd, | sed 's/,/, /g')
    ynh_config_add --template="rspamd_whitelist.conf" --destination="/etc/rspamd/local.d/whitelist.conf"
    chmod 644 /etc/rspamd/local.d/whitelist.conf
}
