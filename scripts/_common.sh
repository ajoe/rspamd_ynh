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

# Ensure /var/lib/unbound/root.key exists before running unbound-checkconf.
# The Debian unbound package's postinst does not create it on some releases;
# unbound-checkconf with auto-trust-anchor-file then fails with a fatal error.
_ensure_unbound_root_key() {
    if [[ ! -e "/var/lib/unbound/root.key" ]]; then
        mkdir -p /var/lib/unbound
        ynh_print_info "Fetching the IANA root trust anchor for unbound..."
        local tmp_anchors
        tmp_anchors=$(mktemp)
        if get -q -f "$tmp_anchors" https://data.iana.org/root-anchors/root-anchors.csv 2>/dev/null; then
            # The CSV has columns: zone,name,type,class,ttl,ds-pubkey
            # Take the first DNSKEY record for "ROOT"
            local root_key
            root_key=$(awk -F, '$2=="ROOT" && $3=="DNSKEY" {print $6; exit}' "$tmp_anchors")
            if [[ -n "$root_key" ]]; then
                printf '%s\n' "$root_key" > /var/lib/unbound/root.key
                chmod 644 /var/lib/unbound/root.key
            fi
        fi
        rm -f "$tmp_anchors"
        if [[ ! -s "/var/lib/unbound/root.key" ]]; then
            ynh_die "Could not obtain /var/lib/unbound/root.key (IANA download failed or empty)."
        fi
    fi
}
