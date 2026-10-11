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
# We fetch the IANA root-anchors.xml and extract the base64 DNSKEY PublicKey
# of the most recently valid (validFrom latest) key.
_ensure_unbound_root_key() {
    if [[ -e "/var/lib/unbound/root.key" ]]; then
        return
    fi
    mkdir -p /var/lib/unbound
    ynh_print_info "Fetching the IANA root trust anchor for unbound..."
    local tmp_xml
    tmp_xml=$(mktemp)
    if wget -q -O "$tmp_xml" https://data.iana.org/root-anchors/root-anchors.xml \
       || get -q -f "$tmp_xml" https://data.iana.org/root-anchors/root-anchors.xml; then
        # The XML has multiple <KeyDigest> entries each with a <PublicKey>
        # child on one line. Take the last one (most recently added anchor).
        local root_key
        root_key=$(sed -n 's|.*<PublicKey>\(.*\)</PublicKey>.*|\1|p' "$tmp_xml" | tail -1)
        if [[ -n "$root_key" ]]; then
            printf '%s\n' "$root_key" > /var/lib/unbound/root.key
            chmod 644 /var/lib/unbound/root.key
        fi
    fi
    rm -f "$tmp_xml"
    if [[ ! -s "/var/lib/unbound/root.key" ]]; then
        ynh_die "Could not obtain /var/lib/unbound/root.key (IANA download failed or empty)."
    fi
}
