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
# We fetch the IANA root-anchors.xml and extract the base64 DNSKEY RDATA
# (the <PublicKey> field) of the most recently added valid anchor, then write
# it in the format unbound expects:
#   <domain> <ttl> <class> <type> <flags> <protocol> <algorithm> <base64>
# The flags/protocol/algorithm values come from the XML <Flags> and <Algorithm>
# elements (not from the base64 itself, which packs them differently).
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
        # Extract the last <KeyDigest> block that has a <PublicKey> child.
        # We need: PublicKey (base64 RDATA), Flags, Algorithm from the XML.
        local pubkey flags algo
        # The last block with a PublicKey is the most recently added anchor.
        # Use awk to capture the whole last block.
        local last_block
        last_block=$(awk '/<KeyDigest[^>]*>/{block=""} {block=block $0 "\n"} /<\/KeyDigest>/{if(block ~ /<PublicKey>/) last=block} END{printf "%s", last}' "$tmp_xml")
        pubkey=$(sed -n 's|.*<PublicKey>\(.*\)</PublicKey>.*|\1|p' <<< "$last_block")
        flags=$(sed -n 's|.*<Flags>\(.*\)</Flags>.*|\1|p' <<< "$last_block")
        algo=$(sed -n 's|.*<Algorithm>\(.*\)</Algorithm>.*|\1|p' <<< "$last_block")
        if [[ -n "$pubkey" && -n "$flags" && -n "$algo" ]]; then
            printf '. 3600 IN DNSKEY %s 3 %s %s\n' "$flags" "$algo" "$pubkey" > /var/lib/unbound/root.key
            chmod 644 /var/lib/unbound/root.key
        fi
    fi
    rm -f "$tmp_xml"
    if [[ ! -s "/var/lib/unbound/root.key" ]]; then
        ynh_die "Could not obtain /var/lib/unbound/root.key (IANA download failed or empty)."
    fi
}
