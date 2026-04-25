-- /etc/rspamd/lua.local.d/custom_spam_rules.lua
-- Custom Lua rules added 2026-04-25 to catch patterns the stock config misses.

----------------------------------------------------------------------
-- 1) From: localpart looks machine-generated
--    Heuristics:
--      a) 4..12 chars, contains a 4+-letter consonant cluster, OR
--      b) 4..12 chars, no real vowel-consonant rhythm and no separator
--    Example matches: "uymawnv", "kqxhvbz", "wprtnmgh"
----------------------------------------------------------------------
local function looks_random(user)
    if not user or #user < 4 or #user > 12 then return false end
    if user:match('[%.%-%+_]') then return false end       -- separators -> probably real
    -- Consonant run of >= 4 (no vowel in 4 consecutive letters)
    if user:match('[bcdfghjklmnpqrstvwxz][bcdfghjklmnpqrstvwxz][bcdfghjklmnpqrstvwxz][bcdfghjklmnpqrstvwxz]') then
        return true
    end
    -- All-consonant short string
    if user:match('^[bcdfghjklmnpqrstvwxz]+$') then return true end
    return false
end

rspamd_config.RANDOM_FROM_LOCALPART = {
    callback = function(task)
        local from = task:get_from('mime')
        if not from or not from[1] or not from[1].user then return false end
        local user = from[1].user:lower()
        if looks_random(user) then
            return true, 1.0, user
        end
        return false
    end,
    score = 3.0,
    description = "From: localpart looks randomly generated",
    group = "header",
}

----------------------------------------------------------------------
-- 2) From: localpart equals a label inside Message-ID's RHS subdomain
--    e.g. From: uymawnv@axertione.click
--         Message-ID: <...@mta.uymawnv.axertione.click>
--    Strong bulk-mailer fingerprint (per-recipient/per-campaign subdomain).
----------------------------------------------------------------------
rspamd_config.MID_RHS_CONTAINS_LOCALPART = {
    callback = function(task)
        local from = task:get_from('mime')
        if not from or not from[1] or not from[1].user then return false end
        local user = from[1].user:lower()
        if #user < 4 then return false end
        local mid = task:get_header('Message-ID')
        if not mid then return false end
        mid = mid:lower():gsub('^<', ''):gsub('>$', '')
        local rhs = mid:match('@(.+)$')
        if not rhs then return false end
        -- Walk subdomain labels
        for label in rhs:gmatch('([^%.]+)') do
            if label == user then
                return true, 1.0, user
            end
        end
        return false
    end,
    score = 3.5,
    description = "From: localpart appears as a Message-ID subdomain label",
    group = "header",
}

----------------------------------------------------------------------
-- 3) Charset / language mismatch
--    Body declares cyrillic charset (windows-1251 / koi8-r) but detected
--    language is western European.
----------------------------------------------------------------------
rspamd_config.CHARSET_LANG_MISMATCH = {
    callback = function(task)
        local parts = task:get_text_parts()
        if not parts then return false end
        for _, p in ipairs(parts) do
            local cs = p:get_charset()
            local lang = p:get_language()
            if cs and lang then
                cs = cs:lower()
                local cyrillic = cs:match('windows%-125[12]')
                              or cs:match('koi8')
                              or cs:match('iso%-8859%-5')
                local western = (lang == 'de' or lang == 'en'
                              or lang == 'fr' or lang == 'es'
                              or lang == 'it' or lang == 'nl'
                              or lang == 'pt')
                if cyrillic and western then
                    return true, 1.0, cs .. '/' .. lang
                end
            end
        end
        return false
    end,
    score = 4.0,
    description = "Cyrillic charset declared but body language is western European",
    group = "mime_types",
}

----------------------------------------------------------------------
-- 4) Message-ID local part matches bulk-MTA pattern
--    Pattern: 20+ chars, contains digits AND uppercase, no dot/dash.
----------------------------------------------------------------------
rspamd_config.MID_BULK_PATTERN = {
    callback = function(task)
        local mid = task:get_header('Message-ID')
        if not mid then return false end
        mid = mid:gsub('^<', ''):gsub('>$', '')
        local lhs = mid:match('^([^@]+)@')
        if not lhs then return false end
        if #lhs >= 20
           and lhs:match('%d')
           and lhs:match('%u')
           and not lhs:match('[%.%-]') then
            return true, 1.0, lhs
        end
        return false
    end,
    score = 2.5,
    description = "Message-ID local part matches bulk-MTA pattern",
    group = "headers",
}

----------------------------------------------------------------------
-- 5) Subject is a single fully-base64-encoded MIME word
----------------------------------------------------------------------
rspamd_config.SUBJECT_FULLY_B64 = {
    callback = function(task)
        local subj = task:get_header_raw('Subject')
        if not subj then return false end
        if subj:match('^=%?[uU][tT][fF]%-8%?[bB]%?[A-Za-z0-9+/=]+%?=%s*$') then
            return true, 1.0
        end
        return false
    end,
    score = 1.5,
    description = "Subject is a single base64-encoded MIME word",
    group = "headers",
}
