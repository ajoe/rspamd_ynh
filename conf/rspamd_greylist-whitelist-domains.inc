# Senders for which greylisting is skipped. Large email service providers
# deliver from big server pools and often retry from a different network, so
# greylisting them risks delaying or losing legitimate mail. (2026-09-16)
#
# rspamd matches these entries against the reverse DNS name of the connecting
# server and its registered domain, NOT against the sender address. Entries are
# therefore the domains the providers' outgoing servers are named after, checked
# against PTR records of their SPF ranges. (2026-10-03: the former sender domains
# like gmail.com, hotmail.com, icloud.com or mailgun.org never matched.)

# Microsoft: Outlook.com, Hotmail, Microsoft 365 (*.outbound.protection.outlook.com)
outlook.com
# Google: Gmail, Google Workspace (mail-*.google.com, *.1e100.net)
google.com
1e100.net
# Yahoo and AOL (*.mail.yahoo.com)
yahoo.com
# Apple iCloud (*.me.com, *.eps.apple.com)
me.com
apple.com

# Email service providers
# SendGrid (*.sendgrid.net)
sendgrid.net
# Mailgun (*.mailgun.net)
mailgun.net
# Mandrill (*.mandrillapp.com)
mandrillapp.com
# Postmark (*.mtasv.net)
mtasv.net
# Salesforce: Marketing Cloud (*.mta.exacttarget.com), core (*.mta.salesforce.com, not verified)
exacttarget.com
salesforce.com
