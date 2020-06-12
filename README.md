# ExchangeOnlineManagement
A rework of the Exchange Online Management Module as much as possible to use Powershell best practices

# To Use
Copy the .psd1 and .psm1 over the top of your existing ExchangeOnlineManagement module. This is currently only tested with `1.0.1` at the moment.

# New Features
1. `-ShowBanner` is now `-HideBanner` to reflect proper use of `[Switch]` parameters
1. You can specify `$_EXO_SUPPRESSBANNER=$true` in your profile or session to remove the "MOTD" from `Connect-ExchangeOnline`
1. `-CommandName` parameter added to `Connect-ExchangeOnline` to allow you to only import a subset of commands. This can drastically improve the login performance time.
1. No longer pollutes your session with a bunch of `_EXO_` global variables!
1. Extensive cleanup of unnecessary module importing to improve performance and reduce verbosity
1. `Connect-ExchangeOnline` is now idempotent, and will not start a new connection if you already have one unless you specify `-Force` or the connection is in a broken or disconnected state.

## Special Note to the Exchange Team
I very carefully made each commit standalone and annotated. PLEASE CONSIDER cherry-picking some of these commits to the main module, and consider a more open an transparent method of development and issue tracking than just a UserVoice and an email address!