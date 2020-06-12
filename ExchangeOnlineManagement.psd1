@{
RootModule = 'ExchangeOnlineManagement.psm1'
FunctionsToExport = @('Connect-ExchangeOnline', 'Connect-IPPSSession', 'Disconnect-ExchangeOnline')
ModuleVersion = '1.0.1'
GUID = 'B5ECED50-AFA4-455B-847A-D8FB64140A22'
Author = 'Microsoft Corporation'
CompanyName = 'Microsoft Corporation'
Copyright = '(c) 2020 Microsoft. All rights reserved.'
Description = 'This is a General Availability (GA) release of Exchange Online PowerShell V2 module.
Please check the documentation here - https://aka.ms/exops-docs.
For issues related to the module, contact Microsoft support.'
PowerShellVersion = '3.0'
ProcessorArchitecture = 'AMD64'
CmdletsToExport = @('Get-EXOCasMailbox','Get-EXOMailbox','Get-EXOMailboxFolderPermission','Get-EXOMailboxFolderStatistics','Get-EXOMailboxPermission','Get-EXOMailboxStatistics','Get-EXOMobileDeviceStatistics','Get-EXORecipient','Get-EXORecipientPermission','Get-UserBriefingConfig','Set-UserBriefingConfig')
FileList = @('.\Microsoft.Exchange.Management.AdminApiProvider.dll',
        '.\Microsoft.Exchange.Management.ExoPowershellGalleryModule.dll',
        '.\Microsoft.Exchange.Management.RestApiClient.dll',
        '.\Microsoft.IdentityModel.Clients.ActiveDirectory.dll',
        '.\Microsoft.OData.Client.dll',
        '.\Microsoft.OData.Core.dll',
        '.\Microsoft.OData.Edm.dll',
        '.\Microsoft.Online.CSE.RestApiPowerShellModule.Instrumentation.dll',
        '.\Microsoft.Spatial.dll',
        '.\Newtonsoft.Json.dll',
        '.\System.IO.Abstractions.dll',
        '.\System.Management.Automation.dll',
        '.\license.txt')

PrivateData = @{
    PSData = @{
    # Tags applied to this module. These help with module discovery in online galleries.
    Tags = 'Exchange', 'ExchangeOnline', 'EXO', 'EXOV2', 'Mailbox', 'Management'
    ReleaseNotes = '
---------------------------------------------------------------------------------------------
Whats new in this release:
 
v1.0.1 :
    1. This is the General Availability (GA) version of EXO PowerShell V2 Module. It is stable and ready for being used in production environments.
    2. Get-ExoMobileDeviceStatistics cmdlet now supports Identity parameter.
    3. Improved reliability of session auto-connect in certain cases where script was executing for ~50minutes and threw "Cmdlet not found" error due to a bug in auto-reconnect logic.
    4. Fixed data-type issues of two commonly used attributed "User" and "MailboxFolderUser" for easy migration of scripts.
    5. Enhanced support for filters as it now supports 4 more operators - endswith, contains, not and notlike support. Please check online documentation for attributes which are not supported in filter string.
 
---------------------------------------------------------------------------------------------
Previous Releases:
 
v0.4578.0 :
    1. Added support for configuring Briefing Email for your organization at the user level with "Set-UserBriefingConfig" and "Get-UserBriefingConfig" cmdlets.
    2. Support for session cleanup using Disconnect-ExchangeOnline cmdlet. This cmdlet is V2 equivalent of "Get-PSSession | Remove-PSSession". In addition to cleaning up session object and local files, it also removes access token from cache which is used for authenticating against V2 cmdlets.
    3. You can now use FolderId as identity parameter in Get-ExoMailboxFolderPermission. You can get folderId using Get-MailboxFolder cmdlet. Below are the supported syntax for getting folder permissions -
        a. Get-MailboxFolderPermission -Identity <UPN>:<Folder-Path>
        b. Get-MailboxFolderPermission -Identity <UPN>:\<Folder-Id>
    4. Improved reliability of Get-ExoMailboxStatistics cmdlet as certain request routing errors which led to failures have been resolved
    5. Optimized memory usage when session is created by re-using any existing module with a new session instead of creating a new one every time session is imported
  
v0.4368.1 :
    1. Added support for Exchange Online Protection (EOP) cmdlets using ''Connect-IPPSSession'' cmdlet
    2. Hide announcement banner using ''ShowBanner'' switch. Default value of this switch is $true. Use below syntax to hide the banner
        "Connect-ExchangeOnline -ShowBanner:$false"
    3. Terminate cmdlet execution on client exception
    4. RPS contained various Complex data types which was consciously not supported in EXO cmdlets for improving the performance. Differences in non-complex Data-types between RPS cmdlets and V2 cmdlets has been resolved to allow seamless migration of management scripts.
  
v0.3582.0 :
    1. Support for prefix during session creation
        i. You can create only 1 session at a time which can have prefixed cmdlets.
       ii. Note that the EXO V2 cmdlets will not be prefixed as they already have a prefix ''EXO'' and hence please refrain from using ''EXO'' as a prefix during session creation.
    2. Use EXO V2 cmdlets even if WinRM Basic Auth is disabled on client machine
    3. Identity parameter for V2 cmdlets now supports name and alias as well
        i. Please note that using alias or name slows down the performance of V2 cmdlets and hence it is not recommended to use this option
    4. Fixed issue where data-type of attributes returned by V2 cmdlet was different from Remote PowerShell cmdlets
    5. Fixed bug - Frequent sessions reconnects issue when Connect-ExchangeOnline was invoked with Credentials or UserPrincipalName
   
v0.3555.1 :
    1. Bug fixes and enhancements.
   
v0.3527.4 :
    1. Updated Get-Help.
   
v0.3527.3 :
    1. Added support for managing Exchange for a different tenant using delegation flow.
        Read more here: https://docs.microsoft.com/en-in/powershell/module/exchange/powershell-v2-module/connect-exchangeonline?view=exchange-ps#parameters
    2. Works in tandem with other PowerShell modules in a single PS window
    3. Added support for positional parameters
    4. Date Time field now supports client locale
    5. Fixed Bug : PSCredential getting empty when passed during Connect-ExchangeOnline
    6. Fixed Bug : Client module used to throw error when filter contained $null
    7. Sessions created internal to EXO V2 Module will now have names (Naming pattern : ExchangeOnlineInternalSession_%SomeNumber% )
    8. Fixed Bug : Remote PowerShell cmdlets resulting into intermittent failure due to difference of time between token expiry and PSSession getting Idle.
    9. Major security update
    10. Bug fixes and enhancements
---------------------------------------------------------------------------------------------
'
    LicenseUri="http://aka.ms/azps-license"
    }
}
}