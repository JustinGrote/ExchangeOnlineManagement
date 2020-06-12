############# Helper Functions Begin #############

    <#
    Details to be printed on the console when the Connect-ExchangeOnline function is run
    #>
    function PrintDetails
    {
        Write-Host -ForegroundColor Yellow ""
        Write-Host -ForegroundColor Yellow "----------------------------------------------------------------------------"
        Write-Host -ForegroundColor Yellow "The module allows access to all existing remote PowerShell (V1) cmdlets in addition to the 9 new, faster, and more reliable cmdlets."
        Write-Host -ForegroundColor Yellow ""
        Write-Host -ForegroundColor Yellow "|--------------------------------------------------------------------------|"
        Write-Host -ForegroundColor Yellow "|    Old Cmdlets                    |    New/Reliable/Faster Cmdlets       |"
        Write-Host -ForegroundColor Yellow "|--------------------------------------------------------------------------|"
        Write-Host -ForegroundColor Yellow "|    Get-CASMailbox                 |    Get-EXOCASMailbox                 |"
        Write-Host -ForegroundColor Yellow "|    Get-Mailbox                    |    Get-EXOMailbox                    |"
        Write-Host -ForegroundColor Yellow "|    Get-MailboxFolderPermission    |    Get-EXOMailboxFolderPermission    |"
        Write-Host -ForegroundColor Yellow "|    Get-MailboxFolderStatistics    |    Get-EXOMailboxFolderStatistics    |"
        Write-Host -ForegroundColor Yellow "|    Get-MailboxPermission          |    Get-EXOMailboxPermission          |"
        Write-Host -ForegroundColor Yellow "|    Get-MailboxStatistics          |    Get-EXOMailboxStatistics          |"
        Write-Host -ForegroundColor Yellow "|    Get-MobileDeviceStatistics     |    Get-EXOMobileDeviceStatistics     |"
        Write-Host -ForegroundColor Yellow "|    Get-Recipient                  |    Get-EXORecipient                  |"
        Write-Host -ForegroundColor Yellow "|    Get-RecipientPermission        |    Get-EXORecipientPermission        |"
        Write-Host -ForegroundColor Yellow "|--------------------------------------------------------------------------|"
        Write-Host -ForegroundColor Yellow ""
        Write-Host -ForegroundColor Yellow "To get additional information, run: Get-Help Connect-ExchangeOnline or check https://aka.ms/exops-docs"
        Write-Host -ForegroundColor Yellow ""
        Write-Host -ForegroundColor Yellow "Send your product improvement suggestions and feedback to exocmdletpreview@service.microsoft.com. For issues related to the module, contact Microsoft support. Don't use the feedback alias for problems or support issues."
        Write-Host -ForegroundColor Yellow "----------------------------------------------------------------------------"
        Write-Host -ForegroundColor Yellow ""
    }

    <#
    .Synopsis Validates a given Uri
    #>
    function Test-Uri
    {
        [CmdletBinding()]
        [OutputType([bool])]
        Param
        (
            # Uri to be validated
            [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
            [string]
            $UriString
        )

        [Uri]$uri = $UriString -as [Uri]

        $null -ne $uri.AbsoluteUri -and $uri.Scheme -eq 'https'
    }

    <#
    .Synopsis Is Cloud Shell Environment
    #>
    function IsCloudShellEnvironment()
    {
        if ((-not (Test-Path env:"ACC_CLOUD")) -or ((get-item env:"ACC_CLOUD").Value -ne "PROD"))
        {
            return $false
        }
        return $true
    }

    <#
    .Synopsis Override Get-PSImplicitRemotingSession function for reconnection
    #>
    function UpdateImplicitRemotingHandler()
    {
        $modules = Get-Module tmp_*

        foreach ($module in $modules)
        {
            [bool]$moduleProcessed = $false
            [string] $moduleUrl = $module.Description
            [int] $queryStringIndex = $moduleUrl.IndexOf("?")

            if ($queryStringIndex -gt 0)
            {
                $moduleUrl = $moduleUrl.SubString(0,$queryStringIndex)
            }

            if ($moduleUrl.EndsWith("/PowerShell-LiveId", [StringComparison]::OrdinalIgnoreCase) -or $moduleUrl.EndsWith("/PowerShell", [StringComparison]::OrdinalIgnoreCase))
            {
                & $module { ${function:Get-PSImplicitRemotingSession} = `
                {
                    param(
                        [Parameter(Mandatory = $true, Position = 0)]
                        [string]
                        $commandName
                    )

                    $shouldRemoveCurrentSession = $false;
                    # Clear any left over PS tmp modules
                    if (($null -ne $SCRIPT:_EXO_PreviousModuleName) -and ($SCRIPT:MyModule.Name -ne $SCRIPT:_EXO_PreviousModuleName)) 
                    {
                        Remove-Module -Name $SCRIPT:_EXO_PreviousModuleName -ErrorAction SilentlyContinue
                        $SCRIPT:_EXO_PreviousModuleName = $null
                    }

                    if (($null -eq $SCRIPT:PSSession) -or ($SCRIPT:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                    {
                        Set-PSImplicitRemotingSession `
                            (& $SCRIPT:GetPSSession `
                                -InstanceId $SCRIPT:PSSession.InstanceId.Guid `
                                -ErrorAction SilentlyContinue )
                    }
                    if ($null -ne $SCRIPT:PSSession)
                    {
                        if ($SCRIPT:PSSession.Runspace.RunspaceStateInfo.State -eq 'Disconnected')
                        {
                            # If we are handed a disconnected session, try re-connecting it before creating a new session.
                            Set-PSImplicitRemotingSession `
                                (& $SCRIPT:ConnectPSSession `
                                    -Session $SCRIPT:PSSession `
                                    -ErrorAction SilentlyContinue)
                        }
                        else
                        {
                            # If there is no active token run the new session flow
                            $hasActiveToken = Test-ActiveToken
                            $sessionIsOpened = $SCRIPT:PSSession.Runspace.RunspaceStateInfo.State -eq 'Opened'
                            if (($hasActiveToken -eq $false) -or ($sessionIsOpened -ne $true))
                            {
                                #If there is no active user token or opened session then ensure that we remove the old session
                                $shouldRemoveCurrentSession = $true;
                            }
                        }
                    }
                    if (($null -eq $SCRIPT:PSSession) -or ($SCRIPT:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened') -or ($shouldRemoveCurrentSession -eq $true))
                    {
                        Write-PSImplicitRemotingMessage ('Creating a new Remote PowerShell session using Modern Authentication for implicit remoting of "{0}" command ...' -f $commandName)
                        if (($isCloudShell = IsCloudShellEnvironment) -eq $false)
                        {
                            $session = New-ExoPSSession -UserPrincipalName $SCRIPT:_EXO_UserPrincipalName -ExchangeEnvironmentName $SCRIPT:_EXO_ExchangeEnvironmentName -ConnectionUri $SCRIPT:_EXO_ConnectionUri -AzureADAuthorizationEndpointUri $SCRIPT:_EXO_AzureADAuthorizationEndpointUri -PSSessionOption $SCRIPT:_EXO_PSSessionOption -Credential $SCRIPT:_EXO_Credential -BypassMailboxAnchoring:$SCRIPT:_EXO_BypassMailboxAnchoring -DelegatedOrg $SCRIPT:_EXO_DelegatedOrganization -Reconnect:$true
                        }
                        else
                        {
                            $session = New-ExoPSSession -ExchangeEnvironmentName $SCRIPT:_EXO_ExchangeEnvironmentName -ConnectionUri $SCRIPT:_EXO_ConnectionUri -AzureADAuthorizationEndpointUri $SCRIPT:_EXO_AzureADAuthorizationEndpointUri -PSSessionOption $SCRIPT:_EXO_PSSessionOption -BypassMailboxAnchoring:$SCRIPT:_EXO_BypassMailboxAnchoring -DelegatedOrg $SCRIPT:_EXO_DelegatedOrganization -Reconnect:$true
                        }

                        if ($null -ne $session)
                        {
                            if ($shouldRemoveCurrentSession -eq $true)
                            {
                                Remove-PSSession $SCRIPT:PSSession
                                $SCRIPT:_EXO_PreviousModuleName = $SCRIPT:MyModule.Name
                            }

                            # Import the latest session to ensure that the next cmdlet call would occur on the new PSSession instance.
                            $PSSessionModuleInfo = Import-PSSession $session -AllowClobber -DisableNameChecking
                            Import-Module $PSSessionModuleInfo.Path -Global -DisableNameChecking -Prefix $SCRIPT:_EXO_Prefix
                            UpdateImplicitRemotingHandler
                            $SCRIPT:PSSession = $session

                            # Remove the old sessions only if there is a new session to connect to
                            RemoveBrokenOrClosedPSSession
                        }
                    }
                    if (($null -eq $SCRIPT:PSSession) -or ($SCRIPT:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                    {
                        throw 'No session has been associated with this implicit remoting module'
                    }

                    return [Management.Automation.Runspaces.PSSession]$SCRIPT:PSSession
                }}
            }
        }
    }

    <#
    .Synopsis Remove broken and closed exchange online PSSessions
    #>
    function RemoveBrokenOrClosedPSSession()
    {
        $psBroken = Get-PSSession | where-object {$_.ConfigurationName -like "Microsoft.Exchange" -and $_.Name -eq "ExchangeOnlineInternalSession*" -and $_.State -like "*Broken*"}
        $psClosed = Get-PSSession | where-object {$_.ConfigurationName -like "Microsoft.Exchange" -and $_.Name -eq "ExchangeOnlineInternalSession*" -and $_.State -like "*Closed*"}

        if ($psBroken.count -gt 0)
        {
            for ($index = 0; $index -lt $psBroken.count; $index++)
            {
                Remove-PSSession -session $psBroken[$index]
            }
        }

        if ($psClosed.count -gt 0)
        {
            for ($index = 0; $index -lt $psClosed.count; $index++)
            {
                Remove-PSSession -session $psClosed[$index]
            }
        }
    }

    <#
    .Synopsis Get all existing online PSSessions
    #>
    function GetExistingPSSession() {
        Get-PSSession | Where-Object {$_.ConfigurationName -like "Microsoft.Exchange" -and $_.Name -like "ExchangeOnlineInternalSession*"}
    }

    <#
    .Synopsis Remove all the existing exchange online PSSessions
    #>
    function RemoveExistingPSSession()
    {
        $existingPSSession = GetExistingPSSession

        if ($existingPSSession.count -gt 0) 
        {
            for ($index = 0; $index -lt $existingPSSession.count; $index++)
            {
                $session = $existingPSSession[$index]
                Remove-PSSession -session $session

                Write-Verbose "Removed the PSSession $($session.Name) connected to $($session.ComputerName)"
            }
        }

        # Clear any left over PS tmp modules
        if ($null -ne $SCRIPT:_EXO_PreviousModuleName)
        {
            Remove-Module -Name $SCRIPT:_EXO_PreviousModuleName -ErrorAction SilentlyContinue
            $SCRIPT:_EXO_PreviousModuleName = $null
        }
    }

    <#
    .SYNOPSIS Extract organization name from UserPrincipalName
    #>
    function Get-OrgNameFromUPN
    {
        param([string] $UPN)
        $fields = $UPN -split '@'
        return $fields[-1]
    }

    <#
    .SYNOPSIS Get the command from the given module
    #>
    function Get-WrappedCommand
    {
        param(
        [string] $CommandName,
        [string] $ModuleName,
        [string] $CommandType)

        $cmd = Get-Command -Name $CommandName -Module $ModuleName -CommandType $CommandType -All
        return $cmd
    }

############# Helper Functions End #############

###### Begin Main ######

function Connect-ExchangeOnline 
{
    [CmdletBinding()]
    param(

        # Connection Uri for the Remote PowerShell endpoint
        [string] $ConnectionUri = '',

        # Azure AD Authorization endpoint Uri that can issue the OAuth2 access tokens
        [string] $AzureADAuthorizationEndpointUri = '',

        # Exchange Environment name
        [Microsoft.Exchange.Management.RestApiClient.ExchangeEnvironment] $ExchangeEnvironmentName = 'O365Default',

        # PowerShell session options to be used when opening the Remote PowerShell session
        [System.Management.Automation.Remoting.PSSessionOption] $PSSessionOption = $null,

        # Switch to bypass use of mailbox anchoring hint.
        [switch] $BypassMailboxAnchoring = $false,

        # Delegated Organization Name
        [string] $DelegatedOrganization = '',

        # Prefix 
        [string] $Prefix = '',

        # Show Banner of Exchange cmdlets Mapping and recent updates
        [switch] $HideBanner,

        #Remove any existing connections and re-establish
        [switch] $Force
    )
    DynamicParam
    {
        if (($isCloudShell = IsCloudShellEnvironment) -eq $false)
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # User Principal Name or email address of the user
            $UserPrincipalName = New-Object System.Management.Automation.RuntimeDefinedParameter('UserPrincipalName', [string], $attributeCollection)
            $UserPrincipalName.Value = ''

            # User Credential to Logon
            $Credential = New-Object System.Management.Automation.RuntimeDefinedParameter('Credential', [System.Management.Automation.PSCredential], $attributeCollection)
            $Credential.Value = $null

            # Switch to collect telemetry on command execution. 
            $EnableErrorReporting = New-Object System.Management.Automation.RuntimeDefinedParameter('EnableErrorReporting', [switch], $attributeCollection)
            $EnableErrorReporting.Value = $false
            
            # Where to store EXO command telemetry data. By default telemetry is stored in the directory "%TEMP%/EXOTelemetry" in the file : EXOCmdletTelemetry-yyyymmdd-hhmmss.csv.
            $LogDirectoryPath = New-Object System.Management.Automation.RuntimeDefinedParameter('LogDirectoryPath', [string], $attributeCollection)
            $LogDirectoryPath.Value = ''

            # Create a new attribute and valiate set against the LogLevel
            $LogLevelAttribute = New-Object System.Management.Automation.ParameterAttribute
            $LogLevelAttribute.Mandatory = $false
            $LogLevelAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $LogLevelAttributeCollection.Add($LogLevelAttribute)
            $LogLevelList = @([Microsoft.Online.CSE.RestApiPowerShellModule.Instrumentation.LogLevel]::Default, [Microsoft.Online.CSE.RestApiPowerShellModule.Instrumentation.LogLevel]::All)
            $ValidateSet = New-Object System.Management.Automation.ValidateSetAttribute($LogLevelList)
            $LogLevel = New-Object System.Management.Automation.RuntimeDefinedParameter('LogLevel', [Microsoft.Online.CSE.RestApiPowerShellModule.Instrumentation.LogLevel], $LogLevelAttributeCollection)
            $LogLevel.Attributes.Add($ValidateSet)

# EXO params start

            # Switch to track perfomance 
            $TrackPerformance = New-Object System.Management.Automation.RuntimeDefinedParameter('TrackPerformance', [bool], $attributeCollection)
            $TrackPerformance.Value = $false

            # Flag to enable or disable showing the number of objects written
            $ShowProgress = New-Object System.Management.Automation.RuntimeDefinedParameter('ShowProgress', [bool], $attributeCollection)
            $ShowProgress.Value = $false

            # Switch to enable/disable Multi-threading in the EXO cmdlets
            $UseMultithreading = New-Object System.Management.Automation.RuntimeDefinedParameter('UseMultithreading', [bool], $attributeCollection)
            $UseMultithreading.Value = $true

            # Pagesize Param
            $PageSize = New-Object System.Management.Automation.RuntimeDefinedParameter('PageSize', [uint32], $attributeCollection)
            $PageSize.Value = 1000

# EXO params end
            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('UserPrincipalName', $UserPrincipalName)
            $paramDictionary.Add('Credential', $Credential)
            $paramDictionary.Add('EnableErrorReporting', $EnableErrorReporting)
            $paramDictionary.Add('LogDirectoryPath', $LogDirectoryPath)
            $paramDictionary.Add('LogLevel', $LogLevel)
            $paramDictionary.Add('TrackPerformance', $TrackPerformance)
            $paramDictionary.Add('ShowProgress', $ShowProgress)
            $paramDictionary.Add('UseMultithreading', $UseMultithreading)
            $paramDictionary.Add('PageSize', $PageSize)
            return $paramDictionary
        }
        else
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # Switch to MSI auth 
            $Device = New-Object System.Management.Automation.RuntimeDefinedParameter('Device', [switch], $attributeCollection)
            $Device.Value = $false

            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Device', $Device)
            return $paramDictionary
        }
    }
    process {

        # Validate parameters
        if (($ConnectionUri -ne '') -and (-not (Test-Uri $ConnectionUri)))
        {
            throw "Invalid ConnectionUri parameter '$ConnectionUri'"
        }
        if (($AzureADAuthorizationEndpointUri -ne '') -and (-not (Test-Uri $AzureADAuthorizationEndpointUri)))
        {
            throw "Invalid AzureADAuthorizationEndpointUri parameter '$AzureADAuthorizationEndpointUri'"
        }
        if (($Prefix -ne '') -and ($Prefix -eq 'EXO'))
        {
            throw "Prefix 'EXO' is a reserved Prefix, please use a different prefix."
        }

        if (-not $_EXO_SuppressBanner -and -not $HideBanner)
        {
            PrintDetails;
        }

        if (($ConnectionUri -ne '') -and ($AzureADAuthorizationEndpointUri -eq ''))
        {
            Write-Host -ForegroundColor Green "Using ConnectionUri:'$ConnectionUri', in the environment:'$ExchangeEnvironmentName'."
        }
        if (($AzureADAuthorizationEndpointUri -ne '') -and ($ConnectionUri -eq ''))
        {
            Write-Host -ForegroundColor Green "Using AzureADAuthorizationEndpointUri:'$AzureADAuthorizationEndpointUri', in the environment:'$ExchangeEnvironmentName'."
        }

        # Keep track of error count at beginning.
        $errorCountAtStart = $SCRIPT:Error.Count;
        $SCRIPT:_EXO_TelemetryFilePath = $null;

        try
        {
            #Clean up any currently broken or closed sessions
            RemoveBrokenOrClosedPSSession

            if (-not $Force -and (GetExistingPSSession)) {
                Write-Warning "You are already connected to an Exchange Session. Please specify -Force if you wish to create a new connection anyways."
                return
            }

            # Cleanup old exchange online PSSessions
            RemoveExistingPSSession
            
            $SCRIPT:_EXO_ExchangeEnvironmentName = $ExchangeEnvironmentName;
            $SCRIPT:_EXO_ConnectionUri = $ConnectionUri;
            $SCRIPT:_EXO_AzureADAuthorizationEndpointUri = $AzureADAuthorizationEndpointUri;
            $SCRIPT:_EXO_PSSessionOption = $PSSessionOption;
            $SCRIPT:_EXO_BypassMailboxAnchoring = $BypassMailboxAnchoring;
            $SCRIPT:_EXO_DelegatedOrganization = $DelegatedOrganization;
            $SCRIPT:_EXO_Prefix = $Prefix;

            if ($isCloudShell -eq $false)
            {
                $SCRIPT:_EXO_UserPrincipalName = $UserPrincipalName.Value;
                $SCRIPT:_EXO_Credential = $Credential.Value;
                $SCRIPT:_EXO_EnableErrorReporting = $EnableErrorReporting.Value;
            }
            else
            {
                $SCRIPT:_EXO_Device = $Device.Value;
            }

            if ($isCloudShell -eq $false)
            {
                $PSSession = New-ExoPSSession -ExchangeEnvironmentName $ExchangeEnvironmentName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -UserPrincipalName $UserPrincipalName.Value -PSSessionOption $PSSessionOption -Credential $Credential.Value -BypassMailboxAnchoring:$BypassMailboxAnchoring -DelegatedOrg $DelegatedOrganization
            }
            else
            {
                $PSSession = New-ExoPSSession -ExchangeEnvironmentName $ExchangeEnvironmentName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -PSSessionOption $PSSessionOption -BypassMailboxAnchoring:$BypassMailboxAnchoring -Device:$Device.Value -DelegatedOrg $DelegatedOrganization
            }

            if ($null -ne $PSSession)
            {
                $PSSessionModuleInfo = Import-PSSession $PSSession -AllowClobber -DisableNameChecking

                # Import the above module globally. This is needed as with using psm1 files, 
                # any module which is dynamically loaded in the nested module does not reflect globally.
                Import-Module $PSSessionModuleInfo.Path -Global -DisableNameChecking -Prefix $Prefix

                UpdateImplicitRemotingHandler

                # If we are configured to collect telemetry, add telemetry wrappers. 
                if ($EnableErrorReporting.Value -eq $true)
                {
                    $FilePath = Add-EXOClientTelemetryWrapper -Organization (Get-OrgNameFromUPN -UPN $UserPrincipalName.Value) -PSSessionModuleName $PSSessionModuleInfo.Name -LogDirectoryPath $LogDirectoryPath.Value
                    $SCRIPT:_EXO_TelemetryFilePath = $FilePath[0]
                    Import-Module $FilePath[1] -DisableNameChecking

                    Push-EXOTelemetryRecord -TelemetryFilePath $SCRIPT:_EXO_TelemetryFilePath -CommandName Connect-ExchangeOnline -CommandParams $PSCmdlet.MyInvocation.BoundParameters -OrganizationName  $SCRIPT:_EXO_ExPSTelemetryOrganization -ScriptName $SCRIPT:_EXO_ExPSTelemetryScriptName  -ScriptExecutionGuid $SCRIPT:_EXO_ExPSTelemetryScriptExecutionGuid

                    # Set the AppSettings
                    Set-ExoAppSettings -ShowProgress $ShowProgress.Value -PageSize $PageSize.Value -UseMultithreading $UseMultithreading.Value -TrackPerformance $TrackPerformance.Value -ExchangeEnvironmentName $ExchangeEnvironmentName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -EnableErrorReporting $true -LogDirectoryPath $LogDirectoryPath.Value -LogLevel $LogLevel.Value
                }
                else 
                {
                    # Set the AppSettings disabling the logging
                    Set-ExoAppSettings -ShowProgress $ShowProgress.Value -PageSize $PageSize.Value -UseMultithreading $UseMultithreading.Value -TrackPerformance $TrackPerformance.Value -ExchangeEnvironmentName $ExchangeEnvironmentName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -EnableErrorReporting $false
                }
            }
        }
        catch
        {
            # If telemetry is enabled, log errors generated from this cmdlet also. 
            if ($EnableErrorReporting.Value -eq $true)
            {
                $errorCountAtProcessEnd = $SCRIPT:Error.Count 

                if ($null -eq $SCRIPT:_EXO_TelemetryFilePath)
                {
                    $SCRIPT:_EXO_TelemetryFilePath = New-EXOClientTelemetryFilePath -LogDirectoryPath $LogDirectoryPath.Value

                    # Set the AppSettings
                    Set-ExoAppSettings -ShowProgress $ShowProgress.Value -PageSize $PageSize.Value -UseMultithreading $UseMultithreading.Value -TrackPerformance $TrackPerformance.Value -ExchangeEnvironmentName $ExchangeEnvironmentName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -EnableErrorReporting $true -LogDirectoryPath $LogDirectoryPath.Value -LogLevel $LogLevel.Value
                }

                # Log errors which are encountered during Connect-ExchangeOnline execution. 
                Write-Warning("Writing Connect-ExchangeOnline error log to " + $SCRIPT:_EXO_TelemetryFilePath)
                Push-EXOTelemetryRecord -TelemetryFilePath $SCRIPT:_EXO_TelemetryFilePath -CommandName Connect-ExchangeOnline -CommandParams $PSCmdlet.MyInvocation.BoundParameters -OrganizationName  $SCRIPT:_EXO_ExPSTelemetryOrganization -ScriptName $SCRIPT:_EXO_ExPSTelemetryScriptName  -ScriptExecutionGuid $SCRIPT:_EXO_ExPSTelemetryScriptExecutionGuid -ErrorObject $SCRIPT:Error -ErrorRecordsToConsider ($errorCountAtProcessEnd - $errorCountAtStart) 
            }

            throw $_
        }
    }
}

function Connect-IPPSSession
{
    [CmdletBinding()]
    param(
        # Connection Uri for the Remote PowerShell endpoint
        [string] $ConnectionUri = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId',

        # Azure AD Authorization endpoint Uri that can issue the OAuth2 access tokens
        [string] $AzureADAuthorizationEndpointUri = 'https://login.windows.net/common',

        # Delegated Organization Name
        [string] $DelegatedOrganization = '',

        # PowerShell session options to be used when opening the Remote PowerShell session
        [System.Management.Automation.Remoting.PSSessionOption] $PSSessionOption = $null,

        # Switch to bypass use of mailbox anchoring hint.
        [switch] $BypassMailboxAnchoring = $false
    )
    DynamicParam
    {
        if (($isCloudShell = IsCloudShellEnvironment) -eq $false)
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # User Principal Name or email address of the user
            $UserPrincipalName = New-Object System.Management.Automation.RuntimeDefinedParameter('UserPrincipalName', [string], $attributeCollection)
            $UserPrincipalName.Value = ''

            # User Credential to Logon
            $Credential = New-Object System.Management.Automation.RuntimeDefinedParameter('Credential', [System.Management.Automation.PSCredential], $attributeCollection)
            $Credential.Value = $null

            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('UserPrincipalName', $UserPrincipalName)
            $paramDictionary.Add('Credential', $Credential)
            return $paramDictionary
        }
        else
        {
            $attributes = New-Object System.Management.Automation.ParameterAttribute
            $attributes.Mandatory = $false

            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($attributes)

            # Switch to MSI auth 
            $Device = New-Object System.Management.Automation.RuntimeDefinedParameter('Device', [switch], $attributeCollection)
            $Device.Value = $false

            $paramDictionary = New-object System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('Device', $Device)
            return $paramDictionary
        }
    }
    process 
    {
        [string]$newUri = $null;

        if (![string]::IsNullOrWhiteSpace($DelegatedOrganization))
        {
            [UriBuilder] $uriBuilder = New-Object -TypeName UriBuilder -ArgumentList $ConnectionUri;
            [string] $queryToAppend = "DelegatedOrg={0}" -f $DelegatedOrganization;
            if ($null -ne $uriBuilder.Query -and $uriBuilder.Query.Length -gt 0)
            {
                [string] $existingQuery = $uriBuilder.Query.Substring(1);
                $uriBuilder.Query = $existingQuery + "&" + $queryToAppend;
            }
            else
            {
                $uriBuilder.Query = $queryToAppend;
            }

            $newUri = $uriBuilder.ToString();
        }
        else
        {
           $newUri = $ConnectionUri;
        }

        if ($isCloudShell -eq $false)
        {
            Connect-ExchangeOnline -ConnectionUri $newUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -UserPrincipalName $UserPrincipalName.Value -PSSessionOption $PSSessionOption -Credential $Credential.Value -BypassMailboxAnchoring:$BypassMailboxAnchoring -ShowBanner:$false
        }
        else
        {
            Connect-ExchangeOnline -ConnectionUri $newUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -PSSessionOption $PSSessionOption -BypassMailboxAnchoring:$BypassMailboxAnchoring -Device:$Device.Value -ShowBanner:$false
        }
    }
}

function Disconnect-ExchangeOnline 
{
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param()

    process {
        if ($PSCmdlet.ShouldProcess(
            "Running this cmdlet clears all active sessions created using Connect-ExchangeOnline or Connect-IPPSSession.",
            "Press(Y/y/A/a) if you want to continue.",
            "Running this cmdlet clears all active sessions created using Connect-ExchangeOnline or Connect-IPPSSession. "))
        {

            # Keep track of error count at beginning.
            $errorCountAtStart = $SCRIPT:Error.Count;

            try
            {
                # Cleanup current exchange online PSSessions
                RemoveExistingPSSession

                # Remove any active access token from the cache
                Clear-ActiveToken

                Write-Host "Disconnected successfully !"

                if ($SCRIPT:_EXO_EnableErrorReporting -eq $true)
                {
                    if ($null -eq $SCRIPT:_EXO_TelemetryFilePath)
                    {
                        $SCRIPT:_EXO_TelemetryFilePath = New-EXOClientTelemetryFilePath
                    }

                    Push-EXOTelemetryRecord -TelemetryFilePath $SCRIPT:_EXO_TelemetryFilePath -CommandName Disconnect-ExchangeOnline -CommandParams $PSCmdlet.MyInvocation.BoundParameters -OrganizationName  $SCRIPT:_EXO_ExPSTelemetryOrganization -ScriptName $SCRIPT:_EXO_ExPSTelemetryScriptName  -ScriptExecutionGuid $SCRIPT:_EXO_ExPSTelemetryScriptExecutionGuid
                }
            }
            catch
            {
                # If telemetry is enabled, log errors generated from this cmdlet also. 
                if ($SCRIPT:_EXO_EnableErrorReporting -eq $true)
                {
                    $errorCountAtProcessEnd = $SCRIPT:Error.Count 

                    if ($null -eq $SCRIPT:_EXO_TelemetryFilePath)
                    {
                        $SCRIPT:_EXO_TelemetryFilePath = New-EXOClientTelemetryFilePath
                    }

                    # Log errors which are encountered during Disconnect-ExchangeOnline execution. 
                    Write-Warning("Writing Disconnect-ExchangeOnline errors to " + $SCRIPT:_EXO_TelemetryFilePath)

                    Push-EXOTelemetryRecord -TelemetryFilePath $SCRIPT:_EXO_TelemetryFilePath -CommandName Disconnect-ExchangeOnline -CommandParams $PSCmdlet.MyInvocation.BoundParameters -OrganizationName  $SCRIPT:_EXO_ExPSTelemetryOrganization -ScriptName $SCRIPT:_EXO_ExPSTelemetryScriptName  -ScriptExecutionGuid $SCRIPT:_EXO_ExPSTelemetryScriptExecutionGuid -ErrorObject $SCRIPT:Error -ErrorRecordsToConsider ($errorCountAtProcessEnd - $errorCountAtStart) 
                }

                throw $_
            }
        }
    }
}