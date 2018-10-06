$script:PolicyAttrs = @('viewDSXACMLSubtreePolicy','viewDSXACMLEntryPolicy','viewDSXACMLRoleCondition','viewDSXACMLVersionExclusion','viewDSXACMLPrecedence','createTimestamp','modifyTimestamp','updatersName','creatorsName','modifiersName','objectClass')
$script:VersionAttrs = @('viewDSXACMLActivePolicy','viewDSXACMLPolicyVersion','createTimestamp','modifyTimestamp','updatersName','creatorsName','modifiersName','objectClass')

Function New-ASConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, HelpMessage="The hostname or IP address of the Access Sentinel instance")][string]$Hostname,
        [Parameter(HelpMessage="The LDAP port to use for Access Sentinel")][int]$Port = 3006,
        [Parameter(Mandatory=$True, HelpMessage="The distinguished name of the user to authenticate with")][string]$UserDN,
        [Parameter(Mandatory=$True, HelpMessage="The password for the user")][String]$Password,
        [Parameter(Mandatory=$True, HelpMessage="The distinguished name of the XACML access control to connect to")][string]$DomainDN
    )

    $LDAPCon = New-LDAPConnection -Hostname $Hostname -Port $Port -Username $UserDN -Password $Password
    if((Get-LDAPObject -Connection $LDAPCon -DN $DomainDN ) -eq $null){
        Throw "Unable to connect to Access Sentinel access control domain"
    }
    
    New-Object -TypeName PSObject -Property @{
        'Hostname'=$Hostname;
        'Port'=$Port;
        'UserDN'=$UserDN;
        'Password'=$Password;
        'DomainDN'=$DomainDN;
        'LDAPCon'=$null;
    }
}
    
Function Read-ASConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, HelpMessage="The file path to read the connection from")][string]$FilePath
    )
    $Connection = (Get-Content -Path $FilePath) | ConvertFrom-Json
    if($Connection -eq $null){
        Throw "Connection object is empty or not present"
    }
    if($Connection.UserDN -eq $null -or $Connection.Password -eq $null){
        Throw "Invalid credential in connection"
    }
    $Connection
}
            
Function Write-ASConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="The name of the file to save the connection information in")][string]$FilePath,
        [Parameter(Mandatory=$True, HelpMessage="The Access Sentinel connection object to write to file")][PSObject]$Connection
    )
        $ConnectionToWrite = $Connection
        $ConnectionToWrite.LDAPCon = $null
        $ConnectionToWrite | ConvertTo-JSON | Out-File $FilePath
    }
            
Function Set-DefaultASConnection {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName="Command", Mandatory=$True, HelpMessage="The hostname or IP address of the Access Sentinel instance")][string]$Hostname,
        [Parameter(ParameterSetName="Command", HelpMessage="The LDAP port to use for Access Sentinel")][int]$Port = 3006,
        [Parameter(ParameterSetName="Command", Mandatory=$True, HelpMessage="The distinguished name of the user to authenticate with")][string]$UserDN,
        [Parameter(ParameterSetName="Command", Mandatory=$True, HelpMessage="The password for the user")][string]$Password,
        [Parameter(ParameterSetName="Command", Mandatory=$True, HelpMessage="The distinguished name of the XACML access control to connect to")][string]$DomainDN,
        [Parameter(ParameterSetName="File", Mandatory=$True, HelpMessage="The name of the file containing the previously saved connection information")][string]$FilePath,
        [Parameter(ParameterSetName="Connection", Mandatory=$True, HelpMessage="The connection object to use as the default connection")][PSObject]$Connection
    )
        if($PsCmdlet.ParameterSetName -eq 'Command') {
            $global:_DefaultASConnection = New-ASConnection -Hostname $Hostname -Port $Port -UserDN $UserDN -Password $Password -DomainDN $DomainDN
        }
        elseif($PsCmdlet.ParameterSetName -eq 'File') {
            $global:_DefaultASConnection = Read-ASConnection -FilePath $FilePath
            $global:_DefaultASConnection.LDAPCon = New-LDAPConnection -Hostname $global:_DefaultASConnection.Hostname -Port $global:_DefaultASConnection.Port -Username $global:_DefaultASConnection.UserDN -Password $global:_DefaultASConnection.Password

        }        
        elseif($PsCmdlet.ParameterSetName -eq 'Connection') {
            $global:_DefaultASConnection = $Connection
        }
        Write-Verbose "Default Hostname: $($global:_DefaultASConnection.Hostname)"
        Write-Verbose "Default Port: $($global:_DefaultASConnection.Port)"
        Write-Verbose "Default UserDN: $($global:_DefaultASConnection.UserDN)"
        Write-Verbose "Default Password: $($global:_DefaultASConnection.Password)"
        Write-Verbose "Default DomainDN: $($global:_DefaultASConnection.DomainDN)"
        $Host.UI.RawUI.WindowTitle = "Access Sentinel $($global:_DefaultASConnection.Hostname) ($($global:_DefaultASConnection.DomainDN))"
    }
    
Function Get-DefaultASConnection {
    if($global:_DefaultASConnection -eq $null){
        Throw "Default Access Sentinel connection has not been set. Use Set-DefaultASConnection."
    }
    if($global:_DefaultASConnection.LDAPCon -eq $null){
        $global:_DefaultASConnection.LDAPCon = New-LDAPConnection -Hostname $global:_DefaultASConnection.Hostname -Port $global:_DefaultASConnection.Port -Username $global:_DefaultASConnection.UserDN -Password $global:_DefaultASConnection.Password
    }
    return $global:_DefaultASConnection;
}

function Get-ASAttributeDefinitions {
    [CmdletBinding()]
    [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection)

    (Get-LDAPObject -Connection ($ASConnection.LDAPCon) -DN ($ASConnection.DomainDN) -filter '(&(cn=XACML Attribute Mappings)(objectClass=accessControlSubEntry))' -Scope Subtree -Attributes @('viewDSXACMLAttributePresentation')).viewDSXACMLAttributePresentation |
        %{_Parse-AttributeString $_}
}

function Export-ASAttributeDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection),
        [Parameter(Position=1, Mandatory=$True, HelpMessage="The name of the file to export the attribute definitions to")][string]$FilePath
    )
    $WrapperObject = @{}
    $WrapperObject.Add('attributes', (Get-ASAttributeDefinitions $ASConnection))
    $WrapperObject | ConvertTo-Json | Out-File -FilePath $FilePath
}

function Import-ASAttributeDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection),
        [Parameter(Position=1, Mandatory=$True, HelpMessage="The name of the file to import the attribute definitions from")][string]$FilePath,
        [Parameter(HelpMessage="Indicates that corresponding attribute definitions should be replaced")][Switch]$Replace
    )
    Throw "Not implemented"
    # Get the existing definitions
    $OldAttrs = Get-ASAttributeDefinitions $ASConnection
    $NewAttrs = (Get-Content -Path $FilePath | ConvertFrom-JSON)
}

Function Add-ASAttributeDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection),
        [Parameter(Position=1, Mandatory=$True, HelpMessage="The display name of the new attribute")][string]$DisplayName,
        [Parameter(Position=2, Mandatory=$True, HelpMessage="The URI of the category for the new attribute")][string]$Category,
        [Parameter(Position=3, Mandatory=$True, HelpMessage="The XACML URI of the new attribute")][string]$Attribute,
        [Parameter(Position=4, Mandatory=$True, HelpMessage="The XACML URI of the data type for the new attribute")][string]$Datatype,
        [Parameter(Position=5, HelpMessage="The LDAP attribute name or OID that the XACML attribute is sourced from")][string]$LDAPAttr
    )
    $AttributeValue = 'displayName "{0}", category "{1}", attribute identifier:"{2}", dataType "{3}"' -f $DisplayName, $Category, $Attribute, $Datatype
    if(-not [string]::IsNullOrEmpty($LDAPAttr)){
        $AttributeValue += ', type {0}' -f $LDAPAttr
    }
    $AttributeValue = '{ ' + $AttributeValue + ' }'
    Write-Verbose "Attribute value: $AttributeValue"
    $Object = Get-LDAPObject -Connection ($ASConnection.LDAPCon) -DN ($ASConnection.DomainDN) -filter '(&(cn=XACML Attribute Mappings)(objectClass=accessControlSubEntry))' -Scope Subtree
    if($Object -eq $null){
        Throw "Failed retrieving existing attribute mappings"
    }
    Set-LDAPObject -Connection ($ASConnection.LDAPCon) -DN $Object.DN -Add @{'viewDSXACMLAttributePresentation'=$AttributeValue}
}

Function Remove-ASAttributeDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection),
        [Parameter(Position=1, Mandatory=$True, HelpMessage="The display name of the attribute definition to remove")][string]$DisplayName
    )
    #Retrieve the attribute definitions and find the one that matches the given $DisplayName
    $AttrDefs = Get-LDAPObject -Connection ($ASConnection.LDAPCon) -DN ($ASConnection.DomainDN) -filter '(&(cn=XACML Attribute Mappings)(objectClass=accessControlSubEntry))' -Scope Subtree -Attributes @('viewDSXACMLAttributePresentation')
    $AttrDefs.viewDSXACMLAttributePresentation | ForEach-Object {
        $AttrDef = $_ # Remember the unparsed value to give to Set-LDAPObject -Remove
        _Parse-AttributeString $AttrDef | Where-Object { $_.displayName -eq $DisplayName } | For-EachObject {
            Write-Verbose ("Removing value '{0}'" -f $AttrDef)
            Set-LDAPObject -Connection ($ASConnection.LDAPCon) -DN ($AttrDefs.DN) -Remove @{'viewDSXACMLAttributePresentation'=$AttrDef}
        }
    }
}
function _Parse-AttributeString {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="An SDUA attribute string")][string]$SDUAString
    )
    $Attribute = @{}
    #
    # N.B. Does not currently handle attribute option: 
    # permittedValues { <comma separated list of quoted strings> }
    #
    $Regex = '{\s*' + 
        'displayName\s+"(?<displayName>[^"]+)"' +
        '\s*,\s*' +
        'category\s+"(?<category>[^"]+)"' + 
        '\s*,\s*' + 
        'attribute\s+(?<idOrSel>(identifier|selector)):"(?<attribute>[^"]+)"' + 
        '\s*,\s*' + 
        'dataType\s+"(?<dataType>[^"]+)"' + 
        '(\s*,\s*type\s+(?<ldapType>[^\s]+))?' +
        '(\s*,\s*mustBePresent\s+(?<mustBePresent>(TRUE|FALSE)))?' + 
        '(\s*,\s*issuerAttribute\s+(?<issuerAttribute>(TRUE|FALSE)))?' + 
        '(\s*,\s*obsolete\s+(?<obsolete>(TRUE|FALSE)))?' + 
        '(\s*,\s*permittedValues\s+{(?<permittedValues>("[^"]*"(\s*,\s*"[^"]*")*)?)})?' +
        '\s*}'

    if([string]::IsNullOrEmpty($SDUAString)){
        Write-Verbose "The set of attribute definitions is empty"
        $null
    }
    elseif($SDUAString -cmatch $Regex) {
        $Attribute.Add('displayName', $Matches['displayName'])
        $Attribute.Add('idOrSel', $Matches['idOrSel'])
        $Attribute.Add('category', $Matches['category'])
        $Attribute.Add('dataType', $Matches['dataType'])
        $Attribute.Add('attribute', $Matches['attribute'])
        if($Matches.ContainsKey('ldapType')){
            $Attribute.Add('ldapType', $Matches['ldapType'])
        }
        if($Matches.ContainsKey('mustBePresent')){
            $Attribute.Add('mustBePresent', $Matches['mustBePresent'])
        }
        if($Matches.ContainsKey('issuerAttribute')){
            $Attribute.Add('issuerAttribute', $Matches['issuerAttribute'])
        }
        if($Matches.ContainsKey('obsolete')){
            $Attribute.Add('obsolete', $Matches['obsolete'])
        }
        if($Matches.ContainsKey('permittedValues')){
            # Strip the redundant spaces and quotes from each value and add it to the values array
            Write-Host "PermittedValues $permittedValues"
            $permittedValues = @();
            $Matches['permittedValues'].Split(",") | %{$permittedValues += $_.Trim().Trim('"')}
            $Attribute.Add('permittedValues', $permittedValues)
        }
    }
    else {
        throw "Failed parsing attribute definition: $SDUAString"
    }
    return New-Object PSObject -Property $Attribute
}

Function Get-ASABACPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection),
        [Parameter(Position=1, HelpMessage="The ID of the rule to get (e.g. urn:uuid:cf4c7fd6-2c85-44fd-8f80-b9752b3a43bc)")][string]$ID
    )
    if([string]::IsNullOrEmpty($ID)){
        $Filter = '(&(objectClass=subentry)(|(objectClass=viewDSXACMLSubtreePolicySubentry)(objectClass=viewDSXACMLEntryPolicySubentry)))'
    }
    else {
        $Filter = "(&(objectClass=subentry)(|(objectClass=viewDSXACMLSubtreePolicySubentry)(objectClass=viewDSXACMLEntryPolicySubentry))(cn=$ID*))"
    }
    Write-Verbose "Domain: $($ASConnection.DomainDN) Filter: $Filter"
    Get-LDAPObject -Connection ($ASConnection.LDAPCon) -DN ($ASConnection.DomainDN) -Filter $Filter -Scope Subtree -Attributes $script:PolicyAttrs | ForEach-Object {
        $Policy = @{}
        # Figure out if it is an entry policy or a subtree policy
        if($_.objectClass.Contains('viewDSXACMLSubtreePolicySubentry')){
            $Policy.Add('Scope', 'Subtree')
            $Policy.Add('PolicyText', $_.viewDSXACMLSubtreePolicy)
        }
        elseif($_.objectClass.Contains('viewDSXACMLEntryPolicySubentry')){
            $Policy.Add('Scope', 'Entry')
            $Policy.Add('PolicyText', $_.viewDSXACMLEntryPolicy)
        }
        else {
            Throw "No policy text found in entry $_"
        }
        $PolicyXML = [xml]($Policy.PolicyText)
        $Policy.Add('Version', $PolicyXML.Policy.Version)
        $Policy.Add('Target', $_.DN.Parent)
        $Policy.Add('Effect', $PolicyXML.Policy.Rule.Effect)
        $Policy.Add('Name', $PolicyXML.Policy.Description)
        $Policy.Add('Description', $PolicyXML.Policy.Rule.Description)
        $Policy.Add('Id', $PolicyXML.Policy.PolicyId)
        return New-Object PSObject -Property $Policy
    }
}

Function Add-ASABACPolicy {
    [CmdletBinding(DefaultParameterSetName="Policy")]
    param (
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection),
        [Parameter(Mandatory=$True, HelpMessage="The DN of the target directory entry")][string]$Target,
        [Parameter(Mandatory=$True, HelpMessage="The scope of the policy, either 'Entry' or 'Subtree'")][ValidateSet('Entry', 'Subtree')][string]$Scope,
        [Parameter(Position=1, Mandatory=$True, ParameterSetName="Policy", HelpMessage="The complete XACML Policy XML text")][string]$PolicyText,
        [Parameter(Position=1, Mandatory=$True, ParameterSetName="Condition", HelpMessage="The XACML Condition XML text")][string]$Condition,
        [Parameter(Mandatory=$True, ParameterSetName="Condition", HelpMessage="The name of the rule to create")][string]$Name,
        [Parameter(Mandatory=$True, ParameterSetName="Condition", HelpMessage="The effect of the rule, either Permit or Deny")][ValidateSet('Permit','Deny')][string]$Effect,
        [Parameter(Mandatory=$True, ParameterSetName="Condition", HelpMessage="The name of the rule to create")][string]$Description = 'Created via LDAP'
    )
    if($PSCmdlet.ParameterSetName -eq 'Policy'){
        # The entire policy text is provided in $PolicyXML. Extract the bits we need to create the directory entry
        $PolicyXML= [xml]$PolicyText
        $ID = $PolicyXML.Policy.PolicyId
        $Version = $PolicyXML.Policy.Version
        $DN = "cn=$ID $Version,$Target"
    } elseif($PSCmdlet.ParameterSetName -eq 'Condition'){
        # Only the condition XML is provided and we have to compose the Policy XML to contain it
        # Get the current open version
#        $CurrentVersion = Get-OpenVersion
        $CurrentVersion = Get-ASActiveVersion
        $ID = "urn:uuid:$(New-Guid)"
        $DN = "cn=$ID $CurrentVersion,$Target"
        $PolicyText = @"
<n0:Policy xmlns:n0="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="$ID" Version="$CurrentVersion" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:ordered-deny-overrides">
    <n0:Description>$Name</n0:Description>
    <n0:PolicyDefaults>
        <n0:XPathVersion>http://www.w3.org/TR/1999/REC-xpath-19991116</n0:XPathVersion>
    </n0:PolicyDefaults>
    <n0:Target/>
    <n0:Rule RuleId="$(New-Guid)" Effect="$Effect">
        <n0:Description>$Description</n0:Description>
        $Condition
    </n0:Rule>
</n0:Policy>
"@
    }
    else {
        Throw "Unexpected parameter set name '$($PSCmdlet.ParameterSetName)'"
    }

    $Entry = @{
        'cn'=$ID;
        'viewDSXACMLPrecedence'='1';
        'subtreeSpecification'='(####)';
    }
    # Set the appropriate attribute based on the scope specified
    if($Scope -eq 'Entry'){
        $Entry.Add('objectClass', @('subentry','viewDSXACMLEntryPolicySubentry'));
        $Entry.Add('viewDSXACMLEntryPolicy', $PolicyText)
    }
    elseif($Scope -eq 'Subtree'){
        $Entry.Add('objectClass', @('subentry','viewDSXACMLSubtreePolicySubentry'));
        $Entry.Add('viewDSXACMLSubtreePolicy', $PolicyText)
    }
    else {
        Throw "Unexpected value for scope '$Scope'"
    }

    Write-Verbose "DN is $DN"
    Write-Verbose (New-Object PSObject -Property $Entry)
    Add-LDAPObject -Connection $ASConnection.LDAPCon -DN $DN -Attributes $Entry
}

Function Remove-ASABACPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection),
        [Parameter(Position=1, HelpMessage="The ID of policy (e.g. urn:uuid:cf4c7fd6-2c85-44fd-8f80-b9752b3a43bc)")][string]$ID
    )

    $Filter = "(&(objectClass=subentry)(|(objectClass=viewDSXACMLSubtreePolicySubentry)(objectClass=viewDSXACMLEntryPolicySubentry))(cn=$ID*))"
    $Entry = Get-LDAPObject -Connection $ASConnection.LDAPCon -DN ($ASConnection.DomainDN) -Scope Subtree -Filter $Filter | Select -First 1
    Write-Verbose "Deleting policy ID $ID, DN is $($_.DN)"
    Remove-LDAPObject -Connection $ASConnection.LDAPCon -DN $_.DN
}

Function Get-ASActiveVersion {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection)
    )
    $Filter = '(&(objectClass=accessControlSubentry)(viewDSXACMLActivePolicy=*))'
    $Entry = Get-LDAPObject -Connection ($ASConnection.LDAPCon) -DN ($ASConnection.DomainDN) -Filter $Filter -Scope Subtree -Attributes @('viewDSXACMLActivePolicy')
    if($Entry -ne $null){
        $Regex = '\{\s*version\s+"(?<issuer>[^"]+)"\s*\}'
        if($Entry.viewDSXACMLActivePolicy[0] -match $Regex){
            return $Matches.issuer
        }
        else {
            Throw "Unexpected active version value $($Entry.viewDSXACMLActivePolicy)"
        }
    }
    else {
        Throw "Could not find accessControlSubentry with active policy"
    }
}

Function Get-ASVersions {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection)
    )
    $Filter = '(&(objectClass=subentry)(viewDSXACMLPolicyVersion=*))'
    $Entry = Get-LDAPObject -Connection ($ASConnection.LDAPCon) -DN ($ASConnection.DomainDN) -Filter $Filter -Scope Subtree -Attributes $script:VersionAttrs
    # The version attribute is multivalued and each value is an SDUA string that looks something like this:
    # { identifer "1.1", issuer "some issuer", locked FALSE, base "1.0" }
    # identifier is mandatory, the others are optional
    $Regex = '\{\s*' +
        'identifier\s+"(?<id>[^"]+)"\s*' +
        '(,\s*issuer\s+"(?<issuer>[^"]+)")?\s*' +
        '(,\s*locked\s+(?<locked>\w+))?\s*' +
        '(,\s*base\s+"(?<base>[^"]+)")?' +
        '\s*\}'

    $Entry.viewDSXACMLPolicyVersion | ForEach-Object {
        # Extract identifier (mandatory string), issuer (optional string), locked (optional bool, and base (optional string).
        if($_ -match $Regex){
            $Version = @{
                'Identifer'=$Matches.id;
                'Issuer'=$Matches.issuer;
                'Locked'=$(if($Matches.locked -eq 'TRUE'){ $true } else { $false });
                'Base'=$Matches.base;
            }
            return New-Object PSObject -Property $Version
        }
        else {
            Throw "Unexpected version identifier $_"
        }
    }
}

Function Lock-ASVersion {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="A connection to the Access Sentinel instance you are managed")][PSObject]$ASConnection = (Get-DefaultASConnection)
    )
}
