using namespace System
using namespace System.Collections.Generic
using namespace System.Net
using namespace System.Net.Sockets
using namespace System.Net.Security
using namespace System.Security.Authentication
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

#Requires -Version 7


#region Load format file

$formatFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'TcpConnectionStatus.Format.PS1Xml'

if (Test-Path -Path $PSScriptRoot) { Update-FormatData -PrependPath $formatFilePath }

#endregion


#region Load config data

$tcpPortsJsonFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'ConfigData\TcpPorts.json'
$protocolsJsonFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'ConfigData\Protocols.json'
$commonPortsFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'ConfigData\CommonPorts.txt'
$dnsDefaultPrefixesFilePath = Join-Path $PSScriptRoot -ChildPath '.\ConfigData\DnsDefaultPrefixes.txt'

if (-not(Test-Path -Path $tcpPortsJsonFilePath )) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("JSON configuration file not found in the following path: {0}" -f $tcpPortsJsonFilePath )
    throw $FileNotFoundException
}

if (-not(Test-Path -Path $protocolsJsonFilePath )) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("JSON configuration file not found in the following path: {0}" -f $protocolsJsonFilePath)
    throw $FileNotFoundException
}

if (-not(Test-Path -Path $commonPortsFilePath )) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("Common TCP port file not found in the following path: {0}" -f $commonPortsFilePath)
    throw $FileNotFoundException
}

if (-not(Test-Path -Path $dnsDefaultPrefixesFilePath )) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("Default DNS prefix list not found in the following path: {0}" -f $dnsDefaultPrefixesFilePath)
    throw $FileNotFoundException
}

$tcpPortData = Get-Content -Path $tcpPortsJsonFilePath -Raw | ConvertFrom-Json
$protocolData = Get-Content -Path $protocolsJsonFilePath -Raw | ConvertFrom-Json
[int[]]$tcpCommonPorts = Get-Content -Path $commonPortsFilePath | ForEach-Object { if ([Int]::TryParse($_.Trim(), [ref]$null)) { [int]$_.Trim() } }
$defaultDnsPrefixes = Get-Content -Path $dnsDefaultPrefixesFilePath

$tcpPortAndDescriptionData = @{ }
foreach ($entry in $tcpPortData) {
    if (-not($tcpPortAndDescriptionData.ContainsKey([int]$entry.Port))) {
        $tcpPortAndDescriptionData.Add([int]$entry.port, $entry.description)
    }
}

$protocolList = $protocolData | Select-Object -ExpandProperty protocols

#endregion


#region Class Definitions

$tcpConnectionStatusClassDef = @"
using System;
namespace PSTcpIp
{
    public class TcpConnectionStatus
    {
        public string HostName { get; set; }
        public string IPAddress { get; set; }
        public string SourceAddress { get; set; }
        public Int32 Port { get; set; }
        public string Service { get; set; }
        public bool Connected { get; set; }
        public bool HostNameResolved { get; set; }
    }
}
"@


$tlsStatusDefinition = @"
using System;
using System.Security.Cryptography.X509Certificates;
namespace PSTcpIp
{
    public class TlsInfo
    {
        public string HostName { get; set; }
        public string IPAddress { get; set; }
        public int Port { get; set; }
        public string SerialNumber { get; set; }
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public int CertificateValidityPeriodInYears { get; set; }
        public int CertificateValidityPeriodInDays { get; set; }
        public bool? CertificateIsExpired { get; set; }
        public bool? CertificateVerifies { get; set; }
        public bool? CertificateSubjectMatchesHostName { get; set; }
        public bool? IsWildcardCertificate { get; set; }
        public string SignatureAlgorithm { get; set; }
        public string[] NegotiatedCipherSuites { get; set; }
        public string CipherAlgorithm { get; set; }
        public string CipherStrength { get; set; }
        public string KeyExchangeAlgorithm { get; set; }
        public string StrictTransportSecurity { get; set; }
        public string[] SubjectAlternativeNames { get; set; }
        public bool? Ssl2 { get; set; }
        public bool? Ssl3 { get; set; }
        public bool? Tls { get; set; }
        public bool? Tls11 { get; set; }
        public bool? Tls12 { get; set; }
        public bool? Tls13 { get; set; }
    }
}
"@

Add-Type -TypeDefinition $tcpConnectionStatusClassDef -ReferencedAssemblies System.Net.Primitives -ErrorAction Stop
Add-Type -TypeDefinition $tlsStatusDefinition -ErrorAction Stop

#endregion


#region Private Functions

function Get-SourceAddress([string]$Destination = "8.8.8.8") {
    [string]$sourceAddress = ""

    if ($Destination) {
        [string]$targetIP = ""
        try {
            $targetAddresses = [System.Net.Dns]::GetHostAddresses($Destination)
            $targetIP = $targetAddresses | Select-Object -ExpandProperty IPAddressToString -First 1
        }
        catch {
            return $sourceAddress
        }

        if ($targetIP) {
            if ($IsWindows) {
                $sourceAddress = Find-NetRoute -RemoteIPAddress $targetIP | Select-Object -ExpandProperty IPAddress -First 1
            }
            else {
                try {
                    Get-Command -Name ip -ErrorAction Stop | Out-Null
                    $output = $(ip route get $targetIP)
                    $sourceAddress = $output.Split("src")[1].Split(" ")[1]
                }
                catch {
                    return $sourceAddress
                }
            }
        }
    }

    return $sourceAddress
}

function Get-WebServerCertificate([string]$TargetHost, [int]$Port = 443, [int]$Timeout = 30) {

    $cryptographicExceptionMessage = "Unable to establish TLS session with the following host: {0}." -f $TargetHost
    $CryptographicException = [System.Security.Cryptography.CryptographicException]::new($cryptographicExceptionMessage)

    $getCertScriptBlock = {
        [System.Net.Sockets.TcpClient]$tcpClient = $null
        [System.Net.Security.SslStream]$sslStream = $null
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslCert = $null

        try {
            $tcpClient = [System.Net.Sockets.TcpClient]::new($using:TargetHost, $using:Port)
            $callback = { param($certSender, $cert, $chain, $errors) return $true }
            $sslStream = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, $callback)

            $sslStream.AuthenticateAsClient($using:TargetHost)

            $sslCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)

            if ($null -ne $sslStream) {
                $sslStream.Close()
                $sslStream.Dispose()
            }

            if ($null -ne $tcpClient) {
                $tcpClient.Close()
                $tcpClient.Dispose()
            }

            Write-Output -InputObject $sslCert
        }
        catch {
            throw $CryptographicException
        }
    }

    $certRetrievalJob = Start-Job -ScriptBlock $getCertScriptBlock

    Wait-Job -Job $certRetrievalJob -Timeout $Timeout | Out-Null

    $getCertJobResult = Receive-Job -Job $certRetrievalJob

    Remove-Job -Job $certRetrievalJob -Force

    if ($null -ne $getCertJobResult) {
        return $getCertJobResult
    }
    else {
        [bool]$opensslFound = $null -ne (Get-Command -CommandType Application -Name "openssl" -ErrorAction SilentlyContinue)
        if ($opensslFound) {
            # Build target host and part for connect argument for openssl:
            $targetHostAndPort = "{0}:{1}" -f $TargetHost, $Port

            try {
                # Get the cert:
                $openSslResult = "Q" | openssl s_client -connect $targetHostAndPort 2>$null

                # Parse the relevant base64 cert resulting from openssl:
                $beginString = "BEGIN CERTIFICATE"
                $endString = "END CERTIFICATE"
                $base64CertString = (($openSslResult -join "").Split($beginString)[1].Split($endString)[0]).Replace("-", "")

                # Convert the base64 string to a byte array to be fed to the X509Certificate2 constructor:
                [byte[]]$certBytes = [System.Convert]::FromBase64String($base64CertString)

                # Instantiate the certificate from the deserialized byte array:
                $tlsCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

                # return the TLS cert:
                return $tlsCert
            }
            catch {
                throw $CryptographicException
            }
        }
        else {
            throw $CryptographicException
        }
    }
}

function Invoke-TimedWait {
    [CmdletBinding()]
    [OutputType([void])]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)][Int]$Seconds,
        [Parameter(Mandatory = $true, Position = 1)][String]$Activity
    )
    PROCESS {
        for ($i = $Seconds; $i -ge 0; $i--) {
            $percentComplete = (($Seconds - $i) / $Seconds) * 100
            Write-Progress -Activity "Waiting $Seconds seconds prior to $Activity.." -Status "$i seconds remaining" -PercentComplete $percentComplete
            Start-Sleep -Seconds 1
        }

        Write-Host -Object "Sleep cycle complete. Initiating $Activity now..." -ForegroundColor Cyan
    }
}

#endregion


#region Exported Functions

function Test-TcpConnection {
    <#
    .SYNOPSIS
        Tests TCP connectivity to a remote computer.
    .DESCRIPTION
        The Test-TcpConnection function attempts to establish TCP connectivity to one or more target hosts.
    .PARAMETER DNSHostName
        The target hostname to test TCP connectivity against.
    .PARAMETER Port
        The TCP port to test.
    .PARAMETER Count
        The amount of iterations. Default is 1.
    .PARAMETER Timeout
        The timeout value expressed in milliseconds. The default value is 1200.
    .PARAMETER Quiet
        Returns a boolean result only.
    .PARAMETER ShowConnectedOnly
        Returns only succesful connection results.
    .EXAMPLE
        Test-TcpConnection -DNSHostName 'myserver' -Port 80

        Tests HTTP connectivity on the server 'myserver'.
    .EXAMPLE
        Test-TcpConnection -ComputerName 'mydomaincontroller' -Port 389 -Quiet

        Tests LDAP connectivity on the server 'mydomaincontroller' using the parameter alias ComputerName with a boolean return value.
    .EXAMPLE
        Test-TcpConnection -DNSHostName 'mywebserver' -Port 443 -Count 12

        Tests SSL connectivity on the server 'mywebserver' twelve times as opposed to the default four attempts.
    .EXAMPLE
        Test-TcpConnection -IPAddress 134.170.184.133 -Port 80

        Tests HTTP connectivity to a host with an IPV4 address of 134.170.184.133.
    .EXAMPLE
        @((80..445), (5000..6000)) | % { $ports += $_ }
        Test-TcpConnection -ComputerName 'mywebserver' -Port $ports -Count 1 -Timeout 100

        Scans 'mywebserver' for TCP ports 80 through 445, and 5000 through 6000 with a 100 millisecond timeout.
    .EXAMPLE
        Test-TcpConnection -DNSHostName 'myserver'

        Tests TCP connectivity on the server 'myserver' against a set of common ports.
    .EXAMPLE
        Test-TcpConnection -HostName mywebsite.org -ShowConnectedOnly

        Determine the listening TCP ports on mywebsite.org.
    .EXAMPLE
        #requires -Module ActiveDirectory
        Get-ADComputer -Filter {OperatingSystem -like "*2019*"} | Test-TcpConnection -Port 443 -Timeout 100 -ShowConnectedOnly

        GetS all Windows Server 2019 instances from Active Directory and determine which ones are listening on port 443.
    .EXAMPLE
        #requires -Module ActiveDirectory
        Get-ADDomainController -Filter * | Test-TcpConnection -Port 636 -ShowConnectedOnly | Get-TlsCertificate | Select Subject, NotAfter

        Get an expiration report of LDAPS certificates from Active Directory domain controllers.
    .INPUTS
        System.String

            A string value received by the the DNSHostName parameter.
            This is the hostname of the computer that you wish to test TCP connectivity against.
            This parameter is also accessible by the aliases ComputerName, HostName, and IPAddress.

        System.Int32

            An integer value received by the the Port parameter.
     .OUTPUTS
        PSTcpIp.TcpConnectionStatus, System.Boolean

            By default this cmdlet returns a TcpConnectionStatus object. When you use the Quiet parameter, it returns a Boolean.
     .LINK
        Get-ADDomainController
        Get-ADComputer
        Get-TlsCertificate
        https://github.com/anthonyg-1/PSTcpIp
	#>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([PSTcpIp.TcpConnectionStatus], ParameterSetName = 'Default')]
    [OutputType([System.Boolean], ParameterSetName = 'Quiet')]
    [Alias('ttc')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateLength(1, 250)][Alias('ComputerName', 'HostName', 'IPAddress', 'Name', 'h', 'i')][String[]]$DNSHostName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int[]]$Port,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default', Position = 2)][ValidateRange(1, 100000)][Alias('c')][Int]$Count = 1,
        [Parameter(Mandatory = $true, ParameterSetName = 'Quiet', Position = 2)][Alias('q')][Switch]$Quiet,
        [Parameter(Mandatory = $false, Position = 3)][ValidateRange(1, 2500)][Alias('to')][Int]$Timeout = 1200,
        [Parameter(Mandatory = $false, Position = 4)][Alias('sco', 'sc', 'Connected', 'ShowConnected', 'WhereConnected', 'wc')][Switch]$ShowConnectedOnly
    )
    BEGIN {
        $ipv4Addresses = $null
        $ipv4Address = $null
        $tcpClient = $null
    }
    PROCESS {
        $__ComputerNames = $DNSHostName

        foreach ($__ComputerName in $__ComputerNames) {
            if ($Quiet) {
                $amountOfIterations = 1
            }
            else {
                if ($Count -le 0) {
                    $amountOfIterations = 1
                }
                else {
                    $amountOfIterations = $Count
                }
            }

            try {
                $destination = [System.Net.DNS]::GetHostEntry($__ComputerName) | Select-Object -ExpandProperty HostName
            }
            catch {
                $destination = $__ComputerName
            }

            [boolean]$nameResolved = $false
            try {
                $ipv4Addresses = @(([System.Net.Dns]::GetHostAddresses($__ComputerName)).IPAddressToString)
                $ipv4Address = $ipv4Addresses[0]
                $nameResolved = $true
            }
            catch {
                $ipv4Address = 'Unable to resolve hostname'
                $nameResolved = $false
            }

            for ($i = 1; $i -le $amountOfIterations; $i++) {
                [boolean]$connectionSucceeded = $false

                if (-not($PSBoundParameters.ContainsKey("Port"))) {
                    $__PortNumbers = $tcpCommonPorts
                }
                else {
                    $__PortNumbers = $Port
                }

                $__PortNumbers | ForEach-Object {
                    $__PortNumber = $_

                    $connectionStatusObject = [PSTcpIp.TcpConnectionStatus]::new()

                    if ($nameResolved) {
                        $connectionStatusObject.SourceAddress = Get-SourceAddress -Destination $ipv4Address
                        $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
                        try {
                            ($tcpClient.BeginConnect($ipv4Address, $__PortNumber, $null, $null).AsyncWaitHandle.WaitOne($Timeout)) | Out-Null
                            if ($tcpClient.Connected -eq $true) {
                                $connectionSucceeded = $true
                            }
                            else {
                                $connectionSucceeded = $false
                            }
                        }
                        catch {
                            $connectionSucceeded = $false
                        }
                        finally {
                            $tcpClient.Close()
                            $tcpClient.Dispose()
                        }
                    }
                    else {
                        $connectionStatusObject.SourceAddress = Get-SourceAddress
                    }

                    $connectionStatusObject.HostName = $destination
                    $connectionStatusObject.IPAddress = $ipv4Address

                    $connectionStatusObject.Port = $__PortNumber

                    if ($null -ne ($tcpPortAndDescriptionData.Item($__PortNumber))) {
                        $connectionStatusObject.Service = $tcpPortAndDescriptionData.Item($__PortNumber)
                    }
                    else {
                        $connectionStatusObject.Service = "Unknown"
                    }

                    $connectionStatusObject.Connected = $connectionSucceeded
                    $connectionStatusObject.HostNameResolved = $nameResolved

                    if ($Quiet) {
                        return $connectionSucceeded
                    }
                    else {
                        if (($PSBoundParameters.ContainsKey("ShowConnectedOnly"))) {
                            return ($connectionStatusObject | Where-Object -Property Connected)
                        }
                        else {
                            return $connectionStatusObject
                        }
                    }
                }
            }
        }
    }
    END {
        Remove-Variable -Name tcpClient
        Remove-Variable -Name ipv4Address
        Remove-Variable -Name ipv4Addresses
    }
}


function Get-TlsCertificate {
    <#
        .SYNOPSIS
            Gets a TLS certificate from an endpoint.
        .DESCRIPTION
            Gets a TLS certificate from an endpoint specified as a host name and port or URI.
        .PARAMETER HostName
            The target host to obtain an TLS certificate from.
        .PARAMETER Port
            The port for the target host. This parameter is only applicable when using the HostName parameter. Default value is 443.
        .PARAMETER Uri
            Specifies the Uniform Resource Identifier (URI) of the internet resource to which the request for the TLS certificate is sent. This parameter supports HTTPS only.
        .PARAMETER IncludeChain
            Instructs the function to return the x509 certificate chain for the given certificate as a list starting with the end-entity certificate followed by one or more CA certificates.
        .EXAMPLE
            Get-TlsCertificate -HostName www.mysite.com

            Gets a TLS certificate from www.mysite.com over port 443 (default).
        .EXAMPLE
            Get-TlsCertificate -HostName www.mysite.com -Port 8181

            Gets a TLS certificate from www.mysite.com over port 8181.
        .EXAMPLE
            Get-TlsCertificate -HostName www.mysite.com -Port 443 | Select Thumbprint, Subject, NotAfter | Format-List

            Gets a TLS certificate from www.mysite.com over port 443, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list.
        .EXAMPLE
            Get-TlsCertificate -Uri https://www.mysite.com/default.htm | Select Thumbprint, Subject, NotAfter | Format-List

            Gets a TLS certificate from https://www.mysite.com, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list.
        .EXAMPLE
            Get-TlsCertificate -HostName www.mysite.com -IncludeChain | Select Subject, Thumbprint, NotAfter | Format-List

            Gets a TLS certificate from https://www.mysite.com including the full certificate chain and writes the full chain's thumbprint, and expiration as a list to the console.
        .EXAMPLE
            $targets = "www.mywebsite1.com", "www.mywebsite2.com", "www.mywebsite3.com", "www.mywebsite4.com"
            $targets | Test-TcpConnection -Port 443 -ShowConnectedOnly | Get-TlsCertificate | Select Subject, NotAfter | Format-List

            Attempts to connect to an array of hostnames on TCP port 443 and if the target host is listening obtain the TLS certificate, select the subject and expiration, and output the results as a list.
        .INPUTS
            System.String

                A string value is received by the HostName parameter
        .OUTPUTS
            System.Security.Cryptography.X509Certificates.X509Certificate2
        .LINK
            Test-TcpConnection
            Select-Object
            Format-List
            https://github.com/anthonyg-1/PSTcpIp
    #>
    [CmdletBinding(DefaultParameterSetName = 'HostName')]
    [Alias('gtls', 'gtlsc', 'gssl', 'Get-SslCertificate')]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "Uri")][Alias('u', 'Url')][Uri]$Uri,
        [Parameter(Mandatory = $false, Position = 2)][Alias('ic')][Switch]$IncludeChain
    )
    BEGIN {
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    }
    PROCESS {
        [string]$targetHost = ""
        [string]$targetPort = ""

        if ($PSBoundParameters.ContainsKey("Uri")) {
            if ($Uri -like "https://*") {
                $targetHost = $Uri.Authority
                $targetPort = $Uri.Port
            }
            else {
                $argumentExceptionMessage = "Provided URI is not does not contain the necessary https:// prefix."
                $ArgumentException = New-Object ArgumentException -ArgumentList $argumentExceptionMessage
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }
        else {
            $targetHost = $HostName
            $targetPort = $Port
        }

        $connectionTestResult = Test-TcpConnection -DNSHostName $targetHost -Port $targetPort

        [bool]$isIp = $false
        try {
            [IPAddress]::Parse($targetHost) | Out-Null
            $isIp = $true
        }
        catch {
            $isIp = $false
        }

        if ($isIp) {
            $targetHost = $connectionTestResult.HostName
        }

        if ($null -eq $targetHost) {
            $webExceptionMessage = "Host not specified. Unable to connect."
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Stop
        }

        if ($connectionTestResult.Connected) {
            [X509Certificate2]$sslCert = $null
            [bool]$handshakeSucceeded = $false
            try {
                $sslCert = Get-WebServerCertificate -TargetHost $targetHost -Port $Port
                $handshakeSucceeded = $true
            }
            catch {
                $cryptographicExceptionMessage = $_.Exception.Message
                $CryptographicException = New-Object -TypeName CryptographicException -ArgumentList $cryptographicExceptionMessage
                Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction Continue
            }

            if ($handshakeSucceeded) {
                if ($PSBoundParameters.ContainsKey("IncludeChain")) {
                    $chain = [X509Chain]::new()
                    $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::NoCheck
                    $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::AllowUnknownCertificateAuthority
                    $chain.Build($sslCert) | Out-Null
                    $allCertsInChain = $chain.ChainElements | Select-Object -ExpandProperty Certificate

                    return $allCertsInChain
                }
                else {
                    return $sslCert
                }
            }
        }
        else {
            $webExceptionMessage = "Unable to connect to {0} over the following port: {1}" -f $targetHost, $targetPort
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Continue
        }
    }
}


function Get-HttpResponseHeader {
    <#
    .SYNOPSIS
        Retrieves the response headers from a web endpoint.
    .DESCRIPTION
        Retrieves HTTP response headers from a web endpoint. An HTTP response header is a type of HTTP header that is used in the response that typically contains metadata about the target web endpoint.
    .PARAMETER HostName
        The target host for the web endpoint to get HTTP response headers from.
    .PARAMETER Port
        The port for the target host. This parameter is only applicable when using the HostName parameter. Default value is 443.
    .PARAMETER ProtocolScheme
        Determines whether the request is HTTP or HTTPS. Default value is HTTPS.
    .PARAMETER Uri
        Specifies the Uniform Resource Identifier (URI) of the web endpoint. This parameter is mandatory and can be provided through the pipeline or by property name.
    .PARAMETER AsHashtable
        Instructs the function to return the results as an ordered Hashtable as opposed to the default of PSCustomObject.
    .PARAMETER IncludeTargetInformation
         Instructs the function to also return the target computer's host name, IPv4 address, and target URI.
    .EXAMPLE
        Get-HttpResponseHeader -Uri "https://example.com"

        Retrieves the HTTP response headers from the specified web endpoint.
    .EXAMPLE
        Get-HttpResponseHeader -HostName "example.com"

        Retrieves the HTTP response headers from the specified web endpoint with a hostname of example.com.
    .EXAMPLE
        "https://example.com" | Get-HttpResponseHeader

        Retrieves the HTTP response headers from the web endpoint provided through the pipeline.
    .EXAMPLE
        Get-HttpResponseHeader -HostName "example.com" -IncludeTargetInformation

        Retrieves the HTTP response headers from the specified web endpoint with a hostname of example.com including the host name (as HostName), the resolved IPv4 address (as IPAddress), and the target Uri (as Uri).
    .EXAMPLE
        gwrh -u "https://example.com"

        Retrieves the HTTP response headers from the specified web endpoint.
    .EXAMPLE
        gwrh -h "example.com"

        Retrieves the HTTP response headers from the specified web endpoint hostname of example.com.
    .INPUTS
        System.Uri
    .OUTPUTS
        System.Management.Automation.PSCustomObject or System.Collections.Specialized.OrderedDictionary
    .LINK
        https://developer.mozilla.org/en-US/docs/Glossary/Response_header
        https://github.com/anthonyg-1/PSTcpIp
    #>
    [CmdletBinding(DefaultParameterSetName = 'Uri')]
    [Alias('gwrh')]
    [OutputType([System.Management.Automation.PSCustomObject], [System.Collections.Specialized.OrderedDictionary])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'Name', 'h', 'IPAddress', 'i')][String]$HostName,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 2, ParameterSetName = "HostName")][ValidateSet("HTTP", "HTTPS")][Alias('Scheme', 'ps', 's')][String]$ProtocolScheme = "https",

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0, ParameterSetName = "Uri")][Alias('u')][ValidateNotNullOrEmpty()][System.Uri]$Uri,

        [Parameter(Mandatory = $false,
            Position = 3)][Alias('ht')][Switch]$AsHashtable,

        [Parameter(Mandatory = $false,
            Position = 4)][Alias('IncludeTargetInfo', 'iti')][Switch]$IncludeTargetInformation
    )
    PROCESS {
        [Uri]$targetUri = $Uri
        if ($PSBoundParameters.ContainsKey("HostName")) {

            [bool]$hostNameIsUri = [System.Uri]::IsWellFormedUriString($HostName, 1)
            if ($hostNameIsUri) {
                $argumentExceptionMessage = "Value passed to HostName is a URI. Use the Uri parameter instead."
                $ArgumentException = [ArgumentException]::new($argumentExceptionMessage)
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }

            $uriString = "{0}://{1}:{2}" -f $ProtocolScheme.ToLower(), $HostName, $Port
            $targetUri = [System.Uri]::new($uriString)
        }

        [bool]$isValidUri = [System.Uri]::IsWellFormedUriString($targetUri, 1)

        if (-not($isValidUri)) {
            $ArgumentException = [ArgumentException]::new("Invalid data passed to Uri parameter.")
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        [bool]$canConnect = Test-TcpConnection -DNSHostName $targetUri.DnsSafeHost -Port $targetUri.Port -Quiet
        if ($canConnect) {
            try {
                # Get response headers:
                $responseHeaders = Invoke-WebRequest -Uri $targetUri.AbsoluteUri -AllowInsecureRedirect -SkipCertificateCheck -SkipHttpErrorCheck -ErrorAction Stop | Select-Object -ExpandProperty Headers -ErrorAction Stop

                [System.Collections.Hashtable]$responseHeaderTable = $responseHeaders

                [string]$ipAddress = ""
                if ($PSBoundParameters.ContainsKey("IncludeTargetInformation")) {
                    $ipAddress = Test-TcpConnection -DNSHostName $targetUri.DnsSafeHost -Port $targetUri.Port | Select-Object -ExpandProperty IPAddress

                    $hostName = $targetUri.DnsSafeHost
                    $absoluteUri = $targetUri.AbsoluteUri

                    if (-not($responseHeaderTable.ContainsKey("HostName"))) {
                        $responseHeaderTable.Add("HostName", $hostName)
                    }

                    if (-not($responseHeaderTable.ContainsKey("IPAddress"))) {
                        $responseHeaderTable.Add("IPAddress", $ipAddress)
                    }

                    if (-not($responseHeaderTable.ContainsKey("Uri"))) {
                        $responseHeaderTable.Add("Uri", $absoluteUri)
                    }
                }

                # Create sorted table:
                $sortedHeaders = $responseHeaderTable.GetEnumerator() | Sort-Object -Property Key

                # Create empty sorted hash table and populate (can't send PSCustomObject a table that's has GetEnumerator() called on it:
                $headersToReturn = [ordered]@{}
                $sortedHeaders | ForEach-Object { $headersToReturn.Add($_.Key, $_.Value) }

                # Return collection of headers with header name as key:
                if ($PSBoundParameters.ContainsKey("AsHashtable")) {
                    [System.Collections.Hashtable]$headerCollection = $headersToReturn
                    return $headerCollection
                }
                else {
                    [PSCustomObject]$headerCollection = New-Object -TypeName PSCustomObject -Property $headersToReturn
                    return $headerCollection
                }
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }
        }
        else {
            $webExceptionMessage = "Unable to connect to the following endpoint: $targetUri"
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Stop
        }
    }
}


function Get-TlsInformation {
    <#
        .SYNOPSIS
            Gets TLS protocols, certificate and cipher information against a remote computer running TLS/SSL.
        .DESCRIPTION
            Obtains the negotiated TLS protocols, certificate data (lifetime, validity, subject, serial number, subject alternative names, and other identifiable information, etc.) and cipher information against a remote target running TLS/SSL.
        .PARAMETER HostName
            The target host to get TLS/SSL settings from.
        .PARAMETER Port
            The port for the target host. This parameter is only applicable when using the HostName parameter. Default value is 443.
        .PARAMETER Uri
            Specifies the Uniform Resource Identifier (URI) of the internet resource as an alternative to the HostName and Port parameters. This parameter supports HTTPS only.
        .EXAMPLE
            Get-TlsInformation -HostName mysite.com -Port 443

            Obtains TLS settings on mysite.com against TCP port 443.
        .EXAMPLE
            Get-TlsInformation -Uri "https://www.mysite.com"

            Tests TLS settings on "https://www.mysite.com".
        .EXAMPLE
            $targets = "www.mywebsite1.com", "www.mywebsite2.com", "www.mywebsite3.com", "www.mywebsite4.com"
            $targets | Test-TcpConnection -Port 443 -ShowConnectedOnly | Get-TlsInformation

            Attempts to connect to an array of hostnames on TCP port 443 and if the target host is listening obtain TLS information for the target.
        .EXAMPLE
            Get-TlsStatus -HostName www.mysite.com | Select -Expand SubjectAlternativeNames

            Obtain a list of SANs (Subject Alternative Names) from ww.mysite.com.
        .INPUTS
            System.String

                A string value is received by the HostName parameter
        .OUTPUTS
            PSTcpIp.TlsInfo

                This function returns a TlsInfo object. Example output against "https://www.microsoft.com/en-us" using the Uri parameter:

                HostName                          : www.microsoft.com
                IPAddress                         : 23.47.169.232
                Port                              : 443
                SerialNumber                      : 330003E2CD1066AD8DB81C060800000003E2CD
                Thumbprint                        : E1579BA55125CEC3A78E39F55CF81DA8BFA94F88
                Subject                           : CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, S=WA, C=US
                Issuer                            : CN=Microsoft Azure RSA TLS Issuing CA 07, O=Microsoft Corporation, C=US
                ValidFrom                         : 9/14/2023 1:24:20 PM
                ValidTo                           : 9/8/2024 1:24:20 PM
                CertificateValidityPeriodInYears  : 1
                CertificateValidityPeriodInDays   : 360
                CertificateIsExpired              : False
                CertificateVerifies               : True
                CertificateSubjectMatchesHostName : True
                IsWildcardCertificate             : False
                SignatureAlgorithm                : sha384RSA
                NegotiatedCipherSuites            : {TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
                CipherAlgorithm                   : Aes256
                CipherStrength                    : 256
                KeyExchangeAlgorithm              : ECDH Ephemeral
                StrictTransportSecurity           : Strict-Transport-Security not found in header
                SubjectAlternativeNames           : {wwwqa.microsoft.com, www.microsoft.com, staticview.microsoft.com, i.s-microsoft.comΓÇª}
                Ssl2                              : False
                Ssl3                              : False
                Tls                               : False
                Tls11                             : False
                Tls12                             : True
                Tls13                             : False
        .NOTES
            If StrictTransportSecurity returns "Unable to acquire HSTS value" or "No value specified for strict transport security (HSTS)" with the HostName parameter set, try the fully qualified web address with the Uri parameter.
        .LINK
            Test-TcpConnection
            Select-Object
            Format-List
            https://github.com/anthonyg-1/PSTcpIp
    #>
    [CmdletBinding(DefaultParameterSetName = 'Uri')]
    [Alias('Get-TlsStatus', 'Get-TlsInfo', 'gtlsi', 'gtlss')]
    [OutputType([PSTcpIp.TlsInfo])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "Uri")][Alias('u', 'Url')][Uri]$Uri
    )
    BEGIN {
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    }
    PROCESS {
        [string]$targetHost = ""
        [string]$targetPort = ""
        [string]$targetUri = ""

        if ($PSBoundParameters.ContainsKey("Uri")) {
            if ($Uri -like "https://*") {
                $targetHost = $Uri.Authority
                $targetPort = $Uri.Port
                $targetUri = $Uri
            }
            else {
                $argumentExceptionMessage = "Provided URI is not does not contain the necessary https:// prefix."
                $ArgumentException = New-Object ArgumentException -ArgumentList $argumentExceptionMessage
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }
        else {
            $targetHost = $HostName
            $targetPort = $Port
            $targetUri = "https://{0}:{1}" -f $targetHost, $targetPort
        }

        $connectionTestResult = Test-TcpConnection -DNSHostName $targetHost -Port $targetPort

        [bool]$isIp = $false
        try {
            [IPAddress]::Parse($targetHost) | Out-Null
            $isIp = $true
        }
        catch {
            $isIp = $false
        }

        if ($isIp) {
            $targetHost = $connectionTestResult.HostName
        }

        if ($null -eq $targetHost) {
            $webExceptionMessage = "Host not specified. Unable to connect."
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Stop
        }

        [bool]$canConnect = $connectionTestResult.Connected
        if ($canConnect) {
            $tlsInfo = New-Object -TypeName PSTcpIp.TlsInfo
            $tlsInfo.HostName = $targetHost
            try {
                $tlsInfo.IPAddress = $connectionTestResult.IPAddress
            }
            catch {
                $tlsInfo.IPAddress = $null
            }
            $tlsInfo.Port = $targetPort

            [X509Certificate2]$sslCert = $null
            [bool]$handshakeSucceeded = $false
            try {
                $sslCert = Get-WebServerCertificate -TargetHost $targetHost -Port $targetPort
                $tlsInfo.CertificateVerifies = $sslCert.Verify()
                $tlsInfo.ValidFrom = $sslCert.NotBefore
                $tlsInfo.ValidTo = $sslCert.NotAfter
                $tlsInfo.CertificateValidityPeriodInYears = [Math]::Round((($sslCert.NotAfter - $sslCert.NotBefore).Days * 0.00273973), 1)
                $tlsInfo.CertificateValidityPeriodInDays = ($sslCert.NotAfter - $sslCert.NotBefore).Days
                $tlsInfo.CertificateIsExpired = ($sslCert.NotAfter -le (Get-Date))
                $tlsInfo.SerialNumber = $sslCert.GetSerialNumberString()
                $tlsInfo.Thumbprint = $sslCert.Thumbprint
                $tlsInfo.Subject = $sslCert.Subject
                $tlsInfo.Issuer = $sslCert.Issuer
                $handshakeSucceeded = $true
            }
            catch {
                $cryptographicExceptionMessage = $_.Exception.Message
                $CryptographicException = New-Object -TypeName CryptographicException -ArgumentList $cryptographicExceptionMessage
                Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction Continue
            }

            if ($handshakeSucceeded) {
                # Get HTTP Strict Transport Security values:
                [string]$strictTransportSecurityValue = "No value specified for strict transport security (HSTS)"
                try {
                    [Hashtable]$responseHeaders = Get-HttpResponseHeader -Uri $targetUri -AsHashtable

                    $strictTransportSecurityValue = $responseHeaders['Strict-Transport-Security']

                    if ($strictTransportSecurityValue.Length -lt 1) {
                        $strictTransportSecurityValue = "Strict-Transport-Security not found in header"
                    }
                }
                catch {
                    $strictTransportSecurityValue = "Unable to acquire HSTS value"
                }
                $tlsInfo.StrictTransportSecurity = $strictTransportSecurityValue

                # SECTION  If OS is Windows, the X509Certificate2.Extensions property is populated and thus we can infer SANS from that.
                # Else, we default to openssl to obtain the list of SANs on the retrieved certificate:
                $sansList = @()
                if ($IsWindows) {
                    # Get list of Subject Alternative Names:
                    try {
                        $sansList = ($sslCert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }).format($false).Split(",") | ForEach-Object {
                            $_.Replace("DNS Name=", "").Trim()
                        }
                    }
                    catch {
                        $sansList += "Subject alternative names not found on this certificate."
                    }
                }
                else {
                    $opensslFound = $null -ne (Get-Command -CommandType Application -Name "openssl" -ErrorAction SilentlyContinue)
                    if ($opensslFound) {
                        $sansList = (($sslCert.ExportCertificatePem() | openssl x509 -noout -text 2>$null | Select-String -Pattern "DNS:") -split ",") | ForEach-Object {
                            $_.Replace("DNS:", "").Trim()
                        }
                    }
                    else {
                        $opensslNotFoundWarning = "The openssl binary was not found. SubjectAlternativeNames will not be populated."
                        Write-Warning -Message $opensslNotFoundWarning
                    }
                }
                $tlsInfo.SubjectAlternativeNames = $sansList
                #!SECTION

                # SECTION Obtain a list of SANs and cert subject to determine if the certificate subject matches the target host name:
                [Nullable[Boolean]]$certSubjectMatchesHostName = $null

                $validHostNames = [List[String]]::new()

                $parsedCertSubject = (($sslCert.Subject).Split(",")[0].Replace("CN=", "")).Trim()

                $validHostNames = [List[String]]::new()
                foreach ($san in $sansList) {
                    if (-not($validHostNames.Contains($san))) {
                        $validHostNames.Add($san)
                    }
                }
                if (-not($validHostNames.Contains($parsedCertSubject))) {
                    $validHostNames.Add($parsedCertSubject)
                }

                if (-not($isIp)) {
                    if ($targetHost -in $validHostNames) {
                        $certSubjectMatchesHostName = $true
                    }
                    else {
                        $certSubjectMatchesHostName = $false
                    }
                }

                $tlsInfo.CertificateSubjectMatchesHostName = $certSubjectMatchesHostName

                # Determine if certificate is a wildcard certifcate from cert subject and SANs:
                [bool]$isWildcard = $false
                foreach ($name in $validHostNames) {
                    if ($name.StartsWith("*")) {
                        $isWildcard = $true
                        break
                    }
                }

                $tlsInfo.IsWildcardCertificate = $isWildcard

                #!SECTION

                $negotiatedCipherSuites = @()
                foreach ($protocol in $protocolList) {
                    $socket = [Socket]::new([SocketType]::Stream, [ProtocolType]::Tcp)
                    $socket.Connect($targetHost, $targetPort)

                    try {
                        $netStream = [NetworkStream]::new($socket, $true)
                        $callback = { param($certSender, $cert, $chain, $errors) return $true }
                        $sslStream = [SslStream]::new($netStream, $false, $callback)

                        $sslStream.AuthenticateAsClient($targetHost, $null, $protocol, $false)

                        $tlsInfo.SignatureAlgorithm = $sslCert.SignatureAlgorithm.FriendlyName
                        $tlsInfo.$protocol = $true

                        if ($negotiatedCipherSuites -notcontains $sslStream.NegotiatedCipherSuite) {
                            $negotiatedCipherSuites += $sslStream.NegotiatedCipherSuite
                        }

                        if (-not($tlsInfo.CipherAlgorithm)) {
                            $tlsInfo.CipherAlgorithm = $sslStream.CipherAlgorithm
                        }

                        if (-not($tlsInfo.CipherStrength)) {
                            $tlsInfo.CipherStrength = $sslStream.CipherStrength
                        }
                        if (-not($tlsInfo.KeyExchangeAlgorithm)) {
                            if ($sslStream.KeyExchangeAlgorithm.ToString() -eq "44550") {
                                $tlsInfo.KeyExchangeAlgorithm = "ECDH Ephemeral"
                            }
                            else {
                                $tlsInfo.KeyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm.ToString()
                            }
                        }
                    }
                    catch {
                        if ($null -eq $sslCert.SignatureAlgorithm) {
                            $tlsInfo.$protocol = $null
                        }
                        else {
                            $tlsInfo.$protocol = $false
                        }
                    }
                    finally {
                        if ($sslStream) {
                            $sslStream.Close()
                            $sslStream.Dispose()
                        }

                        if ($socket) {
                            $socket.Close()
                            $socket.Dispose()
                        }
                    }
                }
                $tlsInfo.NegotiatedCipherSuites = $negotiatedCipherSuites

                return $tlsInfo
            }
        }
        else {
            $webExceptionMessage = "Unable to connect to {0} over the following port: {1}" -f $targetHost, $targetPort
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Continue
        }
    }
}


function Invoke-DnsEnumeration {
    <#
    .SYNOPSIS
        Performs a DNS enumeration for the specified domain.
    .DESCRIPTION
        The Invoke-DnsEnumeration function retrieves record data for a given domain and its subdomains.
    .PARAMETER Domain
        Specifies the domain to perform DNS enumeration on.
    .PARAMETER WordListPath
        Specifies the path to a word list that contains a list of subdomains and/or hosts to check against the domain.
    .EXAMPLE
        Invoke-DnsEnumeration -Domain "mydomain.org"

        Enumerates DNS record data from the mydomain.org DNS domain.
    .EXAMPLE
        Invoke-DnsEnumeration -Domain mydomain.org -WordListPath subdomains.txt

        Enumerates DNS record data from the mydomain.org DNS domain using the subdomains.txt text file as input.
    .EXAMPLE
        Invoke-DnsEnumeration -Domain mydomain.org | Test-TcpConnection -Port 80,443 -ShowConnectedOnly

        Enumerates DNS record data from the mydomain.org DNS domain, tests connectivity to TCP port 443, and returns only the hosts that are listening on ports 80 and 443.
    .EXAMPLE
        Invoke-DnsEnumeration -Domain mydomain.org | Test-TcpConnection -Port 443 -ShowConnectedOnly | Get-TlsInformation

        Enumerates DNS record data from the mydomain.org DNS domain, tests connectivity to TCP port 443, and obtains to obtain TLS information about the endpoint.
    .EXAMPLE
        Invoke-DnsEnumeration -Domain mydomain.com | Test-TcpConnection -Port 443 -ShowConnectedOnly | Get-TlsInformation |
            Select HostName, IPAddress, Subject, Issuer, CertificateIsExpired, ValidFrom, ValidTo |
                Export-Csv TlsCertificateExpirationReport.csv

        Enumerates DNS record data from the mydomain.org DNS domain, tests connectivity to TCP port 443, obtains to obtain TLS information about the endpoint, and generates an export report as a CSV file.
    .LINK
        Test-TcpConnection
        Get-TlsInformation
        https://github.com/anthonyg-1/PSTcpIp
#>
    [CmdletBinding()]
    [Alias('idnse', 'dnse')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(1, 255)][Alias('d')][System.String]$Domain,

        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][Alias('wl', 'Path')][System.IO.FileInfo]$WordListPath
    )
    BEGIN {
        function _queryDnsDomain([string]$dnsDomain) {
            # Query record data:
            try {
                $ips = [System.Net.Dns]::GetHostAddresses($dnsDomain) | ForEach-Object { $_.IPAddressToString }
                if ($ips.Count -ne 0) {
                    foreach ($ip in $ips) {
                        ([PSCustomObject]@{
                            'HostName'  = $dnsDomain
                            'IPAddress' = $ip
                        })
                    }
                }
            }
            catch {} # Have to swallow exceptions to allow enumeration
        }
    }
    PROCESS {
        # Load subdomains from WordListPath if provided:
        $subdomains = @()
        if ($PSBoundParameters.ContainsKey("WordListPath")) {
            $subdomains = Get-Content -Path $WordListPath
        }
        else {
            $subdomains = $defaultDnsPrefixes
        }

        # Primary domain query:
        _queryDnsDomain $Domain

        # Subdomains/hosts query:
        foreach ($prefix in $subdomains) {
            _queryDnsDomain "$prefix.$Domain"
        }
    }
}


function Get-IPInformation {
    <#
    .SYNOPSIS
        Returns information for a specified IP address.
    .DESCRIPTION
        Returns geolocation and hosting information for a specified IP address by calling the whatismyip.com REST API. This function requires an API key from whatismyip.com. For more on this, see the .NOTES section.
    .EXAMPLE
        #requires -Module Microsoft.PowerShell.SecretManagement
        $secretName = 'whatismyip_api_key'
        $key = Get-Secret -Name $secretName -AsPlainText
        $targetIPAddress = "13.107.213.36"
        Get-IPInformation -IPAddress $targetIPAddress -ApiKey $key

        Obtains IP address geolocation data for 13.107.213.36
    .EXAMPLE
        #requires -Module Microsoft.PowerShell.SecretManagement
        $PSDefaultParameterValues = @{
            "Get-IPInformation:ApiKey"=(Get-Secret -Name 'whatismyip_api_key'-AsPlainText)
        }
        $targetIPAddress = "13.107.213.36"
        Get-IPInformation -IPAddress $targetIPAddress

        Define default value for ApiKey param to be stored in the users profile defined in $PROFILE and obtains IP address geolocation data for 13.107.213.36.
    .PARAMETER IPAddress
        The IP address to obtain for.
    .PARAMETER ApiKey
        The whatismyip.com REST API key.
    .NOTES
        In order to obtain an API key for this function, please see the following: https://members.whatismyip.com/api/
    .LINK
        Get-Secret
        https://members.whatismyip.com/api
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parameters_default_values
    #>
    [CmdletBinding()]
    [Alias('gipi', 'Get-IPAddressInformation')]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)][Alias('ip', 'i')][String]$IPAddress,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1)][Alias('Secret', 'k', 'ak', 's')][String]$ApiKey

    )

    BEGIN {
        $activity = "whatismyip.com REST API call"
        $timeToWaitInSeconds = 60

        [Uri]$baseUri = "https://api.whatismyip.com/ip-address-lookup.php"

    }
    PROCESS {
        [string]$stringIPAddress = ""
        try {
            $stringIPAddress = [System.Net.IPAddress]::Parse($IPAddress).IPAddressToString
        }
        catch {
            $argExcepMessage = "Invalid data was passed to the IPAddress parameter."
            $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $argExcepMessage
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        $url = "{0}?key={1}&input={2}" -f $baseUri.AbsoluteUri, $ApiKey, $stringIPAddress

        try {
            Invoke-TimedWait -Activity $activity -Seconds $timeToWaitInSeconds

            $responses = Invoke-RestMethod -Method Get -Uri $url -SkipCertificateCheck -ErrorAction Stop

            $responses | ForEach-Object {
                $ht = @{}
                $rows = $_.Split("`r`n")

                $rows | ForEach-Object {
                    $columns = $_.Split(":")

                    $prop = $columns[0]
                    $value = $columns[1]

                    if ($prop.Length -ge 1) {
                        $ht.Add($prop, $value)
                    }
                }
                $individualRecord = [PSCustomObject]$ht
                return $individualRecord
            }
        }
        catch {
            if ($null -ne $_.Exception.InnerException) {
                Write-Error -Exception $_.Exception.InnerException -Category InvalidOperation -ErrorAction Continue
            }
            else {
                Write-Error -Exception $_.Exception -Category InvalidOperation -ErrorAction Continue
            }
        }
    }
}


function Invoke-WebCrawl {
    <#
    .SYNOPSIS
        Invokes a web crawl starting from a specified base URI, traversing links up to a specified depth, and optionally including or excluding specific hosts.
    .DESCRIPTION
        The Invoke-WebCrawl function performs a web crawl starting from the provided base URI. It traverses links up to the specified depth and can include or exclude specific hosts based on the provided parameters. The function outputs a custom object for each visited link, containing the URI, hostname, status code, and status description.
    .PARAMETER BaseUri
        The base URI from which the web crawl starts. This parameter is mandatory.
    .PARAMETER Depth
        The depth to which the web crawl should traverse links. The default value is 2. This parameter is optional.
    .PARAMETER Headers
        A hashtable of headers to include to as a hash table. Note that this header collection is for the base URI only, not crawled sites from discovered links. This parameter is optional.
    .PARAMETER IncludeHosts
        An array of hostnames to include in the web crawl. If specified, only links to these hosts will be followed. This parameter is mandatory if the "Include" parameter set is used.
    .PARAMETER ExcludeHosts
        An array of hostnames to exclude from the web crawl. If specified, links to these hosts will not be followed. This parameter is mandatory if the "Exclude" parameter set is used.
    .PARAMETER IncludeContent
        If specified, the website content is returned as a System.String. This parameter is optional.
    .EXAMPLE
        Invoke-WebCrawl -BaseUri "https://example.com" -Depth 3

        Starts a web crawl from "https://example.com" and traverses links up to a depth of 3.
    .EXAMPLE
        Invoke-WebCrawl -BaseUri "https://example.com" -IncludeHosts "example.com", "sub.example.com"

        Starts a web crawl from "https://example.com", traverses links up to a default depth of 2, and includes only links to "example.com" and "sub.example.com".
    .EXAMPLE
        Invoke-WebCrawl -BaseUri "https://example.com" -ExcludeHosts "unwanted.com"

        Starts a web crawl from "https://example.com", traverses links up to a default depth of 2, and excludes links to "unwanted.com".
    .EXAMPLE
        Invoke-WebCrawl -BaseUri "https://example.com" | Where-Object ResponseHeaders -Match "Server=nginx"

        Starts a web crawl from "https://example.com", traverses links up to a default depth of 2, and returns results that have a server response header indicating a server of nginx.
    .EXAMPLE
        Invoke-WebCrawl -BaseUri "https://example.com" -Depth 3 | Where ResponseHeaders -NotMatch "Server=AkamaiNetStorage"

        Starts a web crawl from "https://example.com", traverses links up to a depth of 3, and returns results that do not have a server response header of AkamaiNetStorage.
    .EXAMPLE
        $keywords = @(
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "auth_code",
        "bearer",
        "cert",
        "certificate",
        "credential",
        "id_token",
        "jwt",
        "key",
        "login",
        "oauth",
        "password",
        "secret",
        "session",
        "sso",
        "token",
        "username"
        )

        $crawlResults = Invoke-WebCrawl -BaseUri "https://example.com" -IncludeContent

        foreach ($word in $keywords) {
            $Keyword = @{n = "Keyword"; e = { $word } }
            $regExMatch = '\b{0}\b' -f $word
            $crawlResults | Where Content -match $regExMatch | Select Uri, $Keyword
        }

        Defines a list of common authentication and credential keywords, crawl the target site, determine if any of the keywords exist in the content for each crawled page, and return the URI and keyword.
    .INPUTS
        System.Uri

            A System.Uri value is received by the BaseUri parameter.
    .OUTPUTS
        PSCustomObject

            Outputs a custom object containing the following properties:
            - BaseUri: The base URI from which the web crawl started.
            - Uri: The URI of the visited link.
            - HostName: The hostname of the visited link.
            - StatusCode: The HTTP status code returned for the visited link.
            - StatusDescription: The status description returned for the visited link.
    .LINK
        Where-Object
        Get-HttpResponseHeader
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [Alias('iwc', 'webcrawl')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)][Alias('Uri', 'u', 'bu')][Uri]$BaseUri,
        [Parameter(Mandatory = $false, Position = 1)][Alias('d')][int]$Depth = 2,
        [Parameter(Mandatory = $false, Position = 2)][Alias('h', 'RequestHeaders')][System.Collections.Hashtable]$Headers,
        [Parameter(Mandatory = $true, Position = 3, ParameterSetName = "Include")][Alias('i', 'il', 'ih')][String[]]$IncludeHosts,
        [Parameter(Mandatory = $true, Position = 3, ParameterSetName = "Exclude")][Alias('e', 'el', 'eh')][String[]]$ExcludeHosts,
        [Parameter(Mandatory = $false, Position = 4)][Alias('ic')][Switch]$IncludeContent
    )
    BEGIN {
        # Determines if the website content will be returned in the output for all crawled sites:
        [bool]$addContentToOutput = $false
        if ($PSBoundParameters.ContainsKey("IncludeContent")) {
            $addContentToOutput = $true
        }

        function Get-WebLinkStatus {
            param (
                [Parameter(Mandatory = $true)][Uri]$Uri,
                [Parameter(Mandatory = $false)][int]$Depth = 2,
                [Parameter(Mandatory = $false)][System.Collections.Hashtable]$Headers,
                [Parameter(Mandatory = $false)][String[]]$IncludeHosts,
                [Parameter(Mandatory = $false)][String[]]$ExcludeHosts,
                [Parameter(Mandatory = $false)][Switch]$IncludeContent,
                [hashtable]$Visited = @{}
            )

            PROCESS {
                $targetUri = $Uri.AbsoluteUri

                # Avoid visiting the same URL more than once:
                if ($Visited.ContainsKey($targetUri)) {
                    return
                }

                $Visited[$targetUri] = $true

                $iwrParams = @{
                    Uri                            = $Uri
                    Method                         = "Get"
                    UseBasicParsing                = $true
                    SkipCertificateCheck           = $true
                    SkipHttpErrorCheck             = $true
                    ErrorAction                    = "Stop"
                    AllowInsecureRedirect          = $true
                    AllowUnencryptedAuthentication = $true
                    UseDefaultCredentials          = $true
                    SessionVariable                = "websession"
                }

                if ($PSBoundParameters.ContainsKey("Headers")) {
                    $iwrParams.Add("Headers", $Headers)
                }

                $parsedUri = [Uri]::new($targetUri)
                $targetHost = $parsedUri.Host

                [PSObject]$response = $null
                [int]$statusCode = 0
                [string]$statusDescription = ""
                [System.Net.CookieCollection]$cookies = $null
                [PSCustomObject]$responseHeaders = $null
                try {
                    $response = Invoke-WebRequest @iwrParams
                    $statusCode = $response.StatusCode
                    $statusDescription = $response.StatusDescription

                    $cookies = $websession.Cookies.GetCookies($Uri)

                    # In order to produce a PSCustomObject that contains only the string values of the key/value pairs contained within the headers property
                    # from Invoke-WebRquest, we have to build a new hash table that will contain the string values only of the header names and header values:
                    $stringResponseHeaderHashtable = @{}
                    foreach ($kvp in $response.Headers.GetEnumerator()) {
                        $stringKey = $($kvp.Key)
                        $stringValue = $($kvp.Value) -join ", "

                        if (-not($stringResponseHeaderHashtable.ContainsKey($stringKey))) {
                            $stringResponseHeaderHashtable.Add($stringKey, $stringValue)
                        }
                    }
                    $responseHeaders = New-Object -TypeName PSObject -Property $stringResponseHeaderHashtable
                }
                catch {
                    $statusCode = 520
                    $statusDescription = $_.Exception.Message
                }

                $webCrawlResultHashtable = [ordered]@{
                    BaseUri           = $BaseUri.AbsoluteUri
                    Uri               = $targetUri
                    HostName          = $targetHost
                    StatusCode        = $statusCode
                    StatusDescription = $statusDescription
                    ResponseHeaders   = $responseHeaders
                    Cookies           = $cookies
                }

                if ($addContentToOutput) {
                    [string]$websiteContent = $response.Content
                    $webCrawlResultHashtable.Add("Content", $websiteContent)
                }

                $webCrawlResult = New-Object -TypeName PSObject -Property $webCrawlResultHashtable

                Write-Output -InputObject $webCrawlResult

                # If the depth is 0, we stop here:
                if ($Depth -le 0) {
                    return;
                }

                # Extract absolute and relative links from the HTML content:
                $links = $response.Links | Where-Object { $_.href } | ForEach-Object {
                    $potentialAbsoluteUri = [Uri]::new([Uri]$targetUri, $_.href).AbsoluteUri
                    if ([Uri]::IsWellFormedUriString($potentialAbsoluteUri, 1) -and ($potentialAbsoluteUri -match "https?://")) {
                        Write-Output -InputObject $potentialAbsoluteUri
                    }
                }

                foreach ($link in $links) {
                    # Recursively visit each link:
                    $parsedUri = [Uri]::new($link)
                    $targetHost = $parsedUri.Host

                    $gwlsParamsInner = @{
                        Uri     = $link
                        Depth   = ($Depth - 1)
                        Visited = $Visited
                    }

                    if ($PSBoundParameters.ContainsKey("Headers")) {
                        $gwlsParamsInner.Add("Headers", $Headers)
                    }

                    if ($PSBoundParameters.ContainsKey("IncludeHosts")) {
                        if ($targetHost -in $IncludeHosts) {
                            Get-WebLinkStatus @gwlsParamsInner -IncludeHosts $IncludeHosts
                        }
                    }
                    elseif ($PSBoundParameters.ContainsKey("ExcludeHosts")) {
                        if ($targetHost -notin $ExcludeHosts) {
                            Get-WebLinkStatus @gwlsParamsInner -ExcludeHosts $ExcludeHosts
                        }
                    }
                    else {
                        Get-WebLinkStatus @gwlsParamsInner
                    }
                }
            }
        }
    }
    PROCESS {
        if ([Uri]::IsWellFormedUriString($BaseUri, 1)) {
            $targetHost = $BaseUri.DnsSafeHost
            $targetPort = $BaseUri.Port

            [bool]$canConnect = Test-TcpConnection -DNSHostName $targetHost -Port $targetPort -Quiet
            if (-not($canConnect)) {
                $webExceptionMessage = "Unable to reach base URI. Failed to connect to host {0} over port {1}." -f $targetHost, $targetPort
                $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
                Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Continue
            }

            $gwlsParamsOuter = @{
                Uri   = $BaseUri
                Depth = ($Depth - 1)
            }

            if ($PSBoundParameters.ContainsKey("Headers")) {
                $gwlsParamsOuter.Add("Headers", $Headers)
            }

            if ($PSBoundParameters.ContainsKey("IncludeContent")) {
                $gwlsParamsOuter.Add("IncludeContent", $true)
            }

            if ($PSBoundParameters.ContainsKey("IncludeHosts")) {
                Get-WebLinkStatus @gwlsParamsOuter -IncludeHosts $IncludeHosts
            }
            elseif ($PSBoundParameters.ContainsKey("ExcludeHosts")) {
                Get-WebLinkStatus @gwlsParamsOuter -ExcludeHosts $ExcludeHosts
            }
            else {
                Get-WebLinkStatus @gwlsParamsOuter
            }
        }
        else {
            $argExcepMessage = "{0} is not a valid URI" -f $BaseUri
            $ArgumentException = [ArgumentException]::new($argExcepMessage)
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Continue
        }
    }
}

#endregion


#region Export Statements

Export-ModuleMember -Function Test-TcpConnection
Export-ModuleMember -Function Get-TlsCertificate
Export-ModuleMember -Function Get-HttpResponseHeader
Export-ModuleMember -Function Get-TlsInformation
Export-ModuleMember -Function Invoke-DnsEnumeration
Export-ModuleMember -Function Get-IPInformation
Export-ModuleMember -Function Invoke-WebCrawl

Export-ModuleMember -Alias ttc
Export-ModuleMember -Alias gtls
Export-ModuleMember -Alias gtlsc
Export-ModuleMember -Alias gssl
Export-ModuleMember -Alias Get-SslCertificate
Export-ModuleMember -Alias Get-TlsStatus
Export-ModuleMember -Alias gwrh
Export-ModuleMember -Alias gtlsi
Export-ModuleMember -Alias gtlss
Export-ModuleMember -Alias idnse
Export-ModuleMember -Alias dnse
Export-ModuleMember -Alias gipi
Export-ModuleMember -Alias Get-IPAddressInformation
Export-ModuleMember -Alias iwc
Export-ModuleMember -Alias webcrawl

#endregion
