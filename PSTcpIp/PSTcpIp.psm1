using namespace System
using namespace System.Collections
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

if (-not(Test-Path -Path $tcpPortsJsonFilePath )) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("JSON configuration file not found in the following path: {0}" -f $tcpPortsJsonFilePath )
    throw $FileNotFoundException
}

if (-not(Test-Path -Path $protocolsJsonFilePath )) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("JSON configuration file not found in the following path: {0}" -f $protocolsJsonFilePath)
    throw $FileNotFoundException
}

$tcpPortData = Get-Content -Path $tcpPortsJsonFilePath  -Raw | ConvertFrom-Json
$protocolData = Get-Content -Path $protocolsJsonFilePath  -Raw | ConvertFrom-Json

$portTable = @{ }
foreach ($entry in $tcpPortData) {
    if (-not($portTable.ContainsKey([int]$entry.Port))) {
        $portTable.Add([int]$entry.port, $entry.description)
    }
}

$protocolArray = $protocolData | Select-Object -ExpandProperty protocols

New-Variable -Name tcpPortAndDescriptionData -Value $portTable -Option ReadOnly -Scope Global -Force
New-Variable -Name protocolList -Value $protocolArray -Option ReadOnly -Scope Global -Force

#endregion


#region Class Definitions

$tcpConnectionStatusClassDef = @"
using System;
using System.Net;
namespace PSTcpIp
{
    public class TcpConnectionStatus
    {
        public string HostName { get; set; }
        public string IPAddress { get; set; }
        public Int32 Port { get; set; }
        public string Service { get; set; }
        public bool Connected { get; set; }
        public bool HostNameResolved { get; set; }
    }
}
"@


$tlsStatusDefinition = @"
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
namespace PSTcpIp
{
    public class TlsInfo
    {
        public string HostName { get; set; }
        public IPAddress IPAddress { get; set; }
        public int Port { get; set; }
        public string SerialNumber { get; set; }
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public int CertificateValidityPeriodInYears { get; set; }
        public int CertificateValidityPeriodInDays { get; set; }
        public bool CertificateIsExpired { get; set; }
        public bool CertificateVerifies { get; set; }
        public string SignatureAlgorithm { get; set; }
        public string[] NegotiatedCipherSuites { get; set; }
        public string CipherAlgorithm { get; set; }
        public string CipherStrength { get; set; }
        public string KeyExchangeAlgorithm { get; set; }
        public string StrictTransportSecurity { get; set; }
        public string[] SubjectAlternativeNames { get; set; }
        public bool Ssl2 { get; set; }
        public bool Ssl3 { get; set; }
        public bool Tls { get; set; }
        public bool Tls11 { get; set; }
        public bool Tls12 { get; set; }
        public bool Tls13 { get; set; }
    }
}
"@

Add-Type -TypeDefinition $tcpConnectionStatusClassDef -ReferencedAssemblies System.Net.Primitives -ErrorAction Stop
Add-Type -TypeDefinition $tlsStatusDefinition -ErrorAction Stop

#endregion


#region Private Functions



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
        throw $CryptographicException
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

        Tests TCP connectivity on the server 'myserver' against the following ports: 20, 21, 22, 23, 25, 53, 80, 88, 137, 139, 389, 443, 445, 636, 1433, 1434, 1521, 3306, 3389, 5432, 5985, 5986, 8080, 8443
    .EXAMPLE
        Test-TcpConnection -HostName mywebsite.org | Where Connected

        Determine the listening TCP ports on mywebsite.org.
    .EXAMPLE
        #requires -Module ActiveDirectory
        Get-ADComputer -Filter {OperatingSystem -like "*2019*"} | Test-TcpConnection -Port 443 -Timeout 100 | Where Connected

        GetS all Windows Server 2019 instances from Active Directory and determine which ones are listening on port 443.
    .EXAMPLE
        #requires -Module ActiveDirectory
        Get-ADDomainController -Filter * | Test-TcpConnection -Port 636 | Where Connected | Get-TlsCertificate | Select Subject, NotAfter

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
        Where-Object
        https://github.com/anthonyg-1/PSTcpIp
        Get-ADDomainController
        Get-ADComputer
        Get-TlsCertificate
	#>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [Alias('ttc')]
    [OutputType([PSTcpIp.TcpConnectionStatus], ParameterSetName = 'Default')]
    [OutputType([System.Boolean], ParameterSetName = 'Quiet')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateLength(1, 250)][Alias('ComputerName', 'HostName', 'IPAddress', 'Name', 'h', 'i')][String[]]$DNSHostName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int[]]$Port,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default', Position = 2)][ValidateRange(1, 100000)][Alias('c')][Int]$Count = 1,
        [Parameter(Mandatory = $true, ParameterSetName = 'Quiet', Position = 2)][Alias('q')][Switch]$Quiet,
        [Parameter(Mandatory = $false, Position = 3)][ValidateRange(1, 2500)][Alias('to')][Int]$Timeout = 1200
    )
    BEGIN {
        New-Variable -Name ipv4Addresses -Value $null -Force
        New-Variable -Name ipv4Address -Value $null -Force
        New-Variable -Name tcpClient -Value $null -Force

        $commonPorts = @(20, 21, 22, 23, 25, 53, 80, 88, 137, 139, 389, 443, 445, 636, 1433, 1434, 1521, 3306, 3389, 5432, 5985, 5986, 8080, 8443)
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
                    $__PortNumbers = $commonPorts
                }
                else {
                    $__PortNumbers = $Port
                }

                $__PortNumbers | ForEach-Object {
                    $__PortNumber = $PSItem
                    if ($nameResolved) {
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

                    $connectionStatusObject = New-Object -TypeName PSTcpIp.TcpConnectionStatus
                    $connectionStatusObject.HostName = $destination
                    $connectionStatusObject.IPAddress = $ipv4Address
                    $connectionStatusObject.Port = $__PortNumber
                    $connectionStatusObject.Service = $tcpPortAndDescriptionData.Item($__PortNumber)
                    $connectionStatusObject.Connected = $connectionSucceeded
                    $connectionStatusObject.HostNameResolved = $nameResolved

                    if ($Quiet) {
                        return $connectionSucceeded
                    }
                    else {
                        return $connectionStatusObject
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
            $targets | Test-TcpConnection -Port 443 | Where Connected | Get-TlsCertificate | Select Subject, NotAfter | Format-List

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
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "Uri")][Uri]$Uri,
        [Parameter(Mandatory = $false, Position = 2)][Switch]$IncludeChain
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
    .PARAMETER Uri
        Specifies the Uniform Resource Identifier (URI) of the web endpoint. This parameter is mandatory and can be provided through the pipeline or by property name.
    .PARAMETER AsHashtable
        Instructs the function to return the results as an ordered Hashtable as opposed to the default of PSCustomObject.
    .EXAMPLE
        Get-HttpResponseHeader -Uri "https://example.com"

        Retrieves the HTTP response headers from the specified web endpoint.
    .EXAMPLE
        "https://example.com" | Get-HttpResponseHeader

        Retrieves the HTTP response headers from the web endpoint provided through the pipeline.
    .EXAMPLE
        gwrh -u "https://example.com"

        Retrieves the HTTP response headers from the specified web endpoint.
    .INPUTS
        System.Uri
    .OUTPUTS
        System.Management.Automation.PSCustomObject or System.Collections.Specialized.OrderedDictionary
    .LINK
        https://developer.mozilla.org/en-US/docs/Glossary/Response_heade
    #>
    [CmdletBinding()]
    [Alias('gwrh')]
    [OutputType([System.Management.Automation.PSCustomObject], [System.Collections.Specialized.OrderedDictionary])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)][Alias('u')][ValidateNotNullOrEmpty()][System.Uri]$Uri,

        [Parameter(Mandatory = $false,
            Position = 1)][Alias('ht')][Switch]$AsHashtable
    )
    PROCESS {
        [bool]$isValidUri = [System.Uri]::IsWellFormedUriString($Uri, 1)

        if (-not($isValidUri)) {
            $ArgumentException = [ArgumentException]::new("Invalid data passed to Uri parameter.")
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        [bool]$canConnect = Test-TcpConnection -DNSHostName $Uri.DnsSafeHost -Port $Uri.Port -Quiet
        if ($canConnect) {
            try {
                # Get response headers:
                $responseHeaders = Invoke-WebRequest -Uri $Uri.AbsoluteUri -MaximumRedirection 0 -SkipCertificateCheck -ErrorAction Stop | Select-Object -ExpandProperty Headers -ErrorAction Stop

                # Create sorted table:
                $sortedHeaders = $responseHeaders.GetEnumerator() | Sort-Object -Property Key

                # Create empty sorted hash table and populate (can't send PSCustomObject a table that's has GetEnumerator() called on it:
                $headersToReturn = [ordered]@{}
                $sortedHeaders | ForEach-Object { $headersToReturn.Add($_.Key, $_.Value) }

                # Return collection of headers with header name as key:
                $headerCollection = $null
                if ($PSBoundParameters.ContainsKey("AsHashtable")) {
                    $headerCollection = $headersToReturn
                }
                else {
                    $headerCollection = New-Object -TypeName PSCustomObject -Property $headersToReturn
                }

                return $headerCollection
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }
        }
        else {
            $webExceptionMessage = "Unable to connect to the following endpoint: $Uri"
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Continue
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
            $targets | Test-TcpConnection -Port 443 | Where Connected | Get-TlsInformation

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

                HostName                         : www.microsoft.com
                IPAddress                        : 23.47.169.232
                Port                             : 443
                SerialNumber                     : 330003E2CD1066AD8DB81C060800000003E2CD
                Thumbprint                       : E1579BA55125CEC3A78E39F55CF81DA8BFA94F88
                Subject                          : CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, S=WA, C=US
                Issuer                           : CN=Microsoft Azure RSA TLS Issuing CA 07, O=Microsoft Corporation, C=US
                ValidFrom                        : 9/14/2023 1:24:20 PM
                ValidTo                          : 9/8/2024 1:24:20 PM
                CertificateValidityPeriodInYears : 1
                CertificateValidityPeriodInDays  : 360
                CertificateIsExpired             : False
                CertificateVerifies              : True
                SignatureAlgorithm               : sha384RSA
                NegotiatedCipherSuites           : {TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
                CipherAlgorithm                  : Aes256
                CipherStrength                   : 256
                KeyExchangeAlgorithm             : ECDH Ephemeral
                StrictTransportSecurity          : Strict-Transport-Security not found in header
                SubjectAlternativeNames          : {wwwqa.microsoft.com, www.microsoft.com, staticview.microsoft.com, i.s-microsoft.comΓÇª}
                Ssl2                             : False
                Ssl3                             : False
                Tls                              : False
                Tls11                            : False
                Tls12                            : True
                Tls13                            : False
        .NOTES
            If StrictTransportSecurity returns "Unable to acquire HSTS value" or "No value specified for strict transport security (HSTS)" with the HostName parameter set, try the fully qualified web address with the Uri parameter.
        .LINK
            Test-TcpConnection
            Select-Object
            Format-List
            https://github.com/anthonyg-1/PSTcpIp
    #>
    [CmdletBinding(DefaultParameterSetName = 'Uri')]
    [OutputType([PSTcpIp.TlsInfo])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "Uri")][Uri]$Uri
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

                # If OS is Windows, the X509Certificate2.Extensions property is populated and thus we can infer SANS from that.
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
                        $sansList = (($sslCert.ExportCertificatePem() | openssl x509 -noout -text | Select-String -Pattern "DNS:") -split ",") | ForEach-Object {
                            $_.Replace("DNS:", "").Trim()
                        }
                    }
                    else {
                        $opensslNotFoundWarning = "The openssl binary was not found. SubjectAlternativeNames will not be populated."
                        Write-Warning -Message $opensslNotFoundWarning
                    }
                }
                $tlsInfo.SubjectAlternativeNames = $sansList

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
                        $tlsInfo.$protocol = $false
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

#endregion


Export-ModuleMember -Function Test-TcpConnection
Export-ModuleMember -Function Get-TlsCertificate
Export-ModuleMember -Function Get-HttpResponseHeader
Export-ModuleMember -Function Get-TlsInformation


New-Alias -Name ttc -Value Test-TcpConnection -Force
New-Alias -Name gtls -Value Get-TlsCertificate -Force
New-Alias -Name gssl -Value Get-TlsCertificate -Force
New-Alias -Name Get-SslCertificate -Value Get-TlsCertificate -Force
New-Alias -Name Get-TlsStatus -Value Get-TlsInformation -Force
New-Alias -Name Get-TlsInfo -Value Get-TlsInformation -Force
New-Alias -Name gtlsi -Value Get-TlsInformation -Force
New-Alias -Name gwrh -Value Get-HttpResponseHeader -Force
New-Alias -Name gtlss -Value Get-TlsInformation -Force


Export-ModuleMember -Alias ttc
Export-ModuleMember -Alias gtls
Export-ModuleMember -Alias gssl
Export-ModuleMember -Alias Get-SslCertificate
Export-ModuleMember -Alias Get-TlsStatus
Export-ModuleMember -Alias gwrh
Export-ModuleMember -Alias gtlsi
Export-ModuleMember -Alias gtlss
