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

function Get-WebServerCertificate([string]$TargetHost, [int]$Port = 443) {
    [X509Certificate2]$sslCert = $null
    try {
        $tcpClient = [TcpClient]::new($TargetHost, $Port)
        $callback = { param($certSender, $cert, $chain, $errors) return $true }
        $sslStream = [SslStream]::new($tcpClient.GetStream(), $false, $callback)

        $sslStream.AuthenticateAsClient($TargetHost)

        $sslCert = [X509Certificate2]::new($sslStream.RemoteCertificate)

        $sslStream.Close()
        $sslStream.Dispose()
        $tcpClient.Close()
        $tcpClient.Dispose()
    }
    catch {
        $cryptographicExceptionMessage = "Unable to establish TLS session with the following host: {0}." -f $targetHost
        $CryptographicException = New-Object -TypeName CryptographicException -ArgumentList $cryptographicExceptionMessage
        throw $CryptographicException
    }

    return $sslCert
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

        Tests TCP connectivity on the server 'myserver' against the following ports: 20, 21, 22, 23, 25, 53, 80, 88, 139, 389, 443, 445, 636, 3389, 5985
    .EXAMPLE
        Test-TcpConnection -HostName mywebsite.org | Where Connected

        Determine the listening TCP ports on mywebsite.org.
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

        $commonPorts = @(20, 21, 22, 23, 25, 53, 80, 88, 139, 389, 443, 445, 636, 3389, 5985)
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
        .PARAMETER TlsVersion
            Specifies the TLS version for the target endpoint. Works with both the HostName and Uri parameters. Default value is Tls12.
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
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "Uri")][Uri]$Uri,
        [Parameter(Mandatory = $false, Position = 2)][ValidateSet("Tls", "Tls11", "Tls12", "Tls13")][String]$TlsVersion = "Tls12",
        [Parameter(Mandatory = $false, Position = 3)][Switch]$IncludeChain
    )
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

        if (-not($connectionTestResult.Connected)) {
            $webExceptionMessage = "Unable to connect to {0} over the following port: {1}" -f $targetHost, $targetPort
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Stop
        }

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
                $chain.Build($sslCert) | Out-Null
                $allCertsInChain = $chain.ChainElements | Select-Object -ExpandProperty Certificate

                return $allCertsInChain
            }
            else {
                return $sslCert
            }
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

                HostName                : www.microsoft.com
                IPAddress               : 23.33.242.16
                Port                    : 443
                SerialNumber            : 330059F8B6DA8689706FFA1BD900000059F8B6
                Thumbprint              : 2D6E2AE5B36F22076A197D50009DEE66396AA99C
                Subject                 : CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, S=WA, C=US
                Issuer                  : CN=Microsoft Azure TLS Issuing CA 06, O=Microsoft Corporation, C=US
                ValidFrom               : 10/4/2022 7:23:11 PM
                ValidTo                 : 9/29/2023 7:23:11 PM
                CertificateVerifies     : True
                SignatureAlgorithm      : sha384RSA
                NegotiatedCipherSuites  : {TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_AES_256_GCM_SHA384}
                CipherAlgorithm         : Aes256
                CipherStrength          : 256
                KeyExchangeAlgorithm    : DiffieHellman
                StrictTransportSecurity : Strict-Transport-Security not found in header
                SubjectAlternativeNames : {wwwqa.microsoft.com, www.microsoft.com, staticview.microsoft.com, i.s-microsoft.com…}
                Ssl2                    : False
                Ssl3                    : False
                Tls                     : False
                Tls11                   : False
                Tls12                   : True
                Tls13                   : True

        .NOTES
            If StrictTransportSecurity returns "Unable to acquire HSTS value" or "No value specified for strict transport security (HSTS)" with the HostName parameter set, try the fully qualified web address with the Uri parameter.
        .LINK
            Test-TcpConnection
            Select-Object
            Format-List
            https://github.com/anthonyg-1/PSTcpIp
    #>
    [CmdletBinding()]
    [OutputType([PSTcpIp.TlsInfo])]
    param
    (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "Uri")][Uri]$Uri
    )
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

        if (-not($connectionTestResult.Connected)) {
            $webExceptionMessage = "Unable to connect to {0} over the following port: {1}" -f $targetHost, $targetPort
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Stop
        }

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
            $sslCert = Get-WebServerCertificate -TargetHost $targetHost -Port $targetPort -ErrorAction Stop
            $tlsInfo.CertificateVerifies = $sslCert.Verify()
            $tlsInfo.ValidFrom = $sslCert.NotBefore;
            $tlsInfo.ValidTo = $sslCert.NotAfter;
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
                $webRequestResponse = Invoke-WebRequest -Uri $targetUri -MaximumRedirection 0 -ErrorAction Stop

                [HashTable]$responseHeaders = $webRequestResponse.Headers

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
                $sansList = ($sslCert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }).format($false).Split(",").Replace("DNS Name=", "").Trim()
            }
            else {
                $opensslFound = $null -ne (Get-Command -CommandType Application -Name "openssl" -ErrorAction SilentlyContinue)
                if ($opensslFound) {
                    $sansList = (($sslCert.ExportCertificatePem() | openssl x509 -noout -text | Select-String -Pattern "DNS:") -split ",").Replace("DNS:", "").Trim()
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
}

#endregion


Export-ModuleMember -Function Test-TcpConnection
Export-ModuleMember -Function Get-TlsCertificate
Export-ModuleMember -Function Get-TlsInformation

New-Alias -Name ttc -Value Test-TcpConnection -Force
New-Alias -Name gtls -Value Get-TlsCertificate -Force
New-Alias -Name gssl -Value Get-TlsCertificate -Force
New-Alias -Name Get-SslCertificate -Value Get-TlsCertificate -Force
New-Alias -Name Get-TlsStatus -Value Get-TlsInformation -Force
New-Alias -Name Get-TlsInfo -Value Get-TlsInformation -Force
New-Alias -Name gtlsi -Value Get-TlsInformation -Force
New-Alias -Name gtlss -Value Get-TlsInformation -Force

Export-ModuleMember -Alias ttc
Export-ModuleMember -Alias gtls
Export-ModuleMember -Alias gssl
Export-ModuleMember -Alias Get-SslCertificate
Export-ModuleMember -Alias Get-TlsStatus
Export-ModuleMember -Alias gtlsi
Export-ModuleMember -Alias gtlss
