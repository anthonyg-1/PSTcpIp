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
        public string Destination { get; set; }
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
using System.Security.Cryptography.X509Certificates;
namespace PSTcpIp
{
    public class TlsSslStatus
    {
        public string HostName { get; set; }
        public int Port { get; set; }
        public string SerialNumber { get; set; }
        public string Thumbprint { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public bool CertificateVerifies { get; set; }
        public string SignatureAlgorithm { get; set; }
        public string NegotiatedCipherSuite { get; set; }
        public string CipherAlgorithm { get; set; }
        public string StrictTransportSecurity { get; set; }
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


#region Exported Functions

function Test-TcpConnection {
    <#
    .SYNOPSIS
        Tests TCP connectivity to a remote computer.
    .DESCRIPTION
        The Test-TcpConnection function attempts to establish TCP connectivity
        to one or more remote computers.

        You can use the parameters of Test-TcpConnection to specify the
        receiving computers and to set the number of connection requests.

        Unlike the traditional ping command, Test-TcpConnection returns a PSObject
        that you can investigate in Windows PowerShell, but you can use the Quiet parameter
        to force it to return only a Boolean value.

        Unlike Test-Connection, Test-TcpConnection does not depend on ICMP echo requests
        to determine if connectivity can be established. This is particularly useful in
        cases where firewalls block ICMP but allow access to HTTP and SSL.
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
                    $connectionStatusObject.Destination = $destination
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

function Get-SslCertificate {
    <#
        .SYNOPSIS
            Gets an SSL certificate from an endpoint.
        .DESCRIPTION
            Gets an SSL certificate from an endpoint specified as a host name and port or URI.
        .PARAMETER HostName
            The target host to obtain an SSL certificate from.
        .PARAMETER Port
            The port for the target host. This parameter is only applicable when using the HostName parameter. Default value is 443.
        .PARAMETER Uri
            Specifies the Uniform Resource Identifier (URI) of the internet resource to which the request for the SSL certificate is sent. This parameter supports HTTPS only.
        .PARAMETER TlsVersion
            Specifies the TLS version for the target endpoint. Works with both the HostName and Uri parameters. Default value is Tls12.
        .EXAMPLE
            Get-SslCertificate -HostName www.mysite.com

            Gets an SSL certificate from www.mysite.com over port 443 (default).
        .EXAMPLE
            Get-SslCertificate -HostName www.mysite.com -Port 8181

            Gets an SSL certificate from www.mysite.com over port 8181.
        .EXAMPLE
            Get-SslCertificate -HostName www.mysite.com -Port 443 | Select Thumbprint, Subject, NotAfter | Format-List

            Gets an SSL certificate from www.mysite.com over port 443, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list.
        .EXAMPLE
            Get-SslCertificate -Uri https://www.mysite.com/default.htm | Select Thumbprint, Subject, NotAfter | Format-List

            Gets an SSL certificate from https://www.mysite.com, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list.
        .OUTPUTS
            System.Security.Cryptography.X509Certificates.X509Certificate2
        .LINK
            Select-Object
            Format-List
            https://github.com/anthonyg-1/PSTcpIp
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Uri")][Uri]$Uri,
        [Parameter(Mandatory = $false, Position = 2)][ValidateSet("Tls", "Tls11", "Tls12", "Tls13")][String]$TlsVersion = "Tls12"
    )
    PROCESS {
        [string]$targetHost = ""
        [string]$targetPort = ""

        if ($PSBoundParameters.ContainsKey("Uri")) {
            $targetHost = $Uri.Authority
            $targetPort = $Uri.Port
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
            $targetHost = $connectionTestResult.Destination
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
        try {
            $tcpClient = [TcpClient]::new($targetHost, $Port)
            $sslStream = [SslStream]::new($tcpClient.GetStream())

            $sslStream.AuthenticateAsClient($targetHost)

            $sslCert = [X509Certificate2]::new($sslStream.RemoteCertificate)

            $sslStream.Close()
            $sslStream.Dispose()
            $tcpClient.Close()
            $tcpClient.Dispose()
        }
        catch {
            $cryptographicExceptionMessage = "Unable to establish SSL session with: {0}." -f $targetHost
            $CryptographicException = New-Object -TypeName CryptographicException -ArgumentList $cryptographicExceptionMessage
            Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction Stop
        }

        return $sslCert
    }
}

function Get-TlsStatus {
    <#
        .SYNOPSIS
            Gets TLS protocols, certificate and cipher information against a remote computer running TLS/SSL.
        .DESCRIPTION
            Obtains the negotiated TLS protocols, certificate data (lifetime, validity, subject, serial number and other identifiable information, etc.) and cipher information against a remote target running TLS/SSL.
        .PARAMETER HostName
            The target host to get TLS/SSL settings from.
        .PARAMETER Port
            The port for the target host. This parameter is only applicable when using the HostName parameter. Default value is 443.
        .PARAMETER Uri
            Specifies the Uniform Resource Identifier (URI) of the internet resource as an alternative to the HostName and Port parameters. This parameter supports HTTPS only.
        .EXAMPLE
            Get-TlsStatus -HostName mysite.com -Port 443

            Obtains TLS settings on mysite.com against TCP port 443.
        .EXAMPLE
            Get-TlsStatus -Uri "https://www.mysite.com"

            Tests TLS settings on "https://www.mysite.com".
        .OUTPUTS
            PSTcpIp.TlsSslStatus

                This function returns a TlsSslStatus object. Example output against "https://www.microsoft.com/en-us" using the Uri parameter:

                HostName                : www.microsoft.com
                Port                    : 443
                SerialNumber            : 6B000003F4E3A67A2348550C330000000003F4
                Thumbprint              : 9B2B8AE65169AA477C5783D6480F296EF48CF14D
                Subject                 : CN=www.microsoft.com, OU=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=WA, C=US
                Issuer                  : CN=Microsoft RSA TLS CA 01, O=Microsoft Corporation, C=US
                ValidFrom               : 8/28/2020 6:17:02 PM
                ValidTo                 : 8/28/2021 6:17:02 PM
                CertificateVerifies     : True
                SignatureAlgorithm      : sha256RSA
                NegotiatedCipherSuite   : TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                CipherAlgorithm         : Aes256
                StrictTransportSecurity : max-age=31536000
                Ssl2                    : False
                Ssl3                    : False
                Tls                     : True
                Tls11                   : True
                Tls12                   : True
                Tls13                   : False
        .NOTES
            If StrictTransportSecurity returns "Unable to acquire HSTS value" or "No value specified for strict transport security (HSTS)" with the HostName parameter set, try the fully qualified web address with the Uri parameter.
        .LINK
            Get-SslCertificate
    #>
    [CmdletBinding()]
    [OutputType([PSTcpIp.TlsSslStatus])]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'IPAddress', 'Name', 'h', 'i')][String]$HostName,
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = "HostName")][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Uri")][Uri]$Uri
    )
    PROCESS {
        [string]$targetHost = ""
        [string]$targetPort = ""
        [string]$targetUri = ""

        if ($PSBoundParameters.ContainsKey("Uri")) {
            $targetHost = $Uri.Authority
            $targetPort = $Uri.Port
            $targetUri = $Uri
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
            $targetHost = $connectionTestResult.Destination
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

        $tlsStatus = New-Object -TypeName PSTcpIp.TlsSslStatus
        $tlsStatus.HostName = $targetHost
        $tlsStatus.Port = $targetPort


        [X509Certificate2]$sslCert = $null;
        [bool]$handshakeSucceeded = $false;

        try {
            $sslCert = Get-SslCertificate -HostName $targetHost -Port $targetPort -ErrorAction Stop
            $tlsStatus.CertificateVerifies = $sslCert.Verify()
            $tlsStatus.ValidFrom = $sslCert.NotBefore;
            $tlsStatus.ValidTo = $sslCert.NotAfter;
            $tlsStatus.SerialNumber = $sslCert.GetSerialNumberString()
            $tlsStatus.Thumbprint = $sslCert.Thumbprint
            $tlsStatus.Subject = $sslCert.Subject
            $tlsStatus.Issuer = $sslCert.Issuer
            $handshakeSucceeded = $true
        }
        catch {
            $cryptographicExceptionMessage = "Unable to establish SSL handshake with the following host: {0}" -f $targetHost
            $CryptographicException = New-Object -TypeName CryptographicException -ArgumentList $cryptographicExceptionMessage
            Write-Error -Exception $CryptographicException -Category ProtocolError -ErrorAction Stop
        }

        If ($handshakeSucceeded) {
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
            $tlsStatus.StrictTransportSecurity = $strictTransportSecurityValue

            foreach ($protocol in $protocolList) {
                $socket = [Socket]::new([SocketType]::Stream, [ProtocolType]::Tcp)
                $socket.Connect($targetHost, $targetPort)

                try {
                    $netStream = [NetworkStream]::new($socket, $true)
                    $sslStream = [SslStream]::new($netStream, $true)

                    $sslStream.AuthenticateAsClient($targetHost, $null, $protocol, $false)

                    $tlsStatus.SignatureAlgorithm = $sslCert.SignatureAlgorithm.FriendlyName
                    $tlsStatus.$protocol = $true
                    $tlsStatus.NegotiatedCipherSuite = $sslStream.NegotiatedCipherSuite
                    $tlsStatus.CipherAlgorithm = $sslStream.CipherAlgorithm
                }
                catch {
                    $tlsStatus.$protocol = $false
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
        }
        return $tlsStatus
    }
}

#endregion


Export-ModuleMember -Function Test-TcpConnection
Export-ModuleMember -Function Get-SslCertificate
Export-ModuleMember -Function Get-TlsStatus

New-Alias -Name ttc -Value Test-TcpConnection -Force
New-Alias -Name gssl -Value Get-SslCertificate -Force
New-Alias -Name Get-TlsCertificate -Value Get-SslCertificate -Force
New-Alias -Name Get-TlsInfo -Value Get-TlsStatus -Force
New-Alias -Name gtlss -Value Get-TlsStatus -Force

Export-ModuleMember -Alias ttc
Export-ModuleMember -Alias gssl
Export-ModuleMember -Alias Get-TlsCertificate
Export-ModuleMember -Alias gtlss
Export-ModuleMember -Alias Get-TlsInfo
