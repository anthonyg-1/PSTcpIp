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
$commonPortsFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'ConfigData\CommonPorts.txt'
$dnsDefaultPrefixesFilePath = Join-Path $PSScriptRoot -ChildPath '.\ConfigData\DnsDefaultPrefixes.txt'

if (-not(Test-Path -Path $tcpPortsJsonFilePath )) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("JSON configuration file not found in the following path: {0}" -f $tcpPortsJsonFilePath )
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
[int[]]$tcpCommonPorts = Get-Content -Path $commonPortsFilePath | ForEach-Object { if ([Int]::TryParse($_.Trim(), [ref]$null)) { [int]$_.Trim() } }
$defaultDnsPrefixes = Get-Content -Path $dnsDefaultPrefixesFilePath

$tcpPortAndDescriptionData = @{ }
foreach ($entry in $tcpPortData) {
    if (-not($tcpPortAndDescriptionData.ContainsKey([int]$entry.Port))) {
        $tcpPortAndDescriptionData.Add([int]$entry.port, $entry.description)
    }
}

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

[string]$tlsStatusDefinition = ""

if ($IsLinux) {
    $tlsStatusDefinition = @'
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
        public string SubjectKeyIdentifier { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public System.Security.Cryptography.X509Certificates.X509Certificate2[] CertificateChain { get; set; }
        public bool? CertificateIsTrusted { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public int CertificateValidityPeriodInYears { get; set; }
        public int CertificateValidityPeriodInDays { get; set; }
        public bool? CertificateIsExpired { get; set; }
        public bool CertificateSubjectMatchesHostName { get; set; }
        public bool? IsWildcardCertificate { get; set; }
        public bool? IsSelfSignedCertificate { get; set; }
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
'@
}
else {
    $tlsStatusDefinition = @'
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
        public string SubjectKeyIdentifier { get; set; }
        public string Issuer { get; set; }
        public System.Security.Cryptography.X509Certificates.X509Certificate2[] CertificateChain { get; set; }
        public bool? CertificateIsTrusted { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public int CertificateValidityPeriodInYears { get; set; }
        public int CertificateValidityPeriodInDays { get; set; }
        public bool? CertificateIsExpired { get; set; }
        public bool CertificateSubjectMatchesHostName { get; set; }
        public bool? IsWildcardCertificate { get; set; }
        public bool? IsSelfSignedCertificate { get; set; }
        public string SignatureAlgorithm { get; set; }
        public string[] NegotiatedCipherSuites { get; set; }
        public string CipherAlgorithm { get; set; }
        public string CipherStrength { get; set; }
        public string KeyExchangeAlgorithm { get; set; }
        public int? KeySize { get; set; }
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
'@
}

Add-Type -TypeDefinition $tcpConnectionStatusClassDef -ReferencedAssemblies System.Net.Primitives -ErrorAction Stop
Add-Type -TypeDefinition $tlsStatusDefinition -ErrorAction Stop

#endregion


#region Private Functions

function Test-Uri {
    param (
        [Parameter(Mandatory)]
        [String]$InputString
    )

    try {
        [void][System.Uri]::new($InputString)
        return $true
    }
    catch {
        return $false
    }
}

function Get-SourceIPAddress([string]$Destination = "8.8.8.8") {
    [string]$sourceAddress = ""

    if ($IsWindows) {
        $socket = $null
        try {
            $socket = New-Object System.Net.Sockets.UdpClient
            $socket.Connect($Destination, 53)
            $localEndpoint = $socket.Client.LocalEndPoint
            $sourceAddress = $localEndpoint.Address.ToString()
        }
        catch {
            $ipconfig = ipconfig | Select-String "IPv4 Address" | ForEach-Object { ($_ -split ":")[1].Trim() }
            $sourceAddress = ($ipconfig | Where-Object { $_ -ne "127.0.0.1" })[0]
        }
        finally {
            if ($null -ne $socket) {
                $socket.Dispose()
            }
        }
    }
    else {
        try {
            $getCommandResult = Get-Command -Name ip -ErrorAction Ignore
            if ($null -ne $getCommandResult) {
                $sourceAddress = $(ip route get $Destination | head -1 | cut -d' ' -f7).Trim() -replace "`n|`r", ""
            }
            else {
                $warningMessage = "ip command not installed. Unable to determine source IP address."
                $sourceAddress = $warningMessage
                Write-Warning -Message $warningMessage -WarningAction $WarningPreference
            }
        }
        catch {
            return $sourceAddress
        }
    }

    return $sourceAddress
}

if ($IsWindows) {
    function Get-WebServerCertificate([string]$TargetHost, [int]$Port = 443, [int]$Timeout = 10) {
        $cryptographicExceptionMessage = "Unable to establish TLS session with {0} over port {1}." -f $TargetHost, $Port
        $CryptographicException = [System.Security.Cryptography.CryptographicException]::new($cryptographicExceptionMessage)

        [System.Net.Sockets.TcpClient]$tcpClient = $null
        [System.Net.Security.SslStream]$sslStream = $null
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslCert = $null

        try {
            # Create TcpClient with timeout:
            $tcpClient = [System.Net.Sockets.TcpClient]::new()
            $tcpClient.ReceiveTimeout = $Timeout * 1000
            $tcpClient.SendTimeout = $Timeout * 1000

            # Connect with timeout using async method:
            $connectTask = $tcpClient.ConnectAsync($TargetHost, $Port)
            if (-not $connectTask.Wait($Timeout * 1000)) {
                throw [System.TimeoutException]::new("Connection timed out")
            }

            $callback = { param($certSender, $cert, $chain, $errors) return $true }
            $sslStream = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, $callback)

            # Set read/write timeouts for SSL stream:
            $sslStream.ReadTimeout = $Timeout * 1000
            $sslStream.WriteTimeout = $Timeout * 1000

            $sslStream.AuthenticateAsClient($TargetHost)
            $sslCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)

            return $sslCert
        }
        catch {
            throw $CryptographicException
        }
        finally {
            # CRITICAL: Cleanup must be in finally block to ensure it always happens:
            if ($null -ne $sslStream) {
                try {
                    $sslStream.Close()
                    $sslStream.Dispose()
                }
                catch {
                    # Ignore disposal errors
                }
            }

            if ($null -ne $tcpClient) {
                try {
                    $tcpClient.Close()
                    $tcpClient.Dispose()
                }
                catch {
                    # Ignore disposal errors.
                }
            }
        }
    }
}
else {
    function Get-WebServerCertificate([string]$TargetHost, [int]$Port = 443, [int]$Timeout = 10) {
        $cryptographicExceptionMessage = "Unable to establish TLS session with {0} over port {1}." -f $TargetHost, $Port
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

        $getCertJobResult = $null
        try {
            $certRetrievalJob = Start-Job -ScriptBlock $getCertScriptBlock

            Wait-Job -Job $certRetrievalJob -Timeout $Timeout | Out-Null

            if ((Get-Job -Id $certRetrievalJob.Id).State -ne "Failed") {
                $getCertJobResult = Receive-Job -Job $certRetrievalJob
            }

            Remove-Job -Job $certRetrievalJob -Force
        }
        finally {
            Get-Job | Where-Object -Property State -eq "Failed" | Remove-Job -Force | Out-Null
        }

        if ($null -ne $getCertJobResult) {
            return $getCertJobResult
        }
        else {
            [bool]$opensslFound = $null -ne (Get-Command -CommandType Application -Name "openssl" -ErrorAction SilentlyContinue)
            if ($opensslFound) {
                # Build target host and part for connect argument for openssl:
                $targetHostAndPort = "{0}:{1}" -f $TargetHost, $Port

                try {
                    # Cert object to be returned:
                    $tlsCert = $null

                    # Get the cert:
                    $openSslResult = "Q" | openssl s_client -connect $targetHostAndPort 2>$null

                    $openSslResultString = $openSslResult -join ""

                    # Header and footer values for base64 cert:
                    $beginString = "BEGIN CERTIFICATE"
                    $endString = "END CERTIFICATE"

                    # Determine that the results of the openssl command contain the header and footer for the base64 cert:
                    if (($openSslResultString.Contains($beginString)) -and ($openSslResultString.Contains($endString))) {
                        # Parse the relevant base64 cert resulting from openssl:
                        $base64CertString = ($openSslResultString.Split($beginString)[1].Split($endString)[0]).Replace("-", "")

                        # Convert the base64 string to a byte array to be fed to the X509Certificate2 constructor:
                        [byte[]]$certBytes = [System.Convert]::FromBase64String($base64CertString)

                        # Instantiate the certificate from the deserialized byte array:
                        $tlsCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                    }
                    else {
                        throw $CryptographicException
                    }

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
}

function Get-PublicKeySize {
    param (
        [X509Certificate2]$Certificate
    )

    [string]$oid = ""
    try {
        $oid = $Certificate.PublicKey.Oid.Value
    }
    catch {
        return $null
    }

    $rsaOID = '1.2.840.113549.1.1.1'
    $edsaOID = '1.2.840.10045.2.1'

    switch ($oid) {
        $rsaOID {
            try {
                $rsa = [RSACertificateExtensions]::GetRSAPublicKey($Certificate)
                if ($rsa) {
                    return $rsa.KeySize
                }
                else {
                    return $null
                }
            }
            catch {
                return $null
            }
        }
        $edsaOID {
            try {
                $ecdsa = [ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate)
                if ($ecdsa) {
                    return $ecdsa.KeySize
                }
                else {
                    return $null
                }
            }
            catch {
                return $null
            }
        }
        default {
            return $null
        }
    }
}


function Test-TlsVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,
        [Parameter(Mandatory = $false)]
        [int]$Port = 443,
        [Parameter(Mandatory = $false)]
        [int]$ConnectionTimeout = 10,
        [Parameter(Mandatory = $false)]
        [int]$ReadTimeout = 30000
    )
    BEGIN {
        # Helper function to test a specific protocol:
        function Test-Protocol {
            param($Protocol, $ProtocolName)
            $tcpClient = $null
            $sslStream = $null
            $protocolInfo = @{
                Supported             = $false
                NegotiatedCipherSuite = $null
                CipherAlgorithm       = $null
                CipherStrength        = $null
                KeyExchangeAlgorithm  = $null
            }

            try {
                $tcpClient = [System.Net.Sockets.TcpClient]::new()
                $tcpClient.ReceiveTimeout = $ReadTimeout
                $tcpClient.SendTimeout = $ReadTimeout

                # Connect to host:
                $connectTask = $tcpClient.ConnectAsync($HostName, $Port)
                if (-not $connectTask.Wait($ConnectionTimeout * 1000)) {
                    return $protocolInfo
                }

                $networkStream = $tcpClient.GetStream()

                # Create SSL stream with certificate validation callback that accepts all certificates:
                $certCallback = {
                    param($sslSender, $certificate, $chain, $sslPolicyErrors)
                    return $true
                }
                $sslStream = [System.Net.Security.SslStream]::new($networkStream, $false, $certCallback)

                # Try to authenticate with the specific protocol:
                $sslStream.AuthenticateAsClient($HostName, $null, $Protocol, $false)

                # If we get here, the protocol is supported:
                $protocolInfo.Supported = $true

                # Extract cipher information
                if ($sslStream.NegotiatedCipherSuite) {
                    $protocolInfo.NegotiatedCipherSuite = $sslStream.NegotiatedCipherSuite
                }
                if ($sslStream.CipherAlgorithm) {
                    $protocolInfo.CipherAlgorithm = $sslStream.CipherAlgorithm
                }
                if ($sslStream.CipherStrength) {
                    $protocolInfo.CipherStrength = $sslStream.CipherStrength
                }

                # Handle KeyExchangeAlgorithm with special case for ECDH Ephemeral
                if ($sslStream.KeyExchangeAlgorithm) {
                    $protocolInfo.KeyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm
                }
                else {
                    $protocolInfo.KeyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm.ToString()
                }

                return $protocolInfo
            }
            catch {
                return $protocolInfo
            }
            finally {
                if ($sslStream) {
                    try { $sslStream.Close() } catch { }
                    try { $sslStream.Dispose() } catch { }
                }
                if ($tcpClient) {
                    try { $tcpClient.Close() } catch { }
                    try { $tcpClient.Dispose() } catch { }
                }
            }
        }
    }
    PROCESS {
        # Test each protocol individually:
        $ssl2Info = Test-Protocol -Protocol ([System.Security.Authentication.SslProtocols]::Ssl2) -ProtocolName "Ssl2"
        $ssl3Info = Test-Protocol -Protocol ([System.Security.Authentication.SslProtocols]::Ssl3) -ProtocolName "Ssl3"
        $tlsInfo = Test-Protocol -Protocol ([System.Security.Authentication.SslProtocols]::Tls) -ProtocolName "Tls"
        $tls11Info = Test-Protocol -Protocol ([System.Security.Authentication.SslProtocols]::Tls11) -ProtocolName "Tls11"
        $tls12Info = Test-Protocol -Protocol ([System.Security.Authentication.SslProtocols]::Tls12) -ProtocolName "Tls12"
        $tls13Info = Test-Protocol -Protocol ([System.Security.Authentication.SslProtocols]::Tls13) -ProtocolName "Tls13"

        # Collect all negotiated cipher suites into an array
        $negotiatedCipherSuites = @()
        foreach ($info in @($ssl2Info, $ssl3Info, $tlsInfo, $tls11Info, $tls12Info, $tls13Info)) {
            if ($info.Supported -and $info.NegotiatedCipherSuite) {
                $negotiatedCipherSuites += $info.NegotiatedCipherSuite
            }
        }

        # Get cipher information from the highest supported protocol
        $cipherAlgorithm = ""
        $cipherStrength = ""
        $keyExchangeAlgorithm = ""

        # Check protocols in descending order of preference (TLS 1.3 -> TLS 1.2 -> etc.):
        $allTlsInformation = @($tls13Info, $tls12Info, $tls11Info, $tlsInfo, $ssl3Info, $ssl2Info)

        # Obtain KeyExchangeAlgorithm seperately:
        foreach ($keyExAlg in $allTlsInformation.KeyExchangeAlgorithm) {
            if (($null -ne $keyExAlg) -and ($keyExAlg -ne "None")) {
                if ($keyExAlg.ToString() -eq "44550") {
                    $keyExchangeAlgorithm = "ECDH Ephemeral"
                    break
                }
                else {
                    $keyExchangeAlgorithm = $keyExAlg.ToString()
                }
            }
        }

        # Now obtain CipherAlgorithm and CipherStrength:
        foreach ($info in $allTlsInformation) {
            if ($info.Supported) {
                $cipherAlgorithm = $info.CipherAlgorithm
                $cipherStrength = $info.CipherStrength
                break
            }
        }

        # Initialize result object with original boolean properties plus new cipher information:
        $result = [PSCustomObject]@{
            HostName               = $HostName
            Port                   = $Port
            Ssl2                   = $ssl2Info.Supported
            Ssl3                   = $ssl3Info.Supported
            Tls                    = $tlsInfo.Supported
            Tls11                  = $tls11Info.Supported
            Tls12                  = $tls12Info.Supported
            Tls13                  = $tls13Info.Supported
            NegotiatedCipherSuites = $negotiatedCipherSuites
            CipherAlgorithm        = $cipherAlgorithm
            CipherStrength         = $cipherStrength
            KeyExchangeAlgorithm   = $keyExchangeAlgorithm
        }

        return $result
    }
}


function Get-X509CertificateChain {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    PROCESS {
        $allCertsInChain = $null

        $chain = [X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::AllowUnknownCertificateAuthority
        $chain.Build($Certificate) | Out-Null

        $allCertsInChain = $chain.ChainElements | Select-Object -ExpandProperty Certificate

        return $allCertsInChain
    }
}

function Resolve-DNSHostName {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateLength(1, 250)][Alias('ComputerName', 'HostName')][String]$DNSHostName
    )
    PROCESS {
        [string]$ipAddress = ""

        if (Test-IPAddress -InputString $DNSHostName) {
            $ipAddress = $DNSHostName
        }
        else {
            try {
                $ipAddress = $([System.Net.Dns]::GetHostEntry($DNSHostName)[0] | Select-Object -ExpandProperty AddressList | Select-Object -ExpandProperty IPAddressToString -First 1 )
            }
            catch {
                $webExMessage = "Unable to resolve {0} to an IP address." -f $HostName
                $WebException = [System.Net.WebException]::new($webExMessage)
                throw $WebException
            }
        }
        return $ipAddress
    }
}

#endregion


#region Global Variables

New-Variable -Name MySourceIPAddress -Value (Get-SourceIPAddress) -Option Constant -Force

#endregion


#region Exported Functions

function Test-IPAddress {
    <#
.SYNOPSIS
    Determines whether a given string is a valid IP address.

.DESCRIPTION
    The Test-IPAddress function checks if the provided input string can be parsed as a valid IP address.
    It supports both IPv4 and IPv6 formats using the .NET [System.Net.IPAddress]::Parse() method.
    If the input is a valid IP address, the function returns $true; otherwise, it returns $false.

.PARAMETER InputString
    [String] The string to validate as an IP address.
    This parameter is mandatory and must be provided when calling the function.

.INPUTS
    System.String
    You can pipe a string to this function to test if it is a valid IP address.

.OUTPUTS
    System.Boolean
    Returns $true if the input string is a valid IP address; otherwise, returns $false.

.EXAMPLE
    Test-IPAddress -InputString "192.168.0.1"
    Returns: True

.EXAMPLE
    Test-IPAddress -InputString "example.com"
    Returns: False

.EXAMPLE
    "10.0.0.1" | Test-IPAddress
    Returns: True
#>
    [CmdletBinding()]
    [OutputType([bool])]
    [Alias('tip')]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)][String]$InputString
    )
    PROCESS {
        [bool]$isIpAddress = $false

        $stringToTest = $InputString.Trim()

        try {
            [IPAddress]::Parse($stringToTest) | Out-Null
            $isIpAddress = $true
        }
        catch {
            $isIpAddress = $false
        }

        return $isIpAddress
    }
}

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
        The timeout value expressed in milliseconds. The default value is 2000.
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
    .EXAMPLE
      "192.168.0.0" | Get-IPAddressList | Test-TcpConnection -Port 80 -WhereConnected

       The base IPv4 subnet "192.168.0.0" is passed through the pipeline, and the Get-IPAddressList function will output all possible IP addresses in that subnet, which are then passed to Test-TcpConnection to determine what IP addresses are listening on TCP port 80.
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
        Get-IPAddressList
        https://github.com/anthonyg-1/PSTcpIp
	#>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([PSTcpIp.TcpConnectionStatus], ParameterSetName = 'Default')]
    [OutputType([System.Boolean], ParameterSetName = 'Quiet')]
    [Alias('ttc', 'tmap')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateLength(1, 250)][Alias('ComputerName', 'HostName', 'IPAddress', 'Name', 'h', 'i')][String[]]$DNSHostName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][ValidateRange(1, 65535)][Alias('PortNumber', 'p')][Int[]]$Port,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default', Position = 2)][ValidateRange(1, 100000)][Alias('c')][Int]$Count = 1,
        [Parameter(Mandatory = $true, ParameterSetName = 'Quiet', Position = 2)][Alias('q')][Switch]$Quiet,
        [Parameter(Mandatory = $false, Position = 3)][ValidateRange(1, 2500)][Alias('to')][Int]$Timeout = 2000,
        [Parameter(Mandatory = $false, Position = 4)][Alias('sco', 'sc', 'Connected', 'ShowConnected', 'WhereConnected', 'wc')][Switch]$ShowConnectedOnly
    )
    BEGIN {
        $sourceIpAddress = $MySourceIPAddress
    }
    PROCESS {
        $__ComputerNames = $DNSHostName

        foreach ($__ComputerName in $__ComputerNames) {
            # Declare local variables for each iteration:
            [string[]]$ipv4Addresses = $null
            [string]$ipv4Address = ""
            [string]$destination = ""

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

            [Boolean]$nameResolved = $false
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
                    $tcpClient = $null  # Initialize for each port test:

                    $connectionStatusObject = [PSTcpIp.TcpConnectionStatus]::new()

                    if ($nameResolved) {
                        $connectionStatusObject.SourceAddress = $sourceIpAddress

                        try {
                            $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
                            $connectionResult = $tcpClient.BeginConnect($ipv4Address, $__PortNumber, $null, $null)

                            if ($connectionResult.AsyncWaitHandle.WaitOne($Timeout)) {
                                if ($tcpClient.Connected -eq $true) {
                                    $connectionSucceeded = $true
                                }
                                else {
                                    $connectionSucceeded = $false
                                }
                            }
                            else {
                                $connectionSucceeded = $false
                            }
                        }
                        catch {
                            $connectionSucceeded = $false
                        }
                        finally {
                            # Proper cleanup of TcpClient:
                            if ($tcpClient) {
                                try {
                                    if ($tcpClient.Connected) {
                                        $tcpClient.Close()
                                    }
                                    $tcpClient.Dispose()
                                }
                                finally {
                                    $tcpClient = $null
                                }
                            }
                        }
                    }
                    else {
                        $connectionStatusObject.SourceAddress = $sourceIpAddress
                    }

                    $connectionStatusObject.HostName = $destination
                    $connectionStatusObject.IPAddress = $ipv4Address
                    $connectionStatusObject.Port = $__PortNumber

                    if ($tcpPortAndDescriptionData.ContainsKey($__PortNumber)) {
                        $connectionStatusObject.Service = $tcpPortAndDescriptionData[$__PortNumber]
                    }
                    else {
                        $connectionStatusObject.Service = "Unknown"
                    }

                    $connectionStatusObject.Connected = $connectionSucceeded

                    if (Test-IPAddress -InputString $destination) {
                        $connectionStatusObject.HostNameResolved = $false
                    }
                    else {
                        $connectionStatusObject.HostNameResolved = $nameResolved
                    }

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

            # Clean up variables for each computer iteration:
            $ipv4Addresses = $null
            $ipv4Address = $null
            $destination = $null
        }
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
    PROCESS {
        [string]$targetHost = ""
        [string]$targetPort = ""

        if ($PSBoundParameters.ContainsKey("Uri")) {
            if ((Test-Uri -InputString $Uri) -and ($Uri.Scheme -eq "https")) {
                $targetHost = $Uri.DnsSafeHost
                $targetPort = $Uri.Port
            }
            else {
                $argumentExceptionMessage = "Provided value is not a valid URI or does not contain the necessary https:// prefix."
                $ArgumentException = New-Object ArgumentException -ArgumentList $argumentExceptionMessage
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }
        else {
            $targetHost = $HostName
            $targetPort = $Port
        }

        $connectionTestResult = Test-TcpConnection -DNSHostName $targetHost -Port $targetPort

        [bool]$isIp = Test-IPAddress -InputString $targetHost

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
                Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction $ErrorActionPreference
            }

            if ($handshakeSucceeded) {
                if ($PSBoundParameters.ContainsKey("IncludeChain")) {
                    $allCertsInChain = Get-X509CertificateChain -Certificate $sslCert
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
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction $ErrorActionPreference
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
    .PARAMETER IncludeHttpStatusCode
         Instructs the function to also return the HTTP status code.
    .PARAMETER Headers
        Specifies the HTTP request headers as a hash table.
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
        Get-HttpResponseHeader -HostName "example.com" -IncludeTargetInformation -IncludeHttpStatusCode

        Retrieves the HTTP response headers from the specified web endpoint with a hostname of example.com including the host name (as HostName), the resolved IPv4 address (as IPAddress), and the target Uri (as Uri) as well as the HTTP status code.
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
            Position = 2, ParameterSetName = "HostName")][ValidateSet("HTTP", "HTTPS")][Alias('Scheme', 'ps', 's')][String]$ProtocolScheme = "HTTPS",

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0, ParameterSetName = "Uri")][Alias('u')][System.Uri]$Uri,

        [Parameter(Mandatory = $false, Position = 3)][Alias('ht')][Switch]$AsHashtable,

        [Parameter(Mandatory = $false, Position = 4)][Alias('IncludeTargetInfo', 'iti')][Switch]$IncludeTargetInformation,

        [Parameter(Mandatory = $false, Position = 5)][Alias('RequestHeaders', 'rh')][System.Collections.Hashtable]$Headers,

        [Parameter(Mandatory = $false, Position = 6)][Alias('isc')][Switch]$IncludeHttpStatusCode
    )
    PROCESS {
        [Uri]$targetUri = $Uri
        if ($PSBoundParameters.ContainsKey("HostName")) {

            $webExceptionMessage = "Unable to connect to {0} over port {1}. Verify hostname and port and try again." -f $HostName, $Port
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage

            [bool]$hostNameIsUri = [System.Uri]::IsWellFormedUriString($HostName, 1)
            if ($hostNameIsUri) {
                $argumentExceptionMessage = "Value passed to HostName is a URI. Use the Uri parameter instead."
                $ArgumentException = [ArgumentException]::new($argumentExceptionMessage)
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction $ErrorActionPreference
            }

            $targetPort = $Port
            if (($PSBoundParameters.ContainsKey("ProtocolScheme")) -and ($ProtocolScheme.ToLower() -eq "http") -and (-not($PSBoundParameters.ContainsKey("Port")))) {
                $targetPort = 80
            }

            $uriString = "{0}://{1}:{2}" -f $ProtocolScheme.ToLower(), $HostName, $targetPort
            $targetUri = [System.Uri]::new($uriString)
        }
        else {
            $webExceptionMessage = "Unable to connect to the following endpoint: $Uri. Verify URI and try again."
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
        }

        [bool]$isValidUri = Test-Uri -InputString $targetUri

        if (-not($isValidUri)) {
            $ArgumentException = [ArgumentException]::new("Invalid data passed to Uri parameter.")
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction $ErrorActionPreference
        }
        else {
            $tcpConnectionTestResults = Test-TcpConnection -DNSHostName $targetUri.DnsSafeHost -Port $targetUri.Port

            [bool]$canConnect = $tcpConnectionTestResults.Connected
            if ($canConnect) {
                try {
                    # Get response headers:
                    $iwrParams = @{
                        Uri                      = $targetUri.AbsoluteUri
                        AllowInsecureRedirect    = $true
                        ConnectionTimeoutSeconds = 60
                        ErrorAction              = "SilentlyContinue"
                        MaximumRedirection       = 0
                        SkipCertificateCheck     = $true
                        SkipHttpErrorCheck       = $true
                    }

                    if ($PSBoundParameters.ContainsKey("Headers")) {
                        if ($iwrParams.ContainsKey("Headers")) {
                            $iwrParams.Remove("Headers")
                            $iwrParams.Add("Headers", $Headers)
                        }
                    }

                    $httpResponse = Invoke-WebRequest @iwrParams

                    $responseHeaders = $null
                    [int]$httpStatusCode = 0
                    if ($null -eq $httpResponse) {
                        Write-Error -Exception $WebException -Category ResourceUnavailable -ErrorAction $ErrorActionPreference
                    }
                    else {
                        $responseHeaders = $httpResponse | Select-Object -ExpandProperty Headers -ErrorAction $ErrorActionPreference
                    }

                    [System.Collections.Hashtable]$responseHeaderTable = $responseHeaders

                    [string]$ipAddress = ""
                    if ($PSBoundParameters.ContainsKey("IncludeTargetInformation")) {
                        $ipAddress = $tcpConnectionTestResults | Select-Object -ExpandProperty IPAddress

                        $hostName = $targetUri.DnsSafeHost
                        $absoluteUri = $targetUri.AbsoluteUri
                        $port = $targetUri.Port

                        if (-not($responseHeaderTable.ContainsKey("HostName"))) {
                            $responseHeaderTable.Add("HostName", $hostName)
                        }

                        if (-not($responseHeaderTable.ContainsKey("IPAddress"))) {
                            $responseHeaderTable.Add("IPAddress", $ipAddress)
                        }

                        if (-not($responseHeaderTable.ContainsKey("Port"))) {
                            $responseHeaderTable.Add("Port", $port)
                        }

                        if (-not($responseHeaderTable.ContainsKey("Uri"))) {
                            $responseHeaderTable.Add("Uri", $absoluteUri)
                        }
                    }

                    if ($PSBoundParameters.ContainsKey("IncludeHttpStatusCode")) {
                        $httpStatusCode = $httpResponse.StatusCode
                        $responseHeaderTable.Add("StatusCode", $httpStatusCode)
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
                    Write-Error -Exception $WebException -Category ResourceUnavailable -ErrorAction $ErrorActionPreference
                }
            }
            else {
                Write-Error -Exception $WebException -Category ConnectionError -ErrorAction $ErrorActionPreference
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
                IPAddress                         : 23.56.210.93
                Port                              : 443
                SerialNumber                      : 33009F7B734DB0480411EB0BBA0000009F7B73
                Thumbprint                        : C0CF0C1580E20618EA15357FC1028622518DDC4D
                Subject                           : CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, S=WA, C=US
                SubjectKeyIdentifier              : 0A27CADD90615213B8B28160508ECC41BD2F4D7E
                Issuer                            : CN=Microsoft Azure RSA TLS Issuing CA 04, O=Microsoft Corporation, C=US
                CertificateChain                  : {[Subject]
                                                    CN=www.microsoft.com, O=Microsoft Corporation, L=Redmond, S=WA, C=US

                                                    [Issuer]
                                                    CN=Microsoft Azure RSA TLS Issuing CA 04, O=Microsoft Corporation, C=US

                                                    [Serial Number]
                                                    33009F7B734DB0480411EB0BBA0000009F7B73

                                                    [Not Before]
                                                    8/26/2024 12:01:06 PM

                                                    [Not After]
                                                    8/21/2025 12:01:06 PM

                                                    [Thumbprint]
                                                    C0CF0C1580E20618EA15357FC1028622518DDC4D
                                                    , [Subject]
                                                    CN=Microsoft Azure RSA TLS Issuing CA 04, O=Microsoft Corporation, C=US

                                                    [Issuer]
                                                    CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US

                                                    [Serial Number]
                                                    09F96EC295555F24749EAF1E5DCED49D

                                                    [Not Before]
                                                    6/7/2023 8:00:00 PM

                                                    [Not After]
                                                    8/25/2026 7:59:59 PM

                                                    [Thumbprint]
                                                    BE68D0ADAA2345B48E507320B695D386080E5B25
                                                    , [Subject]
                                                    CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US

                                                    [Issuer]
                                                    CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US

                                                    [Serial Number]
                                                    033AF1E6A711A9A0BB2864B11D09FAE5

                                                    [Not Before]
                                                    8/1/2013 8:00:00 AM

                                                    [Not After]
                                                    1/15/2038 7:00:00 AM

                                                    [Thumbprint]
                                                    DF3C24F9BFD666761B268073FE06D1CC8D4F82A4
                                                    }
                CertificateIsTrusted              : True
                ValidFrom                         : 8/26/2024 12:01:06 PM
                ValidTo                           : 8/21/2025 12:01:06 PM
                CertificateValidityPeriodInYears  : 1
                CertificateValidityPeriodInDays   : 360
                CertificateIsExpired              : False
                CertificateSubjectMatchesHostName : True
                IsWildcardCertificate             : False
                IsSelfSignedCertificate           : False
                SignatureAlgorithm                : sha384RSA
                NegotiatedCipherSuites            : {TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_AES_256_GCM_SHA384}
                CipherAlgorithm                   : Aes256
                CipherStrength                    : 256
                KeyExchangeAlgorithm              : ECDH Ephemeral
                KeySize                           : 2048
                StrictTransportSecurity           : Strict-Transport-Security not found in header
                SubjectAlternativeNames           : {wwwqa.microsoft.com, www.microsoft.com, staticview.microsoft.com, i.s-microsoft.comΓÇª}
                Ssl2                              : False
                Ssl3                              : False
                Tls                               : False
                Tls11                             : False
                Tls12                             : True
                Tls13                             : True

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
    PROCESS {
        [string]$targetHost = ""
        [string]$targetPort = ""
        [string]$targetUri = ""

        if ($PSBoundParameters.ContainsKey("Uri")) {
            if ((Test-Uri -InputString $Uri) -and ($Uri.Scheme -eq "https")) {
                $targetHost = $Uri.DnsSafeHost
                $targetPort = $Uri.Port
                $targetUri = $Uri
            }
            else {
                $argumentExceptionMessage = "Provided value is not a valid URI or does not contain the necessary https:// prefix."
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

        [bool]$handshakeSucceeded = $false

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

            try {
                $sslCert = Get-WebServerCertificate -TargetHost $targetHost -Port $targetPort

                # Obtain certificate chain:
                $fullCertChain = Get-X509CertificateChain -Certificate $sslCert

                if ($null -eq $fullCertChain) {
                    $webExceptionMessage = "Unable to establish TLS session with {0} over port {1}." -f $targetHost, $targetHost
                    $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
                    throw $WebException
                }

                [string]$subjectKeyIdentifier = ""
                $subjectKeyIdentifier = $sslCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.14" } | Select-Object -ExpandProperty SubjectKeyIdentifier
                if ($null -eq $subjectKeyIdentifier ) {
                    $subjectKeyIdentifier = "Unable to determine Subject Key Identifier."
                }

                $tlsInfo.CertificateIsTrusted = $sslCert.Verify()
                $tlsInfo.ValidFrom = $sslCert.NotBefore
                $tlsInfo.ValidTo = $sslCert.NotAfter
                $tlsInfo.CertificateValidityPeriodInYears = [Math]::Round((($sslCert.NotAfter - $sslCert.NotBefore).Days * 0.00273973), 1)
                $tlsInfo.CertificateValidityPeriodInDays = ($sslCert.NotAfter - $sslCert.NotBefore).Days
                $tlsInfo.CertificateIsExpired = ($sslCert.NotAfter -le (Get-Date))
                $tlsInfo.SerialNumber = $sslCert.GetSerialNumberString()
                $tlsInfo.Thumbprint = $sslCert.Thumbprint
                $tlsInfo.Subject = $sslCert.Subject
                $tlsInfo.SubjectKeyIdentifier = $subjectKeyIdentifier
                $tlsInfo.Issuer = $sslCert.Issuer
                $tlsInfo.CertificateChain = $fullCertChain
                $handshakeSucceeded = $true
            }
            catch {
                $cryptographicExceptionMessage = $_.Exception.Message
                $CryptographicException = New-Object -TypeName CryptographicException -ArgumentList $cryptographicExceptionMessage
                Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction $ErrorActionPreference
            }

            if ($handshakeSucceeded) {
                # Get HTTP Strict Transport Security values:
                [string]$strictTransportSecurityValue = "No value specified for strict transport security (HSTS)"
                try {
                    [Hashtable]$responseHeaders = Get-HttpResponseHeader -Uri $targetUri -AsHashtable -ErrorAction Stop

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
                        $sansList += "No subject alternative names found on this certificate"
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
                [Boolean]$certSubjectMatchesHostName = $false

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

                # Determine if certificate is a wildcard certifcate from cert subject and SANs:
                [bool]$wildcardFound = $false
                foreach ($name in $validHostNames) {
                    if ($name.StartsWith("*")) {
                        $wildcardFound = $true
                        break
                    }
                }

                # Construct a list of wildcard entries:
                $wildcardEntries = [List[String]]::new()
                if ($wildcardFound) {
                    foreach ($name in $validHostNames) {
                        if ($name.Contains("*")) {
                            $wcEntry = $name.Replace("*.", "")
                            if (-not($wildcardEntries.Contains($wcEntry))) {
                                $wildcardEntries.Add($wcEntry)
                            }
                        }
                    }
                }

                $certSubjectMatchesHostName = $sslCert.MatchesHostname($targetHost, $true, $true)

                $tlsInfo.CertificateSubjectMatchesHostName = $certSubjectMatchesHostName
                $tlsInfo.IsWildcardCertificate = $wildcardFound

                [bool]$isSelfSigned = $sslCert.Subject -eq $sslCert.Issuer
                $tlsInfo.IsSelfSignedCertificate = $isSelfSigned

                #!SECTION

                # SECTION Obtain TLS version and strength information

                $tlsInfo.SignatureAlgorithm = $sslCert.SignatureAlgorithm.FriendlyName

                # Determine public key size from private function if running in Windows and MacOS only:
                if (-not($IsLinux)) {
                    $tlsInfo.KeySize = Get-PublicKeySize -Certificate $sslCert
                }

                # Test TLS versions and obtain relevant info to return:
                $tlsVersionResults = Test-TlsVersion -HostName $targetHost -Port $targetPort
                $tlsInfo.NegotiatedCipherSuites = $tlsVersionResults.NegotiatedCipherSuites
                $tlsInfo.CipherAlgorithm = $tlsVersionResults.CipherAlgorithm
                $tlsInfo.CipherStrength = $tlsVersionResults.CipherStrength

                if ($tlsVersionResults.KeyExchangeAlgorithm) {
                    $tlsInfo.KeyExchangeAlgorithm = $tlsVersionResults.KeyExchangeAlgorithm
                }
                else {
                    $tlsInfo.KeyExchangeAlgorithm = "Unable to determine key exchange algorithm."
                }

                $tlsInfo.Ssl2 = $tlsVersionResults.Ssl2
                $tlsInfo.Ssl3 = $tlsVersionResults.Ssl3
                $tlsInfo.Tls = $tlsVersionResults.Tls
                $tlsInfo.Tls11 = $tlsVersionResults.Tls11
                $tlsInfo.Tls12 = $tlsVersionResults.Tls12
                $tlsInfo.Tls13 = $tlsVersionResults.Tls13

                #!SECTION

                return $tlsInfo
            }
        }
        else {
            $webExceptionMessage = "Unable to connect to {0} over the following port: {1}" -f $targetHost, $targetPort
            $WebException = New-Object -TypeName WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction $ErrorActionPreference
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


function Get-IPAddressInformation {
    <#
    .SYNOPSIS
        Returns information for a specified IP address.
    .DESCRIPTION
        Returns geolocation and hosting information for a specified IP address by calling the ipinfo.io REST API. This function can take an optional API key from ipinfo.io. For more on this, see the .NOTES section.
    .EXAMPLE
        #requires -Module Microsoft.PowerShell.SecretManagement
        $secretName = 'ipinfo_api_key'
        $key = Get-Secret -Name $secretName -AsPlainText
        $targetIPAddress = "13.107.213.36"
        Get-IPAddressInformation -IPAddress $targetIPAddress -ApiKey $key

        Obtains IP address geolocation data for 13.107.213.36
    .EXAMPLE
        #requires -Module Microsoft.PowerShell.SecretManagement
        $PSDefaultParameterValues = @{
            "Get-IPAddressInformation:ApiKey"=(Get-Secret -Name 'ipinfo_api_key'-AsPlainText)
        }
        $targetIPAddress = "13.107.213.36"
        Get-IPAddressInformation -IPAddress $targetIPAddress

        Define default value for ApiKey param to be stored in the users profile defined in $PROFILE and obtains IP address geolocation data for 13.107.213.36.
    .PARAMETER IPAddress
        The IP address to obtain for.
    .PARAMETER ApiKey
        The ipinfo.io REST API key.
    .NOTES
        In order to obtain an API key for this function, please see the following: https://ipinfo.io/developers
    .LINK
        Get-Secret
        https://ipinfo.io/developers
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.secretmanagement
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parameters_default_values
    #>
    [CmdletBinding()]
    [Alias('gipi', 'Get-IPInformation', 'Get-IPInfo')]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)][Alias('ip', 'i')][String]$IPAddress,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1)][Alias('Secret', 'k', 'ak', 's')][String]$ApiKey

    )
    BEGIN {
        [Uri]$baseUri = "https://ipinfo.io"

        $headers = @{}
        if ($PSBoundParameters.ContainsKey("ApiKey")) {
            $headers.Add("Authorization", "Bearer $ApiKey")
        }
    }
    PROCESS {
        if (-not(Test-IPAddress -InputString $IPAddress)) {
            $argExcepMessage = "Invalid data was passed to the IPAddress parameter."
            $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $argExcepMessage
            Write-Error -Exception $ArgumentException -ErrorAction $ErrorActionPreference
        }
        else {
            $targetUrl = "{0}/{1}" -f $baseUri, $IPAddress

            try {
                $response = $null

                $irmParams = @{
                    Method      = "Get"
                    Uri         = $targetUrl
                    ErrorAction = "Stop"
                }

                if ($PSBoundParameters.ContainsKey("ApiKey")) {
                    $irmParams.Add("Headers", $headers)
                }

                $response = Invoke-RestMethod @irmParams

                Write-Output -InputObject $response

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
            Specifies the request headers for all web requests in the crawl as a hash table. Note that this header collection is for the base URI as well as all crawled sites from discovered links. This parameter is optional.
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
                - IPAddress: the resolved IPv4 address for the given URI
                - Port: The TCP port for the given URI
                - StatusCode: The HTTP status code returned for the visited link.
                - StatusDescription: The status description returned for the visited link.
                - ResponseHeaders: The HTTP response headers expressed as a hashtable
                - Cookies: The HTTP cookies returned from the request to the target URI
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
        # Determines if headers are being passed and if so populates a global variable to pass them to the base URI and every crawled site:
        [bool]$hasHeaders = $false
        [System.Collections.Hashtable]$headerCollection = @{}
        if ($PSBoundParameters.ContainsKey("Headers")) {
            $hasHeaders = $true
            $headerCollection = $Headers
        }

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
                    ConnectionTimeoutSeconds       = 10
                }

                if ($hasHeaders) {
                    $iwrParams.Add("Headers", $headerCollection)
                }

                $parsedUri = [Uri]::new($targetUri)
                $targetHost = $parsedUri.Host
                $targetPort = $parsedUri.Port

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

                [string]$targetIP = ""
                try {
                    $targetIP = Resolve-DNSHostName -DNSHostName $targetHost
                }
                catch {
                    $targetIP = ""
                }

                $webCrawlResultHashtable = [ordered]@{
                    BaseUri           = $BaseUri.AbsoluteUri
                    Uri               = $targetUri
                    HostName          = $targetHost
                    IPAddress         = $targetIP
                    Port              = $targetPort
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


function Get-Whois {
    <#
        .SYNOPSIS
            Retrieves WHOIS information for a specified domain.
        .DESCRIPTION
            The Get-Whois function fetches WHOIS information for a given domain name and returns it as a PowerShell custom object.
        .PARAMETER Domain
            The domain name for which to retrieve WHOIS information. This parameter is mandatory, and it accepts input from the pipeline.
        .INPUTS
            A String is received by the Domain parameter.
        .OUTPUTS
            PSCustomObject
                The function outputs a custom object containing WHOIS information for the specified domain.
        .NOTES
            * This function is only compatible with Linux. If run on a non-Linux system, it will throw an error.
            * The function relies on the `whois`, 'awk', and 'sed command-line tools being available on the system. If these tool are not found, the function will throw a terminating error.=
        .EXAMPLE
                Get-Whois -Domain "example.com"

                Retrieves the WHOIS information for the domain "example.com".

        .EXAMPLE
                "example.com" | Get-Whois

                Passes the domain "example.com" through the pipeline to retrieve WHOIS information.

        .EXAMPLE
                Get-Whois "example.com"

                An alternative syntax using positional parameter.
        .EXAMPLE
                Get-Whois -Domain "example.com" | Select-Object Domain, ExpirationDate

                Retrieves WHOIS information for "example.com" and selects only the domain name and expiration date from the output.
        .LINK
            https://who.is/
    #>
    [CmdletBinding()]
    [Alias('pswhois', 'Get-DnsWhois')]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)][ValidateLength(1, 250)][Alias('d')][String]$Domain
    )
    BEGIN {
        if (-not($IsLinux)) {
            $ApplicationException = [System.ApplicationException]::new("This function is only compatible with Linux.")
            Write-Error -Exception $ApplicationException -Category InvalidOperation -ErrorAction Stop
        }

        $dependencyList = @('whois', 'awk', 'sed')
        foreach ($dependency in $dependencyList) {
            try {
                Get-Command -Name $dependency -ErrorAction Stop | Out-Null
            }
            catch {
                $ArgumentException = [System.ArgumentException]::new("Unable to find the following command dependency: {0}" -f $dependency)
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }
    }
    PROCESS {
        $whoisData = $null

        $ArgumentException = [System.ArgumentException]::new("No whois server is known for the value passed to the Domain parameter.")

        $whoisResults = & whois $Domain 2>$null | awk '/Domain Name:/,/DNSSEC:/' 2>$null | sed -s 's/: */,/' 2>$null

        $registrarLineCount = $whoisResults | Select-String -CaseSensitive "Registrar" | Measure-Object | Select-Object -ExpandProperty Count

        if (($whoisResults) -and ($registrarLineCount -gt 0)) {
            $resultsTable = @{"Domain" = $Domain }

            $whoisResults | ForEach-Object {
                $lineArray = $_.Split(",")
                $key = ($lineArray[0]).Replace(" ", "").Trim()
                $value = ($lineArray[1]).Trim()

                if (-not($resultsTable.ContainsKey($key))) {
                    $resultsTable.Add($key, $value)
                }
                else {
                    $priorValues = @($resultsTable.$key)
                    $currentValue = $value
                    $valueArray = $priorValues += $currentValue
                    $resultsTable.$key = $valueArray
                }
            }

            $expirationDateUTC = $null
            $expirationDateString = $resultsTable.RegistryExpiryDate

            if ($expirationDateString) {
                $expirationDateUTC = Get-Date -Date $expirationDateString -AsUTC
            }

            $resultsTable.Add("ExpirationDate", $expirationDateUTC)

            try {
                $whoisData = New-Object -TypeName PSObject -Property $resultsTable -ErrorAction Stop
            }
            catch {
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Continue
            }
        }

        if ($whoisData) {
            return $whoisData
        }
        else {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Continue
        }
    }
}


function Get-IPAddressList {
    <#
.SYNOPSIS
    Generates a list of IPv4 addresses from a given network address (Class A, B, or C).
.DESCRIPTION
    The Get-IPAddressList function takes an IPv4 network address as input and generates a list of all possible IP addresses within that subnet.
    The function expects a valid network address, meaning the last one or more octets of the address should be set to `0` to represent the network portion (e.g., `192.168.1.0` for a /24 subnet, or `10.0.0.0` for a /8 subnet).
    It works with Class A, B, and C network addresses but does not support Variable Length Subnet Masking (VLSM) or CIDR notation directly.

    Specifically, the function assumes:
    - Class A: Network addresses like `10.0.0.0` (generating all possible IPs in the range `10.x.x.x`).
    - Class B: Network addresses like `172.16.0.0` (generating all possible IPs in the range `172.16.x.x`).
    - Class C: Network addresses like `192.168.1.0` (generating all possible IPs in the range `192.168.1.x`).

    The function does not support generating IP addresses for subnets defined with more specific subnet masks (e.g., `192.168.1.128/25`) or with VLSM configurations.

    If a fully defined IP address is provided (e.g., `192.168.1.1`) where no octets are zero, the function will return that single IP address.
.PARAMETER IPV4Subnet
    Specifies the base network address (IPv4 network) from which to generate the list of IP addresses. The parameter is mandatory and supports pipeline input by both value and property name.
    The value must be a valid IPv4 address in the format of four octets, where the network portion is represented with zeroed-out host bits (e.g., `192.168.1.0` for a /24 subnet).
.INPUTS
    System.String
        The function accepts pipeline input in the form of a string representing the base IPv4 network address.
.OUTPUTS
    System.String
        The function outputs the generated IPv4 addresses as strings to the pipeline.
.EXAMPLE
    Get-IPAddressList -IPV4Subnet "192.168.1.0"

    This command will generate a list of all possible IP addresses in the `192.168.1.x` subnet (192.168.1.1 through 192.168.1.254).
.EXAMPLE
    "10.0.0.0" | Get-IPAddressList

    This example demonstrates how the function can accept input from the pipeline. The base IPv4 network address "10.0.0.0" is passed through the pipeline, and the function will output all possible IP addresses in the `10.x.x.x` range.
.EXAMPLE
    "192.168.0.0" | Get-IPAddressList | Test-TcpConnection -Port 80 -WhereConnected

    The base IPv4 subnet "192.168.0.0" is passed through the pipeline, and the Get-IPAddressList function will output all possible IP addresses in that subnet, which are then passed to Test-TcpConnection to determine what IP addresses are listening on TCP port 80.
.NOTES
    - This function works with network addresses and does not support VLSM subnets or CIDR notation directly.
    - Use a network address with one or more trailing octets set to zero (e.g., `192.168.1.0`).
    - Only the final (host) octet excludes .0 and .255 (uses range 1-254).
    - Non-host variable octets include .0 but exclude .255 (use range 0-254).
    - For Class A networks, this generates approximately 16.6 million addresses (255 × 255 × 254).
    - For Class B networks, this generates approximately 64,770 addresses (255 × 254).
    - For Class C networks, this generates 254 addresses.
.LINK
    Test-TcpConnection
#>
    [CmdletBinding()]
    [Alias('Get-IPList', 'gipl', 'Convert-SubnetToIPList', 'Expand-IPSubnet', 'New-IPAddressList')]
    [OutputType([String])]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateScript({
                try {
                    [IPAddress]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    throw "The value '$_' is not a valid IPv4 address."
                }
            })]
        [Alias('BaseNetwork', 'NetworkAddress', 'SubnetAddress', 'bn', 'na', 'sa')]
        [string]$IPV4Subnet
    )

    PROCESS {
        # Split the subnet into octets and convert to integers for easier comparison
        $octets = $IPV4Subnet.Split('.') | ForEach-Object { [int]$_ }

        # Validate that we have exactly 4 octets
        if ($octets.Count -ne 4) {
            $ArgumentException = [ArgumentException]::new("Invalid IPv4 address format: $IPV4Subnet")
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        # Determine the network class and generate IP addresses accordingly
        # Class A (e.g., 10.0.0.0/8): Last three octets are 0
        if ($octets[1] -eq 0 -and $octets[2] -eq 0 -and $octets[3] -eq 0) {
            Write-Verbose "Generating Class A network addresses for $IPV4Subnet"
            for ($i = 0; $i -le 254; $i++) {
                for ($j = 0; $j -le 254; $j++) {
                    for ($k = 1; $k -le 254; $k++) {
                        Write-Output "$($octets[0]).$i.$j.$k"
                    }
                }
            }
        }
        # Class B (e.g., 172.16.0.0/16): Last two octets are 0
        elseif ($octets[2] -eq 0 -and $octets[3] -eq 0) {
            Write-Verbose "Generating Class B network addresses for $IPV4Subnet"
            for ($i = 0; $i -le 254; $i++) {
                for ($j = 1; $j -le 254; $j++) {
                    Write-Output "$($octets[0]).$($octets[1]).$i.$j"
                }
            }
        }
        # Class C (e.g., 192.168.1.0/24): Last octet is 0
        elseif ($octets[3] -eq 0) {
            Write-Verbose "Generating Class C network addresses for $IPV4Subnet"
            for ($i = 1; $i -le 254; $i++) {
                Write-Output "$($octets[0]).$($octets[1]).$($octets[2]).$i"
            }
        }
        # Case when no octets are zero (fully specified IP address)
        else {
            Write-Warning "No zero octets found in '$IPV4Subnet'. Returning the address as-is."
            Write-Output $IPV4Subnet
        }
    }
}



function Test-PrivateIPAddress {
    <#
    .SYNOPSIS
        Determines if an IP address is private.
    .DESCRIPTION
        This function checks if an IPv4 or IPv6 address falls within the known private address ranges and returns a Boolean value.

        - IPv4 Private Ranges:
          - 10.0.0.0/8        (10.0.0.0 - 10.255.255.255)
          - 172.16.0.0/12     (172.16.0.0 - 172.31.255.255)
          - 192.168.0.0/16    (192.168.0.0 - 192.168.255.255)

        - IPv6 Private Ranges:
          - fc00::/7 (Unique Local Address)
    .PARAMETER IPAddress
        The IP address to evaluate. Accepts pipeline input.
    .OUTPUTS
        [Boolean]
        Returns `$true` if the IP is private, `$false` if it is public.

    .EXAMPLE
        Test-PrivateIPAddress -IPAddress "192.168.1.1"
        Returns: `$true`

    .EXAMPLE
        "192.168.1.1", "8.8.8.8" | Test-PrivateIPAddress
        Returns:
        ```
        True
        False
        ```
    .EXAMPLE
        Get-Content IPs.txt | Test-PrivateIPAddress
        Processes IP addresses from a text file and returns `$true` or `$false` for each.
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    [Alias("tpip", "Test-PrivateIP")]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Enter a valid IPv4 or IPv6 address.")]
        [string]$IPAddress
    )

    process {
        if (-not (Test-IPAddress -InputString $IPAddress)) {
            $argExceptionMessage = "Invalid IP address format: '$IPAddress'. Please provide a valid IPv4 or IPv6 address."
            $ArgumentException = [ArgumentException]::new($argExceptionMessage)
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction $ErrorActionPreference
        }
        else {
            # Convert string to IP object:
            $ip = [System.Net.IPAddress]::Parse($IPAddress)

            if ($ip.AddressFamily -eq 'InterNetwork') {
                # IPv4
                # Parse and split:
                $ipStringArray = $($ip.IPAddressToString).Split(".")

                [int]$firstOctet = $ipStringArray[0]
                [int]$secondOctet = $ipStringArray[1]

                # Private IPv4 ranges:
                if (
                ($firstOctet -eq 10) -or
                ($firstOctet -eq 192 -and $secondOctet -eq 168) -or
                ($firstOctet -eq 172 -and $secondOctet -ge 16 -and $secondOctet -le 31)
                ) {
                    return $true
                }
            }
            elseif ($ip.AddressFamily -eq 'InterNetworkV6') {
                # IPv6
                if ($IPAddress -match "^fc|^fd") {
                    return $true
                }
            }
            return $false
        }
    }
}

#endregion
