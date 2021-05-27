using namespace System
using namespace System.Net
using namespace System.Net.Sockets
using namespace System.Net.Security
using namespace System.Security.Authentication
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates


#region Load format file

$formatFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'TcpConnectionStatus.Format.PS1Xml'

if (Test-Path -Path $PSScriptRoot) { Update-FormatData -PrependPath $formatFilePath }

#endregion


#region Load config data

$jsonFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'ConfigData\TcpPorts.json'

if (-not(Test-Path -Path $jsonFilePath)) {
    $FileNotFoundException = New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ("JSON configuration file not found in the following path: {0}" -f $jsonFilePath)
    throw $FileNotFoundException
}

$tcpPortData = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json

$portTable = @{ }
foreach ($entry in $tcpPortData) {
    if (-not($portTable.ContainsKey([int]$entry.Port))) {
        $portTable.Add([int]$entry.port, $entry.description)
    }
}

New-Variable -Name tcpPortAndDescriptionData -Value $portTable -Option ReadOnly -Scope Global -Force

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

Add-Type -TypeDefinition $tcpConnectionStatusClassDef -ReferencedAssemblies System.Net.Primitives -ErrorAction Stop

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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][Alias('ComputerName', 'HostName', 'IPAddress', 'Name', 'h', 'i')][String[]]$DNSHostName,
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
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "HostName")][Alias('ComputerName', 'Name', 'h')][String]$HostName,
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = "HostName")][Alias('PortNumber', 'p')][Int]$Port = 443,
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Uri")][Uri]$Uri,
        [Parameter(Mandatory = $false, Position = 2)][ValidateSet("Tls", "Tls11", "Tls12", "Tls13")][String]$TlsVersion = "Tls12"
    )
    PROCESS {
        [X509Certificate2]$sslCert = $null

        [string]$targetHostName = ""
        [string]$targetPort = ""

        if ($PSBoundParameters.ContainsKey("Uri")) {
            $targetHostName = $Uri.Authority
            $targetPort = $Uri.Port
        }
        else {
            $targetHostName = $HostName
            $targetPort = $Port
        }

        try {
            $tcpClient = [TcpClient]::new($targetHostName, $targetPort)

            $sslStream = [SslStream]::new($tcpClient.GetStream())

            $sslStream.AuthenticateAsClient($targetHostName, $null, ([SslProtocols]::$TlsVersion), $true)

            $sslCert = [X509Certificate2]::new($sslStream.RemoteCertificate)

            $sslStream.Close()
            $sslStream.Dispose()
            $tcpClient.Close()
            $tcpClient.Dispose()
        }
        catch {
            $cryptographicExceptionMessage = "Unable to establish SSL session with {0}." -f $HostName
            $CryptographicException = New-Object -TypeName CryptographicException -ArgumentList $cryptographicExceptionMessage
            Write-Error -Exception $CryptographicException -ErrorAction Stop
        }

        return $sslCert
    }
}


#endregion


Export-ModuleMember -Function Test-TcpConnection
Export-ModuleMember -Function Get-SslCertificate

New-Alias -Name ttc -Value Test-TcpConnection -Force
New-Alias -Name gssl -Value Get-SslCertificate -Force
New-Alias -Name Get-TlsCertificate -Value Get-SslCertificate -Force

Export-ModuleMember -Alias ttc
Export-ModuleMember -Alias gssl
Export-ModuleMember -Alias Get-TlsCertificate
