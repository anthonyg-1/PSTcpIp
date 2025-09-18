#
# Module manifest for module 'PSTcpIp'
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'PSTcpIp.psm1'

    # Version number of this module.
    ModuleVersion     = '7.8.0'

    # ID used to uniquely identify this module
    GUID              = '99675863-c68e-46fd-b669-0d4942004b28'

    # Author of this module
    Author            = 'Anthony Guimelli'

    # Minimum version of the PowerShell engine required by this module.
    PowerShellVersion = "7.4.2"

    # Description of the functionality provided by this module
    Description       = 'Provides cmdlets to perform various TCPIP and TLS/SSL related tasks.'

    FunctionsToExport = 'Test-IPAddress', 'Test-TcpConnection', 'Get-TlsCertificate', 'Get-HttpResponseHeader', 'Get-TlsInformation', 'Invoke-DnsEnumeration', 'Get-IPAddressInformation', 'Invoke-WebCrawl', 'Get-IPAddressList', 'Test-PrivateIPAddress', 'Get-Whois', 'Test-Uri'

    AliasesToExport   = 'turi', 'tip', 'ttc', 'tmap', 'gtls', 'gtlsc', 'gssl', 'Get-SslCertificate', 'Get-TlsStatus', 'gwrh', 'gtlsi', 'gtlss', 'idnse', 'dnse', 'gipi', 'Get-IPInformation', 'iwc', 'webcrawl', 'Get-IPList', 'gipl', 'Convert-SubnetToIPList', 'Expand-IPSubnet', 'New-IPAddressList', 'tpip', 'Test-PrivateIP', 'pswhois', 'Get-DnsWhois'

    PrivateData       = @{
        PSData = @{
            Tags       = @("TCPIP", "TCP", "network", "TLS", "SSL", "HTTP")
            LicenseUri = "https://github.com/anthonyg-1/PSTcpIp/blob/main/LICENSE"
            ProjectUri = "https://github.com/anthonyg-1/PSTcpIp"
        }
    }
}







