#
# Module manifest for module 'PSTcpIp'
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'PSTcpIp.psm1'

    # Version number of this module.
    ModuleVersion     = '6.28.2'

    # ID used to uniquely identify this module
    GUID              = '99675863-c68e-46fd-b669-0d4942004b28'

    # Author of this module
    Author            = 'Anthony Guimelli'

    # Minimum version of the PowerShell engine required by this module.
    PowerShellVersion = "7.4.2"

    # Description of the functionality provided by this module
    Description       = 'Provides cmdlets to perform various TCPIP and TLS/SSL related tasks.'

    PrivateData       = @{
        PSData = @{
            Tags       = @("TCPIP", "TCP", "network", "TLS", "SSL", "HTTP")
            LicenseUri = "https://github.com/anthonyg-1/PSTcpIp/blob/main/LICENSE"
            ProjectUri = "https://github.com/anthonyg-1/PSTcpIp"
        }
    }
}
