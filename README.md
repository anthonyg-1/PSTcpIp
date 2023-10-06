# ReadMe

## PSTcpIp

This PowerShell module contains functions that provide TCP connectivity testing as well as TLS certificate retrieval, TLS endpoint security posture, DNS record enumeration, and HTTP response header assessment.

### Tested on
:desktop_computer: `Windows 10/11`
:penguin: `Linux`
:apple: `MacOS`

### Requirements
Requires PowerShell 7.2 or above.

### Installation

```powershell
Install-Module PSTcpIp -Repository PSGallery -Scope CurrentUser
```

### TCP connection test examples

```powershell
# Tests HTTP connectivity on the server 'myserver'
Test-TcpConnection -DNSHostName 'myserver' -Port 80

# Tests LDAP connectivity on the server 'mydomaincontroller' using the parameter alias ComputerName with a boolean return value
Test-TcpConnection -ComputerName 'mydomaincontroller' -Port 389 -Quiet

# Tests SSL connectivity on the server 'mywebserver' twelve times as opposed to the default four attempts
Test-TcpConnection -DNSHostName 'mywebserver' -Port 443 -Count 12

# Tests HTTP connectivity to a host with an IPV4 address of 134.170.184.133
Test-TcpConnection -IPAddress 134.170.184.133 -Port 80

# Scans 'mywebserver' for TCP ports 80 through 445, and 5000 through 6000 with a 100 millisecond timeout
@((80..445), (5000..6000)) | % { $ports += $_ }
Test-TcpConnection -ComputerName 'mywebserver' -Port $ports -Count 1 -Timeout 100

# Determine the listening TCP ports on mywebsite.org
Test-TcpConnection -HostName mywebsite.org -ShowConnectedOnly

# Test connectivity to www.mysite1.com, www.mysite2.com over ports 80 and 443 using the aliased version of Test-TcpConnection
ttc -h www.mysite1.com, www.mysite2.com -p 80, 443
```

### TLS/SSL certificate retrieval examples

```powershell
# Gets an SSL certificate from www.mysite.com over port 443 (default)
Get-TlsCertificate -HostName www.mysite.com

# Gets an SSL certificate from www.mysite.com over port 8181
Get-TlsCertificate -HostName www.mysite.com -Port 8181

# Gets an SSL certificate from www.mysite.com over port 443, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list
Get-TlsCertificate -HostName www.mysite.com -Port 443 | Select Thumbprint, Subject, NotAfter | Format-List

# Gets an SSL certificate from https://www.mysite.com, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list
Get-TlsCertificate -Uri "https://www.mysite.com" | Select Thumbprint, Subject, NotAfter | Format-List

# Gets an SSL certificate from https://www.mysite.com including the full certificate chain and writes the full chain's thumbprint, and expiration as a list to the console
Get-TlsCertificate -HostName www.mysite.com -IncludeChain | Select Subject, Thumbprint, NotAfter | Format-List

# Generate an SSL certificate expiration report from a list of target host names
$targetHostNames = "microsoft.com", "linkedin.com", "powershellgallery.com", "github.com", "kubernetes.io", "gitlab.com"
$targetHostNames | ForEach-Object {
    $targetHost = $_
    try {
        $tlsCertInfo = Get-TlsInformation -HostName $targetHost

        [PSCustomObject]@{
            HostName             = $tlsCertInfo.HostName
            Subject              = $tlsCertInfo.Subject
            Expiration           = $tlsCertInfo.ValidTo
            CertificateIsExpired = $tlsCertInfo.CertificateIsExpired
        }
    }
    catch {
        Write-Warning -Message ("Unable to retrieve SSL certificate from the following host: {0}" -f $targetHost)
    }
} | Sort Expiration

# Attempts to connect to an array of hostnames on TCP port 443 and if the target host is listening obtain the TLS certificate, select the subject and expiration, and output the results as a list.
$targets = "www.mywebsite1.com", "www.mywebsite2.com", "www.mywebsite3.com", "www.mywebsite4.com"
$targets | Test-TcpConnection -Port 443 -ShowConnectedOnly | Get-TlsCertificate | Select Subject, NotAfter | Format-List

# Gets an SSL certificate from www.mysite.com over port 443 using the aliased version of Get-TlsCertificate
gtls -h www.mysite.com
```

### TLS/SSL information retrieval examples

```powershell
# Obtains TLS status on mysite.com against TCP port 443.
Get-TlsInformation -HostName mysite.com -Port 443

# Gets TLS status on "https://www.mysite.com" 
Get-TlsInformation -Uri "https://www.mysite.com"

# Attempts to connect to an array of hostnames on TCP port 443 and if the target host is listening and obtain TLS information for the target
$targets = "www.mywebsite1.com", "www.mywebsite2.com", "www.mywebsite3.com", "www.mywebsite4.com"
$targets | Test-TcpConnection -Port 443 -ShowConnectedOnly | Get-TlsInformation

# Obtain a list of SANs (Subject Alternative Names) from ww.mysite.com.
Get-TlsInformation -HostName www.mysite.com | Select -Expand SubjectAlternativeNames

# Gets TLS security information from https://mysite.com using the aliased version of Get-TlsInformation
gtls -u "https://mysite.com/"
```

### DNS record enumeration examples
```powershell
# Enumerates DNS record data from the mydomain.org DNS domain
Invoke-DnsEnumeration -Domain mydomain.org

# Enumerates DNS record data from the mydomain.org DNS domain using the subdomains.txt text file as input
Invoke-DnsEnumeration -Domain mydomain.org -WordListPath subdomains.txt

# Enumerates DNS record data from the mydomain.org DNS domain, tests TCP connectivity, and returns only the hosts that are listening on ports 80 and 443
Invoke-DnsEnumeration -Domain mydomain.org | Test-TcpConnection -Port 80,443 | Where Connected

# Enumerates DNS record data from the mydomain.org DNS domain, tests connectivity to TCP port 443, and obtains to obtain TLS information about the endpoint
Invoke-DnsEnumeration -Domain mydomain.org | Test-TcpConnection -Port 443 | Where Connected | Get-TlsInformation

# Enumerates DNS record data from the mydomain.org DNS domain, tests connectivity to TCP port 443, obtains to obtain TLS information about the endpoint, and generates an export report as a CSV file
Invoke-DnsEnumeration -Domain mydomain.com | Test-TcpConnection -Port 443 | 
    Where Connected | Get-TlsInformation | 
        Select HostName, IPAddress, Subject, Issuer, CertificateIsExpired, ValidFrom, ValidTo | 
            Export-Csv TlsCertificateExpirationReport.csv
```

### Active Directory server security testing

```powershell
#requires -Module ActiveDirectory

# Get all Server 2019 instances from Active Directory and determine which ones are listening on port 443:
Get-ADComputer -Filter {OperatingSystem -like "*2019*"} | Test-TcpConnection -Port 443 -Timeout 100 -ShowConnectedOnly

# Get an expiration report of LDAPS certificates from Active Directory domain controllers:
Get-ADDomainController -Filter * | Test-TcpConnection -Port 636 -ShowConnectedOnly | Get-TlsCertificate | Select Subject, NotAfter
```

### HTTP response header retrieval
```powershell
# Retrieves the HTTP response headers from the specified web endpoint:
Get-HttpResponseHeader -Uri "https://mysite.com/"

# Retrieves the HTTP response headers with the results as a Hashtable from the specified web endpoint:
Get-HttpResponseHeader -Uri "https://mysite.com/" -AsHashtable
```
