# ReadMe

## PSTcpIp

This PowerShell module contains functions that faciliate testing network connectivity, TLS/SSL and other network tasks.

### Tested on
:desktop_computer: `Windows 10/11`
:penguin: `Linux`
:apple: `MacOS`

### Requirements
Requires PowerShell 7 or above.

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
Test-TcpConnection -HostName mywebsite.org | Where Connected
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
        $sslCert = Get-TlsCertificate -HostName $targetHost -ErrorAction Stop

        [PSCustomObject]@{
            HostName   = $targetHost
            Subject    = $sslCert.Subject
            Expiration = $sslCert.NotAfter
        }
    }
    catch {
        Write-Warning -Message ("Unable to retrieve SSL certificate from the following host: {0}" -f $targetHost)
    }
} | Sort Expiration

# Attempts to connect to an array of hostnames on TCP port 443 and if the target host is listening obtain the TLS certificate, select the subject and expiration, and output the results as a list.
$targets = "www.mywebsite1.com", "www.mywebsite2.com", "www.mywebsite3.com", "www.mywebsite4.com"
$targets | Test-TcpConnection -Port 443 | Where Connected | Get-TlsCertificate | Select Subject, NotAfter | Format-List
```

### TLS/SSL information retrieval examples

```powershell
# Obtains TLS status on mysite.com against TCP port 443.
Get-TlsInformation -HostName mysite.com -Port 443

# Gets TLS status on "https://www.mysite.com" 
Get-TlsInformation -Uri "https://www.mysite.com"

# Attempts to connect to an array of hostnames on TCP port 443 and if the target host is listening and obtain TLS information for the target
$targets = "www.mywebsite1.com", "www.mywebsite2.com", "www.mywebsite3.com", "www.mywebsite4.com"
$targets | Test-TcpConnection -Port 443 | Where Connected | Get-TlsInformation

# Obtain a list of SANs (Subject Alternative Names) from ww.mysite.com. NOTE: This only works on Windows operating systems at this time
Get-TlsInformation -HostName www.mysite.com | Select -Expand SubjectAlternativeNames
```
