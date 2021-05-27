# ReadMe

## PSTcpIp

Contains functions that faciliate testing network connectivity, SSL/TLS and other network tasks.

## Install and Usage

Installing the module.

```powershell
# Install module
Install-Module -Name PSTcpIp -Scope CurrentUser -Repository PSGallery
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
```

### TLS/TLS certificate retrieval examples

```powershell
# Gets an SSL certificate from www.mysite.com over port 443 (default)
Get-SslCertificate -HostName www.mysite.com

# Gets an SSL certificate from www.mysite.com over port 8181
Get-SslCertificate -HostName www.mysite.com -Port 8181

# Gets an SSL certificate from www.mysite.com over port 443, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list
Get-SslCertificate -HostName www.mysite.com -Port 443 | Select Thumbprint, Subject, NotAfter | Format-List

# Gets an SSL certificate from https://www.mysite.com, selects three properties (Thumprint, Subject, NotAfter) and formats the output as a list
Get-SslCertificate -Uri https://www.mysite.com/default.htm | Select Thumbprint, Subject, NotAfter | Format-List
```
