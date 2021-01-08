$RegKeyCipher = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
$CipherTDES = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"

$RegPathProtocols = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

$ProtocolsTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
$ProtocolsTLS10C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
$ProtocolsTLS10S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"

$ProtocolsTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
$ProtocolsTLS11C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
$ProtocolsTLS11S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"

$ProtocolsTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
$ProtocolsTLS12C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
$ProtocolsTLS12S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"

#-----------------------------------

# TLS 1.0
$CheckProtocolsTLS10 = Test-Path $ProtocolsTLS10
IF ($CheckProtocolsTLS10 -eq $TRUE)
{
    #ProtocolsTLS10 Path TRUE
    #write-host ("Protocols\TLS 1.0 PATH is TRUE")
}
IF ($CheckProtocolsTLS10 -eq $FALSE)
{
    #ProtocolsTLS10 Path FALSE
    #write-host ("Protocols\TLS 1.0 PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.0'
    $ProtocolsTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
}

# TLS 1.1
$CheckProtocolsTLS11 = Test-Path $ProtocolsTLS11
IF ($CheckProtocolsTLS11 -eq $TRUE)
{
    #ProtocolsTLS11 Path TRUE
    #write-host ("Protocols\TLS 1.1 PATH is TRUE")
}
IF ($CheckProtocolsTLS11 -eq $FALSE)
{
    #ProtocolsTLS11 Path FALSE
    #write-host ("Protocols\TLS 1.1 PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.1'
    $ProtocolsTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
}

# TLS 1.2
$CheckProtocolsTLS12 = Test-Path $ProtocolsTLS12
IF ($CheckProtocolsTLS12 -eq $TRUE)
{
    #ProtocolsTLS12 Path TRUE
    #write-host ("Protocols\TLS 1.2 PATH is TRUE")
}
IF ($CheckProtocolsTLS12 -eq $FALSE)
{
    #ProtocolsTLS12 Path FALSE
    #write-host ("Protocols\TLS 1.2 PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.2'
    $ProtocolsTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
}

#-----------------------------------

# TDES
$CheckCipherTDES = Test-Path $CipherTDES
IF ($CheckCipherTDES -eq $TRUE)
{
    #TDES Path TRUE
    #write-host ("Ciphers\TDES PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherTDES -Name "Enabled" -Value 0
}
IF ($CheckCipherTDES -eq $FALSE)
{
    #TDES Path FALSE
    #write-host ("Ciphers\TDES PATH is FALSE")

    #Create Path and add Val
    New-Item –Path $RegKeyCipher -Name 'Triple DES 168'
    New-ItemProperty -Path $CipherTDES -Name "Enabled" -Value 0 -PropertyType DWORD
}

#-----------------------------------

# TLS 1.0\Client
$CheckProtocolsTLS10C = Test-Path $ProtocolsTLS10C
IF ($CheckProtocolsTLS10C -eq $TRUE)
{
    #ProtocolsTLS10C Path TRUE
    #write-host ("Protocols\TLS 1.0\Client PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsTLS10C -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsTLS10C -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsTLS10C -eq $FALSE)
{
    #ProtocolsTLS10C Path FALSE
    #write-host ("Protocols\TLS 1.0\Client PATH is FALSE")
    
    $ProtocolsTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
    New-Item -Path $ProtocolsTLS10 -Name 'Client'
    
    New-ItemProperty -Path $ProtocolsTLS10C -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsTLS10C -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}
# TLS 1.0\Server
$CheckProtocolsTLS10S = Test-Path $ProtocolsTLS10S
IF ($CheckProtocolsTLS10S -eq $TRUE)
{
    #ProtocolsTLS10S Path TRUE
    #write-host ("Protocols\TLS 1.0\Server PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsTLS10S -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsTLS10S -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsTLS10S -eq $FALSE)
{
    #ProtocolsTLS10S Path FALSE
    #write-host ("Protocols\TLS 1.0\Server PATH is FALSE")
    
    $ProtocolsTLS10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
    New-Item -Path $ProtocolsTLS10 -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsTLS10S -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsTLS10S -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}

# TLS 1.1\Client
$CheckProtocolsTLS11C = Test-Path $ProtocolsTLS11C
IF ($CheckProtocolsTLS11C -eq $TRUE)
{
    #ProtocolsTLS11C Path TRUE
    #write-host ("Protocols\TLS 1.1\Client PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsTLS11C -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsTLS11C -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsTLS11C -eq $FALSE)
{
    #ProtocolsTLS11C Path FALSE
    #write-host ("Protocols\TLS 1.1\Client PATH is FALSE")
    
    $ProtocolsTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
    New-Item -Path $ProtocolsTLS11 -Name 'Client'
    
    New-ItemProperty -Path $ProtocolsTLS11C -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsTLS11C -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
}
# TLS 1.1\Server
$CheckProtocolsTLS11S = Test-Path $ProtocolsTLS11S
IF ($CheckProtocolsTLS11S -eq $TRUE)
{
    #ProtocolsTLS11S Path TRUE
    #write-host ("Protocols\TLS 1.1\Server PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsTLS11S -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsTLS11S -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsTLS11S -eq $FALSE)
{
    #ProtocolsTLS11C Path FALSE
    #write-host ("Protocols\TLS 1.1\Server PATH is FALSE")
    
    $ProtocolsTLS11 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
    New-Item -Path $ProtocolsTLS11 -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsTLS11S -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsTLS11S -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
}

# TLS 1.2\Client
$CheckProtocolsTLS12C = Test-Path $ProtocolsTLS12C
IF ($CheckProtocolsTLS12C -eq $TRUE)
{
    #ProtocolsTLS12C Path TRUE
    #write-host ("Protocols\TLS 1.2\Client PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsTLS12C -Name "Enabled" -Value 4294967295
    Set-ItemProperty -Path $ProtocolsTLS12C -Name "DisabledByDefault" -Value 0
}
IF ($CheckProtocolsTLS12C -eq $FALSE)
{
    #ProtocolsTLS12C Path FALSE
    #write-host ("Protocols\TLS 1.2\Client PATH is FALSE")
    
    $ProtocolsTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
    New-Item -Path $ProtocolsTLS12 -Name 'Client'
    
    New-ItemProperty -Path $ProtocolsTLS12C -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsTLS12C -Name "DisabledByDefault" -Value 0 -PropertyType DWORD
}
# TLS 1.2\Server
$CheckProtocolsTLS12S = Test-Path $ProtocolsTLS12S
IF ($CheckProtocolsTLS12S -eq $TRUE)
{
    #ProtocolsTLS12S Path TRUE
    #write-host ("Protocols\TLS 1.2\Server PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsTLS12S -Name "Enabled" -Value 4294967295
    Set-ItemProperty -Path $ProtocolsTLS12S -Name "DisabledByDefault" -Value 0
}
IF ($CheckProtocolsTLS12S -eq $FALSE)
{
    #ProtocolsTLS12S Path FALSE
    #write-host ("Protocols\TLS 1.2\Server PATH is FALSE")
    
    $ProtocolsTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
    New-Item -Path $ProtocolsTLS12 -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsTLS12S -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsTLS12S -Name "DisabledByDefault" -Value 0 -PropertyType DWORD
}