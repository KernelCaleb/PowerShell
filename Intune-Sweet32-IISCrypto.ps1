# Registry Keys for /Cipher Path
$RegPathCipher = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"

$CipherAES128 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128"
$CipherAES256 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256"

$CipherDES56 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"

$CipherNULL = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL"

$CipherRC2128 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128"
$CipherRC240 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"
$CipherRC256 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128"

$CipherRC4128 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128"
$CipherRC440 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"
$CipherRC456 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"
$CipherRC464 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128"

$CipherTDES = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"

# Registry Keys for /Protocols Path
$RegPathProtocols = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

$ProtocolsHelloC = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client"
$ProtocolsHelloS = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server"

$ProtocolsPCT10C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client"
$ProtocolsPCT10S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server"

$ProtocolsSSL20C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
$ProtocolsSSL20S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
$ProtocolsSSL30C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
$ProtocolsSSL30S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"

$ProtocolsTLS10C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
$ProtocolsTLS10S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
$ProtocolsTLS11C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
$ProtocolsTLS11S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
$ProtocolsTLS12C = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
$ProtocolsTLS12S = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"

# Registry Keys for /Hashes Path
$RegPathHashes = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"

$HashesMD5 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5"

$HashesSHA = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA"
$HashesSHA256 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256"
$HashesSHA384 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384"
$HashesSHA512 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512"

# Registy Keys for /KeyExchange Path
$DiffieHellman = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman"
$ECDH = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH"
$PKCS = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS"


# Registry Keys for /Other Path
#$FipsAlgo = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
#$Crypto = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"

# Custom Functions
function Test-RegistryValue {
  param
  (
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$key,
    [Parameter(Mandatory=$true,Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]$value
  )
    $data = Get-ItemProperty -Path $key -Name $value -ErrorAction SilentlyContinue
 
    if ($data) {
        $true
    }
    else {
        $false
    }
}

#----------SCRIPT BEGIN----------

#----------Ciphers-----------

# AES128
$CheckCipherAES128 = Test-Path $CipherAES128
IF ($CheckCipherAES128 -eq $TRUE)
{
    #AES128 Path TRUE
    #write-host ("Ciphers\AES128 PATH is TRUE")
    
    #Verify/Update

    Set-ItemProperty -Path $CipherAES128 -Name "Enabled" -Value 4294967295
}
IF ($CheckCipherAES128 -eq $FALSE)
{
    #AES128 Path FALSE
    #write-host ("Ciphers\AES128 PATH is FALSE")
    
    #Create Path and add Val
    #New-Item –Path $RegPathCipher –Name 'AES 128control-m$([char]0x2215)128'
    #New-ItemProperty -Path $CipherAES128 -Name "Enabled" -Value "1" -PropertyType DWORD

    $Writable = $True
    $KeyAES128 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128”)
    #$KeyAES128.SetValue(“Enabled”, “ffffffff”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    #New-ItemProperty -Path $CipherAES128 -Name "Enabled" -Value "1" -PropertyType DWORD
    New-ItemProperty -Path $CipherAES128 -Name "Enabled" -Value 4294967295 -PropertyType DWORD
}

# AES256
$CheckCipherAES256 = Test-Path $CipherAES256
IF ($CheckCipherAES256 -eq $TRUE)
{
    #AES256 Path TRUE
    #write-host ("Ciphers\AES256 PATH is TRUE")
    
    #Verify/Update
    Set-ItemProperty -Path $CipherAES256 -Name "Enabled" -Value 4294967295
}
IF ($CheckCipherAES256 -eq $FALSE)
{
    #AES256 Path FALSE
    #write-host ("Ciphers\AES256 PATH is FALSE")
    
    #Create Path and add Val
    #$Writable = $True
    $KeyAES256 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256”)
    #$KeyAES256.SetValue(“Enabled”, “1”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherAES256 -Name "Enabled" -Value 4294967295 -PropertyType DWORD
}

# DES56
$CheckCipherDES56 = Test-Path $CipherDES56
IF ($CheckCipherDES56 -eq $TRUE)
{
    #DES56 Path TRUE
    #write-host ("Ciphers\DES56 PATH is TRUE")
    
    #Verify/Update
    Set-ItemProperty -Path $CipherDES56 -Name "Enabled" -Value 0
}
IF ($CheckCipherDES56 -eq $FALSE)
{
    #DES56 Path FALSE
    #write-host ("Ciphers\DES56 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyDES56 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56”)
    #$KeyDES56.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherDES56 -Name "Enabled" -Value 0 -PropertyType DWORD
}

# NULL
$CheckCipherNULL = Test-Path $CipherNULL
IF ($CheckCipherNULL -eq $TRUE)
{
    #NULL Path TRUE
    #write-host ("Ciphers\NULL PATH is TRUE")
    
    #Verify/Update
    Set-ItemProperty -Path $CipherNULL -Name "Enabled" -Value 0
}
IF ($CheckCipherNULL -eq $FALSE)
{
    #NULL Path FALSE
    #write-host ("Ciphers\NULL PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyNULL = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL”)
    #$KeyNULL.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherNULL -Name "Enabled" -Value 0 -PropertyType DWORD
}

# RC2 128
$CheckCipherRC2128 = Test-Path $CipherRC2128
IF ($CheckCipherRC2128 -eq $TRUE)
{
    #RC2128 Path TRUE
    #write-host ("Ciphers\RC2128 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherRC2128 -Name "Enabled" -Value 0
}
IF ($CheckCipherRC2128 -eq $FALSE)
{
    #RC2128 Path FALSE
    #write-host ("Ciphers\RC2128 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyRC2128 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128”)
    #$KeyRC2128.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherRC2128 -Name "Enabled" -Value 0 -PropertyType DWORD
}

# RC240
$CheckCipherRC240 = Test-Path $CipherRC240
IF ($CheckCipherRC240 -eq $TRUE)
{
    #RC240 Path TRUE
    #write-host ("Ciphers\RC240 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherRC240 -Name "Enabled" -Value 0
}
IF ($CheckCipherRC240 -eq $FALSE)
{
    #RC240 Path FALSE
    #write-host ("Ciphers\RC240 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyRC240 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128”)
    #$KeyRC240.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherRC240 -Name "Enabled" -Value 0 -PropertyType DWORD
}

# RC256
$CheckCipherRC256 = Test-Path $CipherRC256
IF ($CheckCipherRC256 -eq $TRUE)
{
    #RC2 56 Path TRUE
    #write-host ("Ciphers\RC2 56 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherRC256 -Name "Enabled" -Value 0
}
IF ($CheckCipherRC256 -eq $FALSE)
{
    #RC2 56 Path FALSE
    #write-host ("Ciphers\RC2 56 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyRC256 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128”)
    #$KeyRC256.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherRC256 -Name "Enabled" -Value 0 -PropertyType DWORD
}

# RC4128
$CheckCipherRC4128 = Test-Path $CipherRC4128
IF ($CheckCipherRC4128 -eq $TRUE)
{
    #RC4128 Path TRUE
    #write-host ("Ciphers\RC4 128 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherRC4128 -Name "Enabled" -Value 0
}
IF ($CheckCipherRC4128 -eq $FALSE)
{
    #RC4128 Path FALSE
    #write-host ("Ciphers\RC4 128 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyRC4128 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128”)
    #$KeyRC4128.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherRC4128 -Name "Enabled" -Value 0 -PropertyType DWORD
}

# RC440
$CheckCipherRC440 = Test-Path $CipherRC440
IF ($CheckCipherRC440 -eq $TRUE)
{
    #RC440 Path TRUE
    #write-host ("Ciphers\RC4 40 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherRC440 -Name "Enabled" -Value 0
}
IF ($CheckCipherRC440 -eq $FALSE)
{
    #RC440 Path FALSE
    #write-host ("Ciphers\RC4 40 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyRC440 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128”)
    #$KeyRC440.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherRC440 -Name "Enabled" -Value 0 -PropertyType DWORD
}

# RC456
$CheckCipherRC456 = Test-Path $CipherRC456
IF ($CheckCipherRC456 -eq $TRUE)
{
    #RC456 Path TRUE
    #write-host ("Ciphers\RC4 56 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherRC456 -Name "Enabled" -Value 0
}
IF ($CheckCipherRC456 -eq $FALSE)
{
    #RC456 Path FALSE
    #write-host ("Ciphers\RC4 56 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyRC456 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128”)
    #$KeyRC456.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherRC456 -Name "Enabled" -Value 0 -PropertyType DWORD
}

# RC464
$CheckCipherRC464 = Test-Path $CipherRC464
IF ($CheckCipherRC464 -eq $TRUE)
{
    #RC464 Path TRUE
    #write-host ("Ciphers\RC4 64 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $CipherRC464 -Name "Enabled" -Value 0
}
IF ($CheckCipherRC464 -eq $FALSE)
{
    #RC464 Path FALSE
    #write-host ("Ciphers\RC4 64 PATH is FALSE")
    
    #Create Path and add Val
    $Writable = $True
    $KeyRC464 = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128”)
    #$KeyRC464.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherRC464 -Name "Enabled" -Value 0 -PropertyType DWORD
}

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
    $Writable = $True
    $KeyTDES = (Get-Item HKLM:\).OpenSubKey(“SYSTEM”, $Writable).CreateSubKey(“CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168”)
    #$KeyTDES.SetValue(“Enabled”, “0”, [Microsoft.Win32.RegistryValueKind]::DWORD)
    New-ItemProperty -Path $CipherTDES -Name "Enabled" -Value 0 -PropertyType DWORD
}

#----------Protocols----------

# ProtocolsHelloC
$CheckProtocolsHelloC = Test-Path $ProtocolsHelloC
IF ($CheckProtocolsHelloC -eq $TRUE)
{
    #ProtocolsHelloC Path TRUE
    #write-host ("Protocols\Hello\Client PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsHelloC -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsHelloC -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsHelloC -eq $FALSE)
{
    #ProtocolsHelloC Path FALSE
    #write-host ("Protocols\Hello\Client PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'Multi-Protocol Unified Hello'
    $ProtocolsHello = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello"
    New-Item -Path $ProtocolsHello -Name 'Client'
    
    New-ItemProperty -Path $ProtocolsHelloC -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsHelloC -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}
# ProtocolsHelloS
$CheckProtocolsHelloS = Test-Path $ProtocolsHelloS
IF ($CheckProtocolsHelloS -eq $TRUE)
{
    #ProtocolsHelloS Path TRUE
    #write-host ("Protocols\Hello\Server PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsHelloS -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsHelloS -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsHelloS -eq $FALSE)
{
    #ProtocolsHelloS Path FALSE
    #write-host ("Protocols\Hello\Server PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'Multi-Protocol Unified Hello'
    $ProtocolsHello = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello"
    New-Item -Path $ProtocolsHello -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsHelloS -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsHelloS -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}

# PCT 1.0\Client
$CheckProtocolsPCT10C = Test-Path $ProtocolsPCT10C
IF ($CheckProtocolsPCT10C -eq $TRUE)
{
    #ProtocolsPCT10C Path TRUE
    #write-host ("Protocols\PCT 1.0\Client PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsPCT10C -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsPCT10C -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsPCT10C -eq $FALSE)
{
    #ProtocolsHelloC Path FALSE
    #write-host ("Protocols\PCT 1.0\Client PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'PCT 1.0'
    $ProtocolsPCT10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0"
    New-Item -Path $ProtocolsPCT10 -Name 'Client'
    
    New-ItemProperty -Path $ProtocolsPCT10C -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsPCT10C -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}
# PCT 1.0\Server
$CheckProtocolsPCT10S = Test-Path $ProtocolsPCT10S
IF ($CheckProtocolsPCT10S -eq $TRUE)
{
    #ProtocolsPCT10S Path TRUE
    #write-host ("Protocols\PCT 1.0\Server PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsPCT10S -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsPCT10S -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsPCT10S -eq $FALSE)
{
    #ProtocolsHelloS Path FALSE
    #write-host ("Protocols\PCT 1.0\Server PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'PCT 1.0'
    $ProtocolsPCT10 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0"
    New-Item -Path $ProtocolsPCT10 -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsPCT10S -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsPCT10S -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}

# SSL 2.0\Client
$CheckProtocolsSSL20C = Test-Path $ProtocolsSSL20C
IF ($CheckProtocolsSSL20C -eq $TRUE)
{
    #ProtocolsSSL20C Path TRUE
    #write-host ("Protocols\SSL 2.0\Client PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsSSL20C -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsSSL20C -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsSSL20C -eq $FALSE)
{
    #ProtocolsSSL20C Path FALSE
    #write-host ("Protocols\SSL 2.0\Client PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'SSL 2.0'
    $ProtocolsSSL20 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"
    New-Item -Path $ProtocolsSSL20 -Name 'Client'
    
    New-ItemProperty -Path $ProtocolsSSL20C -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsSSL20C -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}
# SSL 2.0\Server
$CheckProtocolsSSL20S = Test-Path $ProtocolsSSL20S
IF ($CheckProtocolsSSL20S -eq $TRUE)
{
    #ProtocolsSSL20S Path TRUE
    #write-host ("Protocols\SSL 2.0\Server PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsSSL20S -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsSSL20S -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsSSL20S -eq $FALSE)
{
    #ProtocolsSSL20S Path FALSE
    #write-host ("Protocols\SSL 2.0\Server PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'SSL 2.0'
    $ProtocolsSSL20 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"
    New-Item -Path $ProtocolsSSL20 -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsSSL20S -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsSSL20S -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}

# SSL 3.0\Client
$CheckProtocolsSSL30C = Test-Path $ProtocolsSSL30C
IF ($CheckProtocolsSSL30C -eq $TRUE)
{
    #ProtocolsSSL30C Path TRUE
    #write-host ("Protocols\SSL 3.0\Client PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsSSL30C -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsSSL30C -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsSSL30C -eq $FALSE)
{
    #ProtocolsSSL30C Path FALSE
    #write-host ("Protocols\SSL 3.0\Client PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'SSL 3.0'
    $ProtocolsSSL30 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"
    New-Item -Path $ProtocolsSSL30 -Name 'Client'
    
    New-ItemProperty -Path $ProtocolsSSL30C -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsSSL30C -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}
# SSL 3.0\Server
$CheckProtocolsSSL30S = Test-Path $ProtocolsSSL30S
IF ($CheckProtocolsSSL30S -eq $TRUE)
{
    #ProtocolsSSL30S Path TRUE
    #write-host ("Protocols\SSL 3.0\Server PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $ProtocolsSSL30S -Name "Enabled" -Value 0
    Set-ItemProperty -Path $ProtocolsSSL30S -Name "DisabledByDefault" -Value 1
}
IF ($CheckProtocolsSSL30S -eq $FALSE)
{
    #ProtocolsSSL30S Path FALSE
    #write-host ("Protocols\SSL 3.0\Server PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'SSL 3.0'
    $ProtocolsSSL30 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"
    New-Item -Path $ProtocolsSSL30 -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsSSL30S -Name "Enabled" -Value 0 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsSSL30S -Name "DisabledByDefault" -Value 1 -PropertyType DWORD
    
}

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
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.0'
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
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.0'
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
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.1'
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
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.1'
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
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.2'
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
    
    #Create Path and add Val
    New-Item –Path $RegPathProtocols –Name 'TLS 1.2'
    $ProtocolsTLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
    New-Item -Path $ProtocolsTLS12 -Name 'Server'
    
    New-ItemProperty -Path $ProtocolsTLS12S -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    New-ItemProperty -Path $ProtocolsTLS12S -Name "DisabledByDefault" -Value 0 -PropertyType DWORD
    
}

#----------Hashes----------

# HashesMD5
$CheckHashesMD5 = Test-Path $HashesMD5
IF ($CheckHashesMD5 -eq $TRUE)
{
    #HashesMD5 Path TRUE
    #write-host ("Hashes\MD5 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $HashesMD5 -Name "Enabled" -Value 4294967295
}
IF ($CheckHashesMD5 -eq $FALSE)
{
    #HashesMD5 Path FALSE
    #write-host ("Hashes\MD5 PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathHashes –Name 'MD5'
    New-ItemProperty -Path $HashesMD5 -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    
}

# HashesSHA
$CheckHashesSHA = Test-Path $HashesSHA
IF ($CheckHashesSHA -eq $TRUE)
{
    #HashesSHA Path TRUE
    #write-host ("Hashes\SHA PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $HashesSHA -Name "Enabled" -Value 4294967295
}
IF ($CheckHashesSHA -eq $FALSE)
{
    #HashesSHA Path FALSE
    #write-host ("Hashes\SHA PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathHashes –Name 'SHA'
    New-ItemProperty -Path $HashesSHA -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    
}

# HashesSHA256
$CheckHashesSHA256 = Test-Path $HashesSHA256
IF ($CheckHashesSHA256 -eq $TRUE)
{
    #HashesSHA256 Path TRUE
    #write-host ("Hashes\SHA256 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $HashesSHA256 -Name "Enabled" -Value 4294967295
}
IF ($CheckHashesSHA256 -eq $FALSE)
{
    #HashesSHA256 Path FALSE
    #write-host ("Hashes\SHA256 PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathHashes –Name 'SHA256'
    New-ItemProperty -Path $HashesSHA256 -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    
}

# HashesSHA384
$CheckHashesSHA384 = Test-Path $HashesSHA384
IF ($CheckHashesSHA384 -eq $TRUE)
{
    #HashesSHA384 Path TRUE
    #write-host ("Hashes\SHA384 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $HashesSHA384 -Name "Enabled" -Value 4294967295
}
IF ($CheckHashesSHA384 -eq $FALSE)
{
    #HashesSHA384 Path FALSE
    #write-host ("Hashes\SHA384 PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathHashes –Name 'SHA384'
    New-ItemProperty -Path $HashesSHA384 -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    
}

# HashesSHA512
$CheckHashesSHA512 = Test-Path $HashesSHA512
IF ($CheckHashesSHA512 -eq $TRUE)
{
    #HashesSHA512 Path TRUE
    #write-host ("Hashes\SHA384 PATH is TRUE")

    #Verify/Update
    Set-ItemProperty -Path $HashesSHA512 -Name "Enabled" -Value 4294967295
}
IF ($CheckHashesSHA512 -eq $FALSE)
{
    #HashesSHA512 Path FALSE
    #write-host ("Hashes\SHA384 PATH is FALSE")
    
    #Create Path and add Val
    New-Item –Path $RegPathHashes –Name 'SHA512'
    New-ItemProperty -Path $HashesSHA512 -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    
}

#----------Key Exchange----------


#DiffieHellman
$CheckDiffieHellman = Test-Path $DiffieHellman
IF ($CheckDiffieHellman -eq $TRUE)
{
    #DiffieHellman Path TRUE
    #write-host ("DiffieHellman PATH is TRUE")
    #Verify/Update
}
IF ($CheckDiffieHellman -eq $FALSE)
{
    #DiffieHellman Path FALSE
    #write-host ("DiffieHellman PATH is FALSE")
    
    #Create Path and add Val
    $KeyExchangeAlgos = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    New-Item –Path $KeyExchangeAlgos –Name "Diffie-Hellman"
    New-ItemProperty -Path $DiffieHellman -Name "Enabled" -Value 4294967295 -PropertyType DWORD
    New-ItemProperty -Path $DiffieHellman -Name "ServerMinKeyBitLength" -Value 2048 -PropertyType DWORD
    
}

#ECDH
$CheckECDH = Test-Path $ECDH
IF ($CheckECDH -eq $TRUE)
{
    #ECDH Path TRUE
    #write-host ("ECDH PATH is TRUE")
    #Verify/Update
}
IF ($CheckECDH -eq $FALSE)
{
    #ECDH Path FALSE
    #write-host ("ECDH PATH is FALSE")
    
    #Create Path and add Val
    $KeyExchangeAlgos = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    New-Item –Path $KeyExchangeAlgos –Name "ECDH"
    New-ItemProperty -Path $ECDH -Name "Enabled" -Value 4294967295 -PropertyType DWORD
}

#PKCS
$CheckPKCS = Test-Path $ECDH
IF ($CheckPKCS -eq $TRUE)
{
    #PKCS Path TRUE
    #write-host ("PKCS PATH is TRUE")
    #Verify/Update
}
IF ($CheckPKCS -eq $FALSE)
{
    #PKCS Path FALSE
    #write-host ("PKCS PATH is FALSE")
    
    #Create Path and add Val
    $KeyExchangeAlgos = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    New-Item –Path $KeyExchangeAlgos –Name "PKCS"
    New-ItemProperty -Path $PKCS -Name "Enabled" -Value 4294967295 -PropertyType DWORD
}

#----------Other-----------


#----------END SCRIPT----------