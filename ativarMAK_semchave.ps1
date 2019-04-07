# Funções

Function Pause {
	Param(
		[string] $pauseKey,
		[string] $prompt,
		[bool] $hideKeyStrokes
	)
	
	Write-Host -NoNewLine "$prompt"
	
	do {
		$key = [Console]::ReadKey($hideKeyStrokes)
	} while($key.Key -ne $pauseKey)
	
	Write-Host
}

Function Test-isWin7OS {
param()
    Begin {
        $isWin7 = $false
    }
    Process {
        try {
           $OS = Get-WmiObject -Query "Select * from Win32_OperatingSystem" -ErrorAction Stop
        } catch {
            $isWin7 = $false
        }
        if ($OS) {
            $Version = $OS.Version -split ".",-1,1
            if ($Version[0] -eq 6 -and $Version[1] -eq 1 -and ($OS.ProductType -eq 1 -or $OS.ProductType -eq 2 -or $OS.ProductType -eq 3)) {
                $isWin7 = $true
            }
        }
        return $isWin7
    } 
    End {}
}

Function Set-O2013Key {
[CmdletBinding()]
Param(
    [parameter(Mandatory=$true)]
    [ValidatePattern('(([0-9A-Z]{5}\-)){4}([0-9A-Z]{5})$')]    
    [system.string]$Key=$null
)
Begin {
    # Verifica se estamos rodando em Admin                                    
    $usercontext = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()                                    
    $IsAdmin = $usercontext.IsInRole(544)                                                       
    if (-not($IsAdmin)) {                                    
        Write-Warning "Deve rodar PowerShell como Administrador para executar esta ação."                                    
        break
    }              
    if (Test-isWin7OS) {
        # Se está rodando Win7, verifica se o Serviço osppsvc está instalado
        try {
            Get-Service -Name osppsvc -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "Erro: O serviço de Software Proteção de Plataforma não está instalado."
            break
        }
        $Class = 'OfficeSoftwareProtectionProduct'
        $SLsvc = Get-WmiObject -Class OfficeSoftwareProtectionService
    } else {
        # Win8 and beyond
        $Class = 'SoftwareLicensingProduct'
        $SLsvc = Get-WmiObject -Class SoftwareLicensingService
    }
} 
Process {
    # Install MAK prodcut key: /inpkey
    try {
        Invoke-WmiMethod -InputObject $SLsvc -Name InstallProductKey -ArgumentList $Key -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning -Message "Falha ao instalar MAK para Office 2013"
    }
    # Activate: /act
    Get-WmiObject -Query "Select * FROM $Class WHERE PartialProductKey <> null" | 
    Where { $_.ApplicationID -eq "0ff1ce15-a989-479d-af46-f275c6370663"} | ForEach-Object -Process {
        try {
            Invoke-WmiMethod -InputObject $_ -Name Activate -ErrorAction Stop | Out-Null
            Write-Verbose -Message "Ativado com sucesso $($_.Name)"
        } catch {
            # Silently fail
        }
    }
}
End {}
}

# Execução do Script

$domain = Read-Host -Prompt "Qual dominio? aluno ou adm"

Switch($domain) {
	"aluno" { $domain = "dominio.com" }
	"adm" { $domain = "dominioadm.local" }
}

$user = Read-Host -Prompt "Entre com o usuario"
$password = Read-Host -Prompt "Entre com a senha" -AsSecureString 
$username = "$domain\$user" 

$LabName = Read-Host -Prompt "Numero do Lab"
$CompName = Read-Host -Prompt "Numero da Maquina"

if($LabName -eq "1" -Or $LabName -eq "2" -Or 	$LabName -eq "3" -Or $LabName -eq "4" -Or "5") {
	$LabName = $LabName + "LABINF"
}

[String]$Computador= "$LabName$CompName"

if(Test-isWin7OS) {
	$key = "chave_confidencial"
} else {
	$key = "chave_confidencial"
}

Set-O2013Key -Key 'chave_confidencial' -Verbose
Set-O2013Key -Key 'chave_confidencial' -Verbose
Set-O2013Key -Key 'chave_confidencial' -Verbose

#Add-Type -Assembly PresentationCore

#Write-Host "Ative o Visio 2013 agora colando a chave no Software."
#[Windows.Clipboard]::SetText("chave_confidencial")
#Pause "ENTER" "Aperte ENTER para continuar..." $true
#Write-Host "Ative o Project 2013 agora colando a chave no Software."
#[Windows.Clipboard]::SetText("chave_confidencial")
#Pause "ENTER" "Aperte ENTER para continuar..." $true

$credential = New-Object System.Management.Automation.PSCredential($username,$password) 
Rename-Computer -NewName $Computador -DomainCredential $credential
Add-Computer -DomainName $domain -Credential $credential -Options JoinWithNewName -NewName $Computador
#$System = Get-WmiObject Win32_ComputerSystem
#$ren = $System.Rename($Computador, $credential.GetNetworkCredential().Password, $credential.Username)

try {
	$all_services = Get-WmiObject -Query "SELECT * FROM SoftwareLicensingService"
	$all_services.InstallProductKey($key)
	#$service = Get-WmiObject SoftwareLicensingProduct | Where-Object { $_.PartialProductKey }
	#$service.Activate()
	$all_services.RefreshLicenseStatus()
} catch {
	cscript c:\windows\System32\slmgr.vbs /ipk $key
	cscript C:\Windows\System32\slmgr.vbs /ato
}

#[Windows.Clipboard]::SetText($key)

$resposta = Read-Host -Prompt "Deseja: (D)esligar (R)einiciar ou (N)ada?"

if($resposta.ToLower() -eq "d") {
	Stop-Computer
} elseif($resposta.ToLower() -eq "r") {
	Restart-Computer
} else {
	Write-Host "Reinicie a máquina para as alteracoes entrem em vigor."
	cmd /k
}
