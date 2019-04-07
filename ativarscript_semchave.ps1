# Este script ativa o Windows (eram usados dois Windows na época, 7 e 10)
# Depois era configurado o nome do computador para ser identificado na rede
# E por fim, os computadores eram inseridos no domínio da rede.
# Este era específico para Windows de licença Retail (KMS ou Volume)
$domain = Read-Host -Prompt "Qual dominio? aluno ou adm"

#$Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
#
#$LocalAdmin = $Computer.Create("User", "alunolocal")
#$LocalAdmin.SetPassword("aluno")
#$LocalAdmin.SetInfo()
#$LocalAdmin.FullName = "Local user by Powershell"
#$LocalAdmin.SetInfo()
#$LocalAdmin.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
#$LocalAdmin.SetInfo()

Switch($domain) {
	"aluno" { $domain = "dominio.com" }
	"adm" { $domain = "dominioadm.com" }
}

$user = Read-Host -Prompt "Entre com o usuario"
$password = Read-Host -Prompt "Entre com a senha" -AsSecureString 
$username = "$domain\$user" 

$LabName = Read-Host -Prompt "Numero do Lab"
$CompName = Read-Host -Prompt "Numero da Maquina"
Switch($LabName) {
	"1" {
		$LabName = "1LABINF"
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
			"05" { $key="chave_confidencial"; break }
			"06" { $key="chave_confidencial"; break }
			"07" { $key="chave_confidencial"; break }
			"08" { $key="chave_confidencial"; break }
			"09" { $key="chave_confidencial"; break }
			"10" { $key="chave_confidencial"; break }
			"11" { $key="chave_confidencial"; break }
			"12" { $key="chave_confidencial"; break }
			"13" { $key="chave_confidencial"; break }
			"14" { $key="chave_confidencial"; break }
			"15" { $key="chave_confidencial"; break }
			"16" { $key="chave_confidencial"; break }
			"17" { $key="chave_confidencial"; break }
			"18" { $key="chave_confidencial"; break }
			"19" { $key="chave_confidencial"; break }
			"20" { $key="chave_confidencial"; break }
		}
	}
	"2" {
		$LabName = "2LABINF"
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
			"05" { $key="chave_confidencial"; break }
			"06" { $key="chave_confidencial"; break }
			"07" { $key="chave_confidencial"; break }
			"08" { $key="chave_confidencial"; break }
			"09" { $key="chave_confidencial"; break }
			"10" { $key="chave_confidencial"; break }
			"11" { $key="chave_confidencial"; break }
			"12" { $key="chave_confidencial"; break }
			"13" { $key="chave_confidencial"; break }
			"14" { $key="chave_confidencial"; break }
			"15" { $key="chave_confidencial"; break }
			"16" { $key="chave_confidencial"; break }
			"17" { $key="chave_confidencial"; break }
			"18" { $key="chave_confidencial"; break }
			"19" { $key="chave_confidencial"; break }
			"20" { $key="chave_confidencial"; break }
		}
	}
	"3" {
		$LabName = "3LABINF"
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
			"05" { $key="chave_confidencial"; break }
			"06" { $key="chave_confidencial"; break }
			"07" { $key="chave_confidencial"; break }
			"08" { $key="chave_confidencial"; break }
			"09" { $key="chave_confidencial"; break }
			"10" { $key="chave_confidencial"; break }
			"11" { $key="chave_confidencial"; break }
			"12" { $key="chave_confidencial"; break }
			"13" { $key="chave_confidencial"; break }
			"14" { $key="chave_confidencial"; break }
			"15" { $key="chave_confidencial"; break }
			"16" { $key="chave_confidencial"; break }
			"17" { $key="chave_confidencial"; break }
			"18" { $key="chave_confidencial"; break }
			"19" { $key="chave_confidencial"; break }
			"20" { $key="chave_confidencial"; break }
		}
	}
	"4" {
		$LabName = "4LABINF"
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
			"05" { $key="chave_confidencial"; break }
			"06" { $key="chave_confidencial"; break }
			"07" { $key="chave_confidencial"; break }
			"08" { $key="chave_confidencial"; break }
			"09" { $key="chave_confidencial"; break }
			"10" { $key="chave_confidencial"; break }
			"11" { $key="chave_confidencial"; break }
			"12" { $key="chave_confidencial"; break }
			"13" { $key="chave_confidencial"; break }
			"14" { $key="chave_confidencial"; break }
			"15" { $key="chave_confidencial"; break }
			"16" { $key="chave_confidencial"; break }
			"17" { $key="chave_confidencial"; break }
			"18" { $key="chave_confidencial"; break }
			"19" { $key="chave_confidencial"; break }
			"20" { $key="chave_confidencial"; break }
		}
	}
	"shp" {
		$LabName = "SHP"
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
			"05" { $key="chave_confidencial"; break }
			"06" { $key="chave_confidencial"; break }
			"07" { $key="chave_confidencial"; break }
			"08" { $key="chave_confidencial"; break }
			"09" { $key="chave_confidencial"; break }
			"10" { $key="chave_confidencial"; break }
			"11" { $key="chave_confidencial"; break }
			"12" { $key="chave_confidencial"; break }
		}
	}
	"secretaria" {
		$LabName = "SECRETARIA"
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
			"05" { $key="chave_confidencial"; break }
			"06" { $key="chave_confidencial"; break }
		}
	}
	"coord" {
		$LabName = "COORD"
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
		}
	}
	"estudos" {
		$LabName = "ESTUDOS"
		$psswd = Read-Host -Prompt "Digite a nova senha" #-AsSecureString
		$admin = ([adsi]"WinNT://ITAUTEC/Administrador,user").SetPassword($psswd)
		Switch($CompName) {
			"01" { $key="chave_confidencial"; break }
			"02" { $key="chave_confidencial"; break }
			"03" { $key="chave_confidencial"; break }
			"04" { $key="chave_confidencial"; break }
			"05" { $key="chave_confidencial"; break }
			"06" { $key="chave_confidencial"; break }
		}
	}
}

[String]$Computador= "$LabName$CompName"

$credential = New-Object System.Management.Automation.PSCredential($username,$password) 
Rename-Computer -NewName $Computador -DomainCredential $credential
Add-Computer -DomainName $domain -Credential $credential -Options JoinWithNewName -NewName $Computador
#$System = Get-WmiObject Win32_ComputerSystem
#$ren = $System.Rename($Computador, $credential.GetNetworkCredential().Password, $credential.Username)

try {
	$all_services = Get-WmiObject -Query "SELECT * FROM SoftwareLicensingService"
	$all_services.InstallProductKey($key)
	$service = Get-WmiObject SoftwareLicensingProduct | Where-Object {$_.PartialProductKey}
	$service.Activate()
	$all_services.RefreshLicenseStatus()
} catch {
	cscript c:\windows\System32\slmgr.vbs -ipk $key
	cscript C:\Windows\System32\slmgr.vbs -ato
}

$resposta = Read-Host -Prompt "Deseja: (D)esligar (R)einiciar ou (N)ada?"

if($resposta.ToLower() -eq "d") {
	Stop-Computer
} elseif($resposta.ToLower() -eq "r") {
	Restart-Computer
} else {
	Write-Host "Reinicie a máquina para as alteracoes entrem em vigor."
	Sleep 5
}
