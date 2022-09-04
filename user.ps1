<#
.NOTES
   Author      : pkfabi0 @pkfabi0
   GitHub      : https://github.com/pkfabio
   Version     : 0.0.1
#>

#===========================================================================
# Configurações
#===========================================================================

# Profile
    Write-Host "Alterando diretório de profile..."
    New-Item -ItemType "Directory" -Path "D:\Profile" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name "ProfilesDirectory" -Type String -Value "D:\Profile"
    
# Usuário
    Write-Host "Informe a senha para o novo usuário : " -NoNewline
    $Password = Read-Host -AsSecureString
    New-LocalUser "pk" -Password $Password -FullName "Fábio" -Description "Usuário padrão"
    Add-LocalGroupMember -Group "Administradores" -Member "pk"
    
# Nome e Grupo do computador 
   Rename-Computer -NewName "Fabio2-pc"
   Add-Computer -WorkGroupName "LAN"
   Restart-Computer
