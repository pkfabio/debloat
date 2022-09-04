<#
.NOTES
   Author      : pkfabi0 @pkfabi0
   GitHub      : https://github.com/pkfabio
   Version     : 0.0.1
#>

#===========================================================================
# Programas
#===========================================================================

# .Net Framework (2,3,4)
    Enable-WindowsOptionalFeature -Online -FeatureName "NetFx4-AdvSrvs" -All
    Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All

# Winget 
    $wingetinstall = New-Object System.Collections.Generic.List[System.Object]

    $wingetinstall.Add("eloston.ungoogled-chromium")
    $wingetinstall.Add("LibreWolf.LibreWolf")
    $wingetinstall.Add("Discord.Discord")
    $wingetinstall.Add("EpicGames.EpicGamesLauncher")
    $wingetinstall.Add("Valve.Steam")
    $wingetinstall.Add("OBSProject.OBSStudio")
    $wingetinstall.Add("VideoLAN.VLC")
    $wingetinstall.Add("7zip.7zip")
    $wingetinstall.Add("KeePassXCTeam.KeePassXC")
    $wingetinstall.Add("Oracle.VirtualBox")
    $wingetinstall.Add("9P1TBXR6QDCX") # HyperX nGENUITY
    $wingetinstall.Add("WhatsApp.WhatsApp")
    
    $wingetinstall.ToArray()
    $wingetResult = New-Object System.Collections.Generic.List[System.Object]
    foreach ( $node in $wingetinstall )
    {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-command winget install -e --accept-source-agreements --accept-package-agreements --silent $node | Out-Host" -Wait -WindowStyle Maximized
        $wingetResult.Add("$node`n")
    }
    $wingetResult.ToArray()
    $wingetResult | % { $_ } | Out-Host
