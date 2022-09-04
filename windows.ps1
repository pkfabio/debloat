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
#    Write-Host "Alterando diretório de profile"
#    New-Item -ItemType "Directory" -Path "D:\Profile" -Force | Out-Null
#    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name "ProfilesDirectory" -Type String -Value "D:\Profile"
    
# Usuário
#    Write-Host "Informe a senha para o novo usuário..."
#    $Password = Read-Host -AsSecureString
#    New-LocalUser "pk" -Password $Password -FullName "Fábio" -Description "Usuário padrão"
#    Add-LocalGroupMember -Group "Administrators" -Member "pk"
    
# Nome e Grupo do computador 
#   Rename-Computer -NewName "Fabio-pc"
#   Add-Computer -WorkGroupName "LAN"

#===========================================================================
# Tweak's
#===========================================================================

# Dump de memoria
    Write-Host "Desativando despejo de memória na inicialização..."
    Get-WmiObject -Class Win32_OSRecoveryConfiguration -EnableAllPrivileges | Set-WmiInstance -Arguments @{ DebugInfoType=0 } | Out-Null

# Histórico de Atividades
    Write-Host "Desativando histórico de atividades..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
  
# DVR de Jogos (captura de tela /xbox bar)
#    Write-Host "Desativando DVR de Jogos..."
#    Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type Hex -Value 00000000
#    Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type Hex -Value 00000000
#    Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type Hex -Value 00000000
#    Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 00000000
  
# Hibernação
    Write-Host "Desativando Hibernação..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
  
# Rede Doméstica
#    Write-Host "Desativando serviços Rede doméstica..."
#    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
#    Set-Service "HomeGroupListener" -StartupType Manual
#    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
#    Set-Service "HomeGroupProvider" -StartupType Manual
  
# Rastreamento de localização
    Write-Host "Desativando rastreamento de localização..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host "Desativando atualizações de Mapas offline"
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
  
# O&O Shutup - App antispy/privacidade
    Write-Host "Executando O&O Shutup com config recomendada"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/pkfabio/debloat/master/ooshutup10.cfg" -Destination ooshutup10.cfg
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
    ./OOSU10.exe ooshutup10.cfg /quiet
  
# Serviços
    $services = @(
        "ALG"                                          # Fornece suporte para plug-ins de protocolo de terceiros para o Compartilhamento de Conexão com a Internet
        "AJRouter"                                     # Roteia mensagens AllJoyn para os clientes AllJoyn locais
        "BcastDVRUserService_5f962"                    # Este serviço de usuário é usado para Gravações de Jogos e Transmissões Ao Vivo
        #"BDESVC"                                      # serviço de Criptografia de Unidade de Disco BitLocker
        #"BFE"                                         # Mecanismo de Filtragem Básica (BFE) (Gerencia o firewall e a segurança do protocolo da internet)
        "BluetoothUserService_5f962"                   # O serviço de usuário de Bluetooth dá suporte à funcionalidade adequada dos recursos Bluetooth relevantes para cada sessão de usuário
        #"BrokerInfrastructure"                        # Serviço de infraestrutura do Windows que controla quais tarefas de segundo plano podem ser executadas no sistema
        "BthAvctpSvc"                                  # Este é o serviço Protocolo de Transporte de Controle de Áudio e Vídeo (bluetooth)
        "CaptureService_5f962"                         # Habilita a funcionalidade de captura de tela opcional para aplicativos que chamam a API Windows.Graphics.Capture.
        "cbdhsvc_5f962"                                # Este serviço de usuário é usado para cenários de área de transferência
        "diagnosticshub.standardcollector.service"     # Serviço Coletor de Padrões de Hub de Diagnóstico. Quando executado, esse serviço coleta eventos ETW em tempo real e os processa.
        "DiagTrack"                                    # O serviço Experiências do Usuário Conectado e Telemetria habilita recursos que dão suporte a experiências de usuários conectados e no aplicativo
        "dmwappushservice"                             # Roteia as mensagens de envio por Push WAP recebidas pelo dispositivo e sincroniza as sessões de Gerenciamento de Dispositivos
        "DPS"                                          # O Serviço de Política de Diagnóstico permite detecção, solução e resolução de problemas em componentes do Windows
        "edgeupdate"                                   # Serviço de updates Edge
        "edgeupdatem"                                  # Outro serviço de update
       #"EntAppSvc"                                    # Serviço de Gerenciamento de Aplicativos Empresariais
        "Fax"                                          # Serviço de Fax
        "fhsvc"                                        # Histórico de Fax
        "FontCache"                                    # Serviço de Cache de Fontes do Windows
        #"FrameServer"                                 # Permite que vários clientes acessem os quadros de vídeo de dispositivos com câmera.
       ##"gupdate"                                     # Google Update
       ##"gupdatem"                                    # Another Google Update Service
        "iphlpsvc"                                     # Fornece conectividade em túnel usando tecnologias de transição do IPv6
        "lfsvc"                                        # Esse serviço monitora a localização atual do sistema e gerencia as cercas geográficas
        #"LicenseManager"                              # Fornece suporte de infraestrutura para a Microsoft Store
        "lmhosts"                                      # Oferece suporte ao serviço NetBIOS sobre TCP/IP (NetBT) e à resolução de nomes NetBIOS para clientes na rede
        "MapsBroker"                                   # Serviço Windows para acessar mapas baixados usando um aplicativo
        "MicrosoftEdgeElevationService"                # Outro serviço de update do Edge
        "MSDTC"                                        # Coordena as transações que incluem vários gerenciadores de recursos
        "NetTcpPortSharing"                            # Fornece a capacidade de compartilhar portas TCP no protocolo net.tcp
        "PcaSvc"                                       # Este serviço dá suporte ao PCA (Auxiliar de Compatibilidade de Programa)
        "PerfHost"                                     # Permite que usuários remotos e processos de 64 bits consultem contadores de desempenho fornecidos por DLLs de 32 bits
        "PhoneSvc"                                     # Gerencia o estado de telefonia no dispositivo
        #"PNRPsvc"                                     # Habilita a resolução de nomes de par sem servidor na Internet usando o protocolo PNRP
        #"p2psvc"                                      # Habilita a comunicação com vários participantes usando o Agrupamento Ponto a Ponto
        #"p2pimsvc"                                    # Fornece serviços de identidade para os serviços Protocolo PNRP e Agrupamento Ponto a Ponto
        "PrintNotify"                                  # Notificações de um servidor de impressão ou de uma impressora remota
        "QWAVE"                                        # Quality Windows Audio Video Experience (qWave) é uma plataforma de rede para aplicativos de streaming de áudio e vídeo (AV) em redes IP domésticas
        "RemoteAccess"                                 # Oferece serviços de roteamento a empresas em ambientes de rede local e de longa distância
        "RemoteRegistry"                               # Permite que usuários remotos modifiquem configurações do Registro neste computador
        "RetailDemo"                                   # O serviço de Demonstração de Revenda controlará a atividade do dispositivo enquanto ele estiver no modo de demonstração de revenda.
        #"RtkBtManServ"                                # Realtek Bluetooth
        "SCardSvr"                                     # Gerencia o acesso a cartões inteligentes lidos por este computador
        "seclogon"                                     # Ativa a inicialização de processos sob credenciais alternativas
        "SEMgrSvc"                                     # Gerencia pagamentos e elementos seguros baseados em comunicação a curta distância (NFC)
        "SharedAccess"                                 # Fornece serviços de conversão de endereço de rede, endereçamento, resolução de nomes e/ou prevenção contra invasão para redes domésticas ou de pequena empresa
        #"Spooler"                                     # Este serviço processa trabalhos de impressão e faz a interação com a impressora
        "stisvc"                                       # Fornece serviços de aquisição de imagem a scanners e câmeras
        #"StorSvc"                                     # Fornece serviços de habilitação para configuração de armazenamento e expansão de armazenamento externo
        "SysMain"                                      # Mantém e aprimora o desempenho do sistema com o passar do tempo
        "TrkWks"                                       # Mantém vínculos entre arquivos NTFS em um computador ou através de computadores em uma rede
        "WbioSrvc"                                     # O serviço de biometria do Windows permite que os aplicativos cliente capturem, comparem, manipulem e armazenem dados biométricos sem obter acesso direto a nenhum exemplo ou hardware de biometria
        "WerSvc"                                       # Permite que os erros sejam relatados quando os programas param de funcionar ou de responder e possibilita que soluções existentes sejam oferecidas
        "wisvc"                                        # Fornece suporte de infraestrutura para o Programa Windows Insider
        "WlanSvc"                                      # O serviço WLANSVC fornece a lógica necessária para configurar, descobrir, se conectar e desconectar de uma WLAN (rede local sem fio), conforme definido pelos padrões IEEE 802.11
        "WMPNetworkSvc"                                # Compartilha bibliotecas do Windows Media Player com outros players e dispositivos de mídia da rede por meio de Universal Plug and Play
        "WpcMonSvc"                                    # Impõe controles dos pais para contas de criança no Windows
        "WPDBusEnum"                                   # Impõe a política de grupo a dispositivos de armazenamento em massa removíveis
        "WpnService"                                   # Este serviço é executado na sessão 0 e hospeda a plataforma de notificação e o provedor conexão que manipula a conexão entre o dispositivo e o servidor WNS
        #"wscsvc"                                      # O serviço WSCSVC (Central de Segurança do Windows) monitora e relata as configurações de integridade de segurança no computador
        "WSearch"                                      # Windows Search
        ## -----> Xbox 
        "XblAuthManager"                               # Fornece serviços de autenticação e autorização para interagir com o Xbox Live
        "XblGameSave"                                  # Esse serviço sincroniza dados salvos para a opção salvar jogos habilitados no Xbox Live
        "XboxNetApiSvc"                                # Esse serviço oferece suporte a interface de programação de aplicativo Windows.Networking.XboxLive
        "XboxGipSvc"                                   # Esse serviço gerencia acessórios xbox conectados
        ## -----> Hyper-V 
        "HvHost"                                       # Oferece uma interface com o hipervisor Hyper-V para fornecer contadores de desempenho por partição para o sistema operacional do host.
        "vmicguestinterface"                           # Apresenta uma interface para o host Hyper-V interagir com os serviços específicos executados na máquina virtual
        "vmicheartbeat"                                # Monitora o estado desta máquina virtual reportando uma pulsação em intervalos regulares
        "vmickvpexchange"                              # Fornece um mecanismo de troca de dados entre a máquina virtual e o sistema operacional em execução no computador físico
        "vmicrdv"                                      # Apresenta uma plataforma para comunicação entre a máquina virtual e o sistema operacional em execução no computador físico
        "vmicshutdown"                                 # Fornece um mecanismo de desligamento do sistema operacional desta máquina virtual por meio das interfaces de gerenciamento no computador físico
        "vmictimesync"                                 # Sincroniza a hora do sistema desta máquina virtual com a hora do sistema do computador físico
        "vmicvmsession"                                # Fornece um mecanismo para gerenciar máquinas virtuais com o PowerShell por meio de sessão VM sem uma rede virtual
    )
        
    foreach ($service in $services) {
        Write-Host "Setando $service para modo de inicialização manual..."
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual
    }
  
# Sensor de Armazenamento
    Write-Host "Desativando sensor de armazenamento..."
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
  
# Telemetria
    Write-Host "Desativando Telemetria..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

    Write-Host "Desativando sugestões de Aplicativos..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

    Write-Host "Desativando Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Desativando experiências personalizadas..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

    Write-Host "Desativando ID de publicidade..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

    Write-Host "Desativando relatórios de erro..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

    Write-Host "Restringindo o Windows Update P2P apenas à rede local..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

    Write-Host "Desativando o serviço de rastreamento de diagnóstico..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled

    Write-Host "Desativando o serviço WAP Push..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled

    Write-Host "Ativando as opções do menu de inicialização (F8)..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

    Write-Host "Desativando assistência remota..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

    Write-Host "Desativando o serviço Superfetch..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
    
    # Detalhes do gerenciador de tarefas 
    If ((get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild -lt 22557) {
        Write-Host "Exibindo detalhes no gerenciador de tarefas..."
        $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
        Do {
            Start-Sleep -Milliseconds 100
            $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
        } Until ($preferences)
        Stop-Process $taskmgr
        $preferences.Preferences[28] = 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    } else {Write-Host "Patch do gerenciador de tarefas não roda em versões 22557+ devido a um bug"}

    Write-Host "Mostrando detalhes das operações de arquivo..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

    Write-Host "Ocultando o botão de vizualizar tarefas..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

    Write-Host "Ocultando ícone de pessoas..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

    Write-Host "Alterando a visualização padrão do Explorer..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

    Write-Host "Ocultando ícones de objeto 3D..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue  

    ## Aplicando Tweaks e mais Telemetria 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 00000000
#    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0000000a
#    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0000000a
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type DWord -Value 2000
#    Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "MenuShowDelay" -Type DWord -Value 0
#    Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type DWord -Value 5000
#    Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "HungAppTimeout" -Type DWord -Value 4000
#    Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "AutoEndTasks" -Type DWord -Value 1
#    Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Type DWord -Value 00001000
#    Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "WaitToKillServiceTimeout" -Type DWord -Value 00002000
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 00000000
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 00000004
#    Set-ItemProperty -Path "HKLM:\Control Panel\Mouse" -Name "MouseHoverTime" -Type DWord -Value 00000010

    # Tweaks de rede
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

    # Agrupando processos svchost.exe 
    $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ram -Force

    Write-Host "Desativando Notícias e interesses..."
#    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0

    # Remove "Notícias e interesses" da barra de tarefas
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
    
    # Remove o botão "Reunir Agora" da barra de tarefas 
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

    Write-Host "Removendo o arquivo AutoLogger e restringindo o diretório..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

    Write-Host "Desativando o serviço de rastreamento de diagnóstico..."
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled
  
# Wifi Sense
    Write-Host "Desativando Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    
# Power Throttling
    Write-Host "Desativando Power Throttling..."
#    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 00000001
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0000000
    
# Boot NumLock 
    Write-Host "Ativando NumLock no boot..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2

# Extensões de arquivos
    Write-Host "Exibindo extensões de arquivos conhecidos..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Hora UTC
    Write-Host "Setando Hora da BIOS para UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

# Efeitos Visuais
    Write-Host "Configurando efeitos visuais para desempenho..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0

# Windows apps
    $Bloatware = @(
        # Apps desnecessários
        "Microsoft.3DBuilder"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.AppConnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.BingFoodAndDrink"
        "Microsoft.BingHealthAndFitness"
        "Microsoft.BingTravel"
        "Microsoft.MinecraftUWP"
        "Microsoft.GamingServices"
        # "Microsoft.WindowsReadingList"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.Office.OneNote"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsPhone"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.XboxApp"
        "Microsoft.ConnectivityStore"
        "Microsoft.CommsPhone"
        "Microsoft.ScreenSketch"
        "Microsoft.Xbox.TCUI"
        #"Microsoft.XboxGameOverlay"
        #"Microsoft.XboxGameCallableUI"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.MixedReality.Portal"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        #"Microsoft.YourPhone"
        "Microsoft.Getstarted"
        "Microsoft.MicrosoftOfficeHub"
        # -------> Apps de parceiros
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"
        "*HotspotShieldFreeVPN*"
        # -------> Opicionais: 
        "*Microsoft.Advertising.Xaml*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
    )
    
    Write-Host "Iniciando remoção de Apps desnecessários..."
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "`t`Removendo $Bloat."
    }
    Write-Host "Fim da remoção de Apps desnecessários..."

#===========================================================================
# Windows Update
#===========================================================================

    Write-Host "Desativando atualização de drivers via Windows Update..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
    Write-Host "Disabling Windows Update automatic restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
    
    Write-Host "Ativando apenas updates de segurança..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays " -Type DWord -Value 4

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
    # Define Output variable
    $wingetResult = New-Object System.Collections.Generic.List[System.Object]
    foreach ( $node in $wingetinstall )
    {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-command winget install -e --accept-source-agreements --accept-package-agreements --silent $node | Out-Host" -Wait -WindowStyle Maximized
        $wingetResult.Add("$node`n")
    }
    $wingetResult.ToArray()
    $wingetResult | % { $_ } | Out-Host

    Write-Host "Programas instalados..."
    Write-Host $wingetResult
