param(
    [Parameter(Mandatory=True)]
    [ValidateSet('sender', 'receiver')]
    [string]
    ,

    [string]
    ,

    [int]
     = 7902,

    [int]
     = 20,

    [ValidateSet('tcp', 'udp')]
    [string]
     = 'tcp',

    [string]
     = 'demo\tmp_sprint3_test\downloads'
)

 = Split-Path -Path System.Management.Automation.InvocationInfo.MyCommand.Definition -Parent
Set-Location 

function Ensure-File {
    param([string])
    if (-not (Test-Path )) {
        throw  Le fichier $InputPath est introuvable.
    }
    return (Resolve-Path ).Path
}

switch () {
    'sender' {
        if (-not ) {
            throw 'Indiquez le chemin complet vers le fichier ? partager via -Path.'
        }
         = Ensure-File 
        Write-Host Pr?paration du manifeste pour ...
        python main.py send 
        Write-Host Lancement du n?ud Archipel sur le port ...
        python main.py start --port  --share 
    }
    'receiver' {
        if (-not ) {
            throw 'Indiquez le manifeste JSON g?n?r? via -Path.'
        }
         = Ensure-File 
        Write-Host T?l?chargement via TCP/UDP depuis ...
        python main.py download  --port  --wait-seconds  --output-dir  --transport 
    }
}
