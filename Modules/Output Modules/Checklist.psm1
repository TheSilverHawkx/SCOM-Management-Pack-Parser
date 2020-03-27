function initialize($WorkDirectory ="C:\temp") {

    # Create Work Directory
    if (![System.IO.Directory]::Exists($WorkDirectory)) {
        New-Item -ItemType Directory -Path $WorkDirectory -Force
    }

    # Create Tables Folder
    $SaveFolder = New-Item -ItemType Directory -Path "$WorkDirectory" -Force
    
    return $SaveFolder.FullName
}

function Export-Table {
    Param (
        [Parameter(ValueFromPipeline)]
        [Object[]]$Table,
        [string]$SaveFolder,
        [string]$Extention
    )
    Export-Csv -InputObject $Table -NoTypeInformation -Path $($SaveFolder + "\" + $ManagementPack.ID + "." + $Extention + ".csv") 
}
function write-Checklist {
    Param (
        [Parameter(Mandatory)]
        [object]$ManagementPack,
        [string]$WorkDirectory
    )

    $SaveFolder = initialize -WorkDirectory $($($WorkDirectory.TrimEnd('\')) + "\" +$ManagementPack.ID)

    if ($ManagementPack.Monitors.count -ne 0) {
        $ManagementPack.Monitors | Where-Object {$_.Type -like "*Unit*"} | `
        Select-Object DisplayName,Type,Enabled,Target,Alerting,'Alert Priority','Alert Severity','Status','Changes' | `
        Export-Csv -NoTypeInformation -Path $($SaveFolder + "\" + $ManagementPack.ID + "." + "monitors" + ".csv") 
    }
    
    if ($ManagementPack.Rules.count -ne 0) {
        $ManagementPack.Rules | Select-Object DisplayName,Enabled,Target,'Status','Changes' | `
        Export-Csv -NoTypeInformation -Path $($SaveFolder + "\" + $ManagementPack.ID + "." + "rules" + ".csv") 
    }
}

Export-ModuleMember -Function write-Checklist