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
function write-table {
    Param (
        [Parameter(Mandatory)]
        [object]$ManagementPack,
        [string]$WorkDirectory
    )

    $SaveFolder = initialize -WorkDirectory $($($WorkDirectory.TrimEnd('\')) + "\" +$ManagementPack.ID)
    $ManagementPack.Dependencies | Select-Object ID,Version,Alias | `
    Export-Csv -NoTypeInformation -Path $($SaveFolder + "\" + $ManagementPack.ID + "." + "dependencies" + ".csv") 

    $ManagementPack.Classes.Discovery | Select-Object ID,Enabled,Type,Target | `
    Export-Csv -NoTypeInformation -Path $($SaveFolder + "\" + $ManagementPack.ID + "." + "discoveries" + ".csv")

    $ManagementPack.Monitors | Select-Object DisplayName,Type,Enabled,Target,MonitorType,Category,ParentMonitor,Alerting,'Alert Priority','Alert Severity' | `
    Export-Csv -NoTypeInformation -Path $($SaveFolder + "\" + $ManagementPack.ID + "." + "monitors" + ".csv") 

    $ManagementPack.Rules | Select-Object DisplayName,Enabled,Target | `
    Export-Csv -NoTypeInformation -Path $($SaveFolder + "\" + $ManagementPack.ID + "." + "rules" + ".csv") 
}

Export-ModuleMember -Function write-table