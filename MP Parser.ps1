[CmdletBinding()]
Param (
    [Parameter(Position = 0, Mandatory = $true,ParameterSetName= "FileScenario", Valuefrompipeline)]
    [string[]]$File,
    [Parameter(Position = 0, Mandatory = $true,ParameterSetName= "FolderScenario")]
    [string]$Folder,

    [Parameter(Position = 1, Mandatory = $true,ParameterSetName= "FileScenario")]
    [Parameter(Position = 1,ParameterSetName= "FolderScenario")]
    [ArgumentCompleter(
        {(get-childitem -Path "Modules\Output Modules" -Filter "*.ps*1").Basename}
        )]
    [ValidateScript(
            { $_ -in $(get-childitem -Path "Modules\Output Modules" -Filter "*.ps*1").Basename }
        )]
    [string[]]$Mode = "Report",

    [Parameter(Position = 2, ParameterSetName= "FileScenario")]
    [Parameter(Position = 2, ParameterSetName= "FolderScenario")]
    [string]$OutputFolder = "C:\temp\"
)

Import-Module ".\Modules\Parser\Parser.psm1"
function ParseManagementPackXml {
    Param (
        [string]$Path
    )
    $XMLReadersettings = New-Object System.Xml.XmlReaderSettings
    $XMLReadersettings.IgnoreComments = $true
    $XMLReadersettings.IgnoreWhitespace = $true

    $reader = [System.Xml.XmlReader]::Create("$Path",$XMLReadersettings)

    $doc = new-object System.Xml.XmlDocument
    $doc.Load($reader)
    return $doc
}

if ($PSCmdlet.ParameterSetName -eq "FileScenario") {
    foreach ($f in $File) {
        if ([System.IO.File]::Exists($f)) {
            $FilesToParse = ($File | ForEach-Object {Get-ChildItem -path $_}).FullName
        }
        else {
             Write-Host "Could not find management pack '$f'" -ForegroundColor Red
        }
    }
    if ($FilesToParse.Count -eq 0) {
        exit 1
    }
}
elseif ($PSCmdlet.ParameterSetName -eq "FolderScenario") {
    if ([System.IO.Directory]::Exists($Folder)) {
        [System.IO.FileInfo[]]$FilesToParse = (Get-ChildItem -Path $Folder -Filter '*.xml').FullName

        if ($FilesToParse.Count -eq 0) {
            Write-Host "Could not find any management pack under '$Folder'" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Could not find folder '$Folder'" -ForegroundColor Red
        exit 1
    }
}

foreach ($file in $FilesToParse) {
    Write-Host "Working on $($file)..."

    $doc = ParseManagementPackXml -Path $File
    $mp = $doc.ManagementPack
    
    $ManagementPack = New-Object System.Object

    #--------------------------------Collect Name---------------------------------#
    $ManagementPack | Add-Member -MemberType NoteProperty -Name ID -Value $mp.Manifest.Identity.ID
    $ManagementPack | Add-Member -MemberType NoteProperty -Name Name -Value ($mp.LanguagePacks.LanguagePack.DisplayStrings.ChildNodes | where-object {$_.ElementID -eq $ManagementPack.ID}).Name

    #-----------------------------------------------------------------------------#
    #-----------------------------Collect dependencies----------------------------#
    $ManagementPack | Add-Member -MemberType NoteProperty -Name Dependencies -Value (Parse-Manifest -Node $mp.Manifest)

    #-----------------------------------------------------------------------------#
    #-------------------------------Collect Classes-------------------------------#
    $ManagementPack | Add-Member -MemberType NoteProperty -Name Classes -Value (New-Object System.Collections.ArrayList)

    $mp.TypeDefinitions.EntityTypes.ClassTypes.ChildNodes | ForEach-Object {
        $ManagementPack.Classes.Add((Parse-Class -Node $_)) > $null 2>&1
    }
    
    #-----------------------------------------------------------------------------#
    #-----------------------------Collect Discoveries-----------------------------#
    $mp.Monitoring.Discoveries.ChildNodes | ForEach-Object {
        $Discovery = Parse-Discovery -Node $_
        foreach ($i in $_.DiscoveryTypes.DiscoveryClass.TypeID) {

            $ManagementPack.Classes | Where-Object {$_.ID -eq $i} | ForEach-Object {
                $_.discovery.add($Discovery) > $null 2>&1
            }
        }
    }
    
    #-----------------------------------------------------------------------------#
    #-------------------------------Collect Monitors------------------------------#
    $ManagementPack | Add-Member -MemberType NoteProperty -Name Monitors -Value (New-Object System.Collections.ArrayList)

    $mp.Monitoring.Monitors.ChildNodes | ForEach-Object {
        $Monitor = Parse-Monitor -Node $_

        $ManagementPack.Monitors.add($Monitor) > $null 2>&1
    }

    #-----------------------------------------------------------------------------#
    #------------------------------Collect Rules----------------------------------#
    $ManagementPack | Add-Member -MemberType NoteProperty -Name Rules -Value (New-Object System.Collections.ArrayList)

    $mp.Monitoring.Rules.ChildNodes | ForEach-Object  {
        $Rule = Parse-Rule -Node $_

        $ManagementPack.Rules.Add($Rule)  > $null 2>&1
    }

    #-----------------------------------------------------------------------------#
    #-------------------------Enrich From LanguagePacks---------------------------#
    $displaystrings = $mp.LanguagePacks.LanguagePack.DisplayStrings.ChildNodes | where-object {$_.SubElementID -eq $nul}

    

    Add-DisplayNames -DisplayStrings $displaystrings -ListOfObjects $ManagementPack.Classes

    Add-DisplayNames -DisplayStrings $displaystrings -ListOfObjects $ManagementPack.Rules

    Add-DisplayNames -DisplayStrings $displaystrings -ListOfObjects $ManagementPack.Monitors

    #-----------------------------------------------------------------------------#
    #------------------------------Process Output---------------------------------#

    foreach ($outputMode in $Mode) {
        Import-Module ".\Modules\Output Modules\$outputMode.ps*1" -ErrorAction Continue 1> $null
        $command = Get-Command -Module $outputMode -Name "write-*"
        &$command -ManagementPack $ManagementPack -WorkDirectory $OutputFolder

        Remove-Module $outputMode
    }
}