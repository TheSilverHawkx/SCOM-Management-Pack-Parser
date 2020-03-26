[CmdletBinding()]
Param (
    [Parameter(Position = 0, Mandatory = $true,ParameterSetName= "FileScenario", Valuefrompipeline)]
    [string[]]$File,
    [Parameter(Position = 0, Mandatory = $true,ParameterSetName= "FolderScenario")]
    [string]$Folder,

    [Parameter(Position = 1, Mandatory = $true,ParameterSetName= "FileScenario")]
    [Parameter(Position = 1,ParameterSetName= "FolderScenario")]
    [ArgumentCompleter(
        {((get-childitem -Path "Modules\Output Modules" -Filter "*.ps*1").name.split('.')[0])}
        )]
    [ValidateScript(
            { $_ -in $((get-childitem -Path "Modules\Output Modules" -Filter "*.ps*1").name.split('.')[0]) }
        )]
    [string[]]$Mode = "Report",

    [Parameter(Position = 2, ParameterSetName= "FileScenario")]
    [Parameter(Position = 2, ParameterSetName= "FolderScenario")]
    [string]$OutputFolder = "C:\temp\"
)

Import-Module ".\Modules\Parser\Parser.psm1"
function write-report($text) {
    
    "$text" | Out-File -Append -FilePath $OutputFile 
}
function printHirarchy {
    Param (
        [object]$Node,
        [ValidateSet('Discovery','Monitor','Rule')]
        [string]$Mode,
        [int]$BaseLevel = 1
    )
    $offset = 0
    $Counter = 1
    switch ($Mode) {
        "Discovery" {
            write-report "$("`t" * ($BaseLevel + $offset))Discovery:"
            write-report "$("`t" * ($BaseLevel + $offset))$("-" *"Discovery:".length)"


            foreach ($discovery in $Node.discovery) {
                write-report "$("`t" * ($BaseLevel + $offset))$Counter.`tID: $($discovery.ID):"
                $offset++
                write-report "$("`t" * ($BaseLevel + $offset))Target: $($discovery.Target):"
                write-report "$("`t" * ($BaseLevel + $offset))Running: $($Node.Discovery.Enabled)"
                write-report "$("`t" * ($BaseLevel + $offset))Type: $($Node.Discovery.Type)"
                write-report "$("`t" * ($BaseLevel + $offset))Configuration:"

                $offset++

                $discovery.Configuration.keys | ForEach-Object {
                    if ($_ -eq "Files") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$discovery.Configuration["$_"]).File.Name)"
                    } elseif ($_ -eq "InstanceSettings") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                        $a = $_

                        $offset++
                        $Discovery.Configuration["$_"].keys | ForEach-Object {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $($Discovery.Configuration["$a"]["$_"]) "
                        }
                        $offset--
                    } elseif ($_ -like "*Expression*") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):  $(($Discovery.Configuration["$_"]).trimEnd())"
                    } elseif ($_ -eq "MembershipRules" -or $_ -eq "RegistryAttributeDefinitions") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                        $offset++
                        foreach ($rule in $Discovery.Configuration["$_"])
                        {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_) $($Counter):"
                            $offset++
                        
                            $rule.keys | ForEach-Object {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($rule["$_"]) "
                            }
                            $offset--
                            $Counter++
                        }
                        $offset--
                    } else {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_): $($Discovery.Configuration["$_"])"
                    }
                }
                $offset--
                $offset--
                $Counter++
                write-report ""
            }
        }
        "Monitor" {
            write-report "$("`t" * ($BaseLevel + $offset))Related Monitors:"
            write-report "$("`t" * ($BaseLevel + $offset))$("-" *"Related Monitors:".length)"

            foreach ($monitor in $Node) {
                if ($monitor.Type -notlike "Unit*") { continue }

                write-report "$("`t" * ($BaseLevel + $offset))$Counter. $($monitor.DisplayName):"
                $Counter++
                $offset++

                write-report "$("`t" * ($BaseLevel + $offset))Running: $($monitor.Enabled)"
                write-report "$("`t" * ($BaseLevel + $offset))Type: $($monitor.MonitorType)"
                if ($monitor.Alerting -eq "true") {
                    write-report "$("`t" * ($BaseLevel + $offset))Alert:"
                    $offset++
                    write-report "$("`t" * ($BaseLevel + $offset))Alert Severity: $($monitor.'Alert Severity')"
                    write-report "$("`t" * ($BaseLevel + $offset))Alert Priority: $($monitor.'Alert Priority')"
                    $offset--
                }
                else {
                    write-report "$("`t" * ($BaseLevel + $offset))Alert: None"
                }

                write-report "$("`t" * ($BaseLevel + $offset))Configuration:"
                $offset++
                $monitor.Configuration.keys | ForEach-Object {
                    if ($_ -eq "Files") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$monitor.Configuration["$_"]).File.Name)"
                    } elseif ($_ -eq "InstanceSettings") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                        $a = $_
                        $offset++
                        $monitor.Configuration["$a"].keys | ForEach-Object {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $($monitor.Configuration["$a"]["$_"])"
                        }
                        $offset--

                    } elseif ($_ -eq "Consolidator") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                        $offset++
                        $a = $_
                        $monitor.Configuration["$a"].keys | ForEach-Object {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $($monitor.Configuration["$a"]["$_"])"
                        }
                        $offset--
                    } elseif ($_ -like "*Expression*") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_): $(($monitor.Configuration["$_"]).trimEnd())"
                    } else {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_): $($monitor.Configuration["$_"])"
                    }
                }
                $offset--
                $offset--
            }
        }
        "Rule" {
            write-report "$("`t" * ($BaseLevel + $offset))Related Rules:"
            write-report "$("`t" * ($BaseLevel + $offset))$("-" *"Related Rules:".length)"

            foreach ($rule in $Node) {
                write-report "$("`t" * ($BaseLevel + $offset))$Counter. $($rule.DisplayName):"
                
                $Offset++
                $Counter++

                write-report "$("`t" * ($BaseLevel + $offset))Running: $($rule.Enabled)"
                if ($rule.WriteActions.Type -like "*GenerateAlert*") {
                    write-report "$("`t" * ($BaseLevel + $offset))Alert:"
                    $Offset++
                    write-report "$("`t" * ($BaseLevel + $offset))Alert Severity: $($rule.'WriteActions'.Configuration.Severity)"
                    write-report "$("`t" * ($BaseLevel + $offset))Alert Priority: $($rule.'WriteActions'.Configuration.Priority)"
                    $Offset--
                }
                else {
                    write-report "$("`t" * ($BaseLevel + $offset))Alert: None"
                }

                write-report "$("`t" * ($BaseLevel + $offset))DataSource:"
                $Offset++
                $InnerCounter = 1
                foreach ($ds in $rule.DataSources) {
                    write-report "$("`t" * ($BaseLevel + $offset))$InnerCounter. Type: $($ds.Type)"
                    $InnerCounter++
                    $offset++
                    $ds.Configuration.Keys | ForEach-Object {
                        if ($_ -eq "Files") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$ds.Configuration["$_"]).File.Name)"
                        } elseif ($_ -eq "InstanceSettings") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $offset++
                            $rule.Configuration["$a"].keys | ForEach-Object {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"]) "
                            }
                            $offset--
                        } elseif ($_ -eq "Consolidator") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $ds.Configuration["$a"].keys | ForEach-Object {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -like "*Expression*") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $(($ds.Configuration["$_"]).trimEnd()) "
                        } elseif ($_ -eq "Scheduler"){
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $ds.Configuration["$a"].keys | ForEach-Object {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } else {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$_"])"
                        }
                    }
                    $offset--
                }
                $Offset--

                if ($null -ne $rule.ConditionDetection) {
                    write-report "$("`t" * ($BaseLevel + $offset))ConditionDetection:"
                    $offset++
                    write-report "$("`t" * ($BaseLevel + $offset))1. Type: $($rule.ConditionDetection.Type)"
                    $offset++
                    $rule.ConditionDetection.Configuration.Keys | ForEach-Object { 
                        if ($_ -eq "Files") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$rule.ConditionDetection.Configuration["$_"]).File.Name)"
                        } elseif ($_ -eq "InstanceSettings") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $rule.Configuration["$_"].keys | ForEach-Object {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($rule.ConditionDetection.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -eq "Consolidator") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $offset++
                            $rule.ConditionDetection.Configuration["$a"].keys | ForEach-Object {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($rule.ConditionDetection.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -like "*Expression*") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):  $(($rule.ConditionDetection.Configuration["$_"]).trimEnd())"
                        } else {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $($rule.ConditionDetection.Configuration["$_"])"
                        }
                    }
                    $Offset--
                    $Offset--
                }
                write-report ""
                write-report "$("`t" * ($BaseLevel + $offset))WriteActions:"
                $InnerCounter = 1
                $offset++
                foreach ($wa in $rule.WriteActions) {
                    write-report "$("`t" * ($BaseLevel + $offset))$InnerCounter. Type: $($wa.Type)"
                    $InnerCounter++
                }
                $offset--

                $offset--
                write-report ""
            }
        }
    }
}
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
    $ManagementPack | Add-Member -MemberType NoteProperty -Name Name -Value $mp.Manifest.Name

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

    $ManagementPack
    #-----------------------------------------------------------------------------#
    #------------------------------Process Output---------------------------------#

    foreach ($outputMode in $Mode) {
        Import-Module ".\Modules\Output Modules\$outputMode.ps*1" -ErrorAction Continue 1> $null

        write-$outputMode

        Remove-Module $outputMode
    }
}