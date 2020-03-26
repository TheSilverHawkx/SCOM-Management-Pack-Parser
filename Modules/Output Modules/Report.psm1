function initialize($WorkDirectory ="C:\temp",$Name) {

    # Create Work Directory
    if (![System.IO.Directory]::Exists($WorkDirectory)) {
        New-Item -ItemType Directory -Path $WorkDirectory -Force
    }

    # Create Report File
    $OutputFile = New-Item -ItemType File -Path "$WorkDirectory\$Name.txt" -Force
    return $OutputFile
}

function Write-Hirarchy {
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
            write-line "$("`t" * ($BaseLevel + $offset))Discovery:"
            write-line "$("`t" * ($BaseLevel + $offset))$("-" *"Discovery:".length)"


            foreach ($discovery in $Node.discovery) {
                write-line "$("`t" * ($BaseLevel + $offset))$Counter.`tID: $($discovery.ID):"
                $offset++
                write-line "$("`t" * ($BaseLevel + $offset))Target: $($discovery.Target):"
                write-line "$("`t" * ($BaseLevel + $offset))Running: $($Node.Discovery.Enabled)"
                write-line "$("`t" * ($BaseLevel + $offset))Type: $($Node.Discovery.Type)"
                write-line "$("`t" * ($BaseLevel + $offset))Configuration:"

                $offset++

                $discovery.Configuration.keys | ForEach-Object {
                    if ($_ -eq "Files") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$discovery.Configuration["$_"]).File.Name)"
                    } elseif ($_ -eq "InstanceSettings") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                        $a = $_

                        $offset++
                        $Discovery.Configuration["$_"].keys | ForEach-Object {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $($Discovery.Configuration["$a"]["$_"]) "
                        }
                        $offset--
                    } elseif ($_ -like "*Expression*") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_):  $(($Discovery.Configuration["$_"]).trimEnd())"
                    } elseif ($_ -eq "MembershipRules" -or $_ -eq "RegistryAttributeDefinitions") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                        $offset++
                        foreach ($rule in $Discovery.Configuration["$_"])
                        {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_) $($Counter):"
                            $offset++
                        
                            $rule.keys | ForEach-Object {
                                write-line "$("`t" * ($BaseLevel + $offset))$($_): $($rule["$_"]) "
                            }
                            $offset--
                            $Counter++
                        }
                        $offset--
                    } else {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_): $($Discovery.Configuration["$_"])"
                    }
                }
                $offset--
                $offset--
                $Counter++
                write-line ""
            }
        }
        "Monitor" {
            write-line "$("`t" * ($BaseLevel + $offset))Related Monitors:"
            write-line "$("`t" * ($BaseLevel + $offset))$("-" *"Related Monitors:".length)"

            foreach ($monitor in $Node) {
                if ($monitor.Type -notlike "Unit*") { continue }

                write-line "$("`t" * ($BaseLevel + $offset))$Counter. $($monitor.DisplayName):"
                $Counter++
                $offset++

                write-line "$("`t" * ($BaseLevel + $offset))Running: $($monitor.Enabled)"
                write-line "$("`t" * ($BaseLevel + $offset))Type: $($monitor.MonitorType)"
                if ($monitor.Alerting -eq "true") {
                    write-line "$("`t" * ($BaseLevel + $offset))Alert:"
                    $offset++
                    write-line "$("`t" * ($BaseLevel + $offset))Alert Severity: $($monitor.'Alert Severity')"
                    write-line "$("`t" * ($BaseLevel + $offset))Alert Priority: $($monitor.'Alert Priority')"
                    $offset--
                }
                else {
                    write-line "$("`t" * ($BaseLevel + $offset))Alert: None"
                }

                write-line "$("`t" * ($BaseLevel + $offset))Configuration:"
                $offset++
                $monitor.Configuration.keys | ForEach-Object {
                    if ($_ -eq "Files") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$monitor.Configuration["$_"]).File.Name)"
                    } elseif ($_ -eq "InstanceSettings") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                        $a = $_
                        $offset++
                        $monitor.Configuration["$a"].keys | ForEach-Object {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $($monitor.Configuration["$a"]["$_"])"
                        }
                        $offset--

                    } elseif ($_ -eq "Consolidator") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                        $offset++
                        $a = $_
                        $monitor.Configuration["$a"].keys | ForEach-Object {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $($monitor.Configuration["$a"]["$_"])"
                        }
                        $offset--
                    } elseif ($_ -like "*Expression*") {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_): $(($monitor.Configuration["$_"]).trimEnd())"
                    } else {
                        write-line "$("`t" * ($BaseLevel + $offset))$($_): $($monitor.Configuration["$_"])"
                    }
                }
                $offset--
                $offset--
            }
        }
        "Rule" {
            write-line "$("`t" * ($BaseLevel + $offset))Related Rules:"
            write-line "$("`t" * ($BaseLevel + $offset))$("-" *"Related Rules:".length)"

            foreach ($rule in $Node) {
                write-line "$("`t" * ($BaseLevel + $offset))$Counter. $($rule.DisplayName):"
                
                $Offset++
                $Counter++

                write-line "$("`t" * ($BaseLevel + $offset))Running: $($rule.Enabled)"
                if ($rule.WriteActions.Type -like "*GenerateAlert*") {
                    write-line "$("`t" * ($BaseLevel + $offset))Alert:"
                    $Offset++
                    write-line "$("`t" * ($BaseLevel + $offset))Alert Severity: $($rule.'WriteActions'.Configuration.Severity)"
                    write-line "$("`t" * ($BaseLevel + $offset))Alert Priority: $($rule.'WriteActions'.Configuration.Priority)"
                    $Offset--
                }
                else {
                    write-line "$("`t" * ($BaseLevel + $offset))Alert: None"
                }

                write-line "$("`t" * ($BaseLevel + $offset))DataSource:"
                $Offset++
                $InnerCounter = 1
                foreach ($ds in $rule.DataSources) {
                    write-line "$("`t" * ($BaseLevel + $offset))$InnerCounter. Type: $($ds.Type)"
                    $InnerCounter++
                    $offset++
                    $ds.Configuration.Keys | ForEach-Object {
                        if ($_ -eq "Files") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$ds.Configuration["$_"]).File.Name)"
                        } elseif ($_ -eq "InstanceSettings") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $offset++
                            $rule.Configuration["$a"].keys | ForEach-Object {
                                write-line "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"]) "
                            }
                            $offset--
                        } elseif ($_ -eq "Consolidator") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $ds.Configuration["$a"].keys | ForEach-Object {
                                write-line "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -like "*Expression*") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $(($ds.Configuration["$_"]).trimEnd()) "
                        } elseif ($_ -eq "Scheduler"){
                            write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $ds.Configuration["$a"].keys | ForEach-Object {
                                write-line "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } else {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$_"])"
                        }
                    }
                    $offset--
                }
                $Offset--

                if ($null -ne $rule.ConditionDetection.keys) {
                    write-line "$("`t" * ($BaseLevel + $offset))ConditionDetection:"
                    $offset++
                    write-line "$("`t" * ($BaseLevel + $offset))1. Type: $($rule.ConditionDetection.Type)"
                    $offset++
                    $rule.ConditionDetection.Configuration.Keys | ForEach-Object { 
                        if ($_ -eq "Files") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$rule.ConditionDetection.Configuration["$_"]).File.Name)"
                        } elseif ($_ -eq "InstanceSettings") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $rule.Configuration["$_"].keys | ForEach-Object {
                                write-line "$("`t" * ($BaseLevel + $offset))$($_): $($rule.ConditionDetection.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -eq "Consolidator") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $offset++
                            $rule.ConditionDetection.Configuration["$a"].keys | ForEach-Object {
                                write-line "$("`t" * ($BaseLevel + $offset))$($_): $($rule.ConditionDetection.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -like "*Expression*") {
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $(($rule.ConditionDetection.Configuration["$_"]).trimEnd())"
                        } else {
                            write-host $_
                            write-line "$("`t" * ($BaseLevel + $offset))$($_): $($rule.ConditionDetection.Configuration["$_"])"
                        }
                    }
                    $Offset--
                    $Offset--
                }
                write-line ""
                write-line "$("`t" * ($BaseLevel + $offset))WriteActions:"
                $InnerCounter = 1
                $offset++
                foreach ($wa in $rule.WriteActions) {
                    write-line "$("`t" * ($BaseLevel + $offset))$InnerCounter. Type: $($wa.Type)"
                    $InnerCounter++
                }
                $offset--

                $offset--
                write-line ""
            }
        }
    }
}

function write-line($text) {
    
    "$text" | Out-File -FilePath $file -Append
    
}

function write-report {
    Param (
        [Parameter(Mandatory)]
        [object]$ManagementPack,
        [string]$WorkDirectory
    )
        write-host $ManagementPack.Name,"i"
        $file = initialize -WorkDirectory $WorkDirectory -Name $ManagementPack.Name 

        write-line "$($ManagementPack.Name)"
        write-line "$('=' * $ManagementPack.Name.Length)"
        write-line ""

        write-line "Dependencies"
        write-line "$('-' * 12)"

        $ManagementPack.Dependencies | ForEach-Object {
            write-line "$($_.ID)`t$($_.Version)`t$($_.Alias)"
        }
        write-line ""
        write-line ""


        write-line "Classes"
        write-line "$('-' * 7)"
        $i = 1
        foreach ($class in $ManagementPack.Classes) {
            if ($class.IsAbstract -eq "True")
            {
                write-line "$i.`tName: $($class.DisplayName)"
                write-line "$(' ' * ("$i".Length))  ID: $($class.ID)"
                write-line "$(' ' * ("$i".Length))  Abstract: $($class.IsAbstract)"
                $i++
                write-line ""
                continue
            }
            write-line "$i. Name: $($class.DisplayName)"
            write-line "$(' ' * ("$i".Length))  ID: $($class.ID)"
            $i++
            write-line ""
            if ($class.Discovery.count -ne 0) {
                Write-Hirarchy -Node $class -Mode Discovery -BaseLevel 1
            } else {
                write-line "`tDiscovery:"
                write-line "`t$("-" *"Discovery:".length)"
                write-line "`tNone"
            }
            write-line ""

            if (($Managementpack.Monitors | where-object {$_.target -eq $class.ID -and $_.Type -like "*Unit*"}).Count -ne 0 ) {
                Write-Hirarchy -Node ($Managementpack.Monitors | where-object {$_.target -eq $class.ID}) -Mode Monitor -BaseLevel 1
            }
            else {
                write-line "`tRelated Monitors:"
                write-line "`t$("-" *"Related Monitors:".length)"
                write-line "`t`None"
            }
            write-line ""
    
            if (($ManagementPack.Rules | where-object {$_.target -eq $class.ID}).Count -ne 0 ) {

                Write-Hirarchy -Node ($ManagementPack.Rules | where-object {$_.target -eq $class.ID}) -Mode Rule -BaseLevel 1
            }
            else {
                write-line "`tRelated Rules:"
                write-line "`t$("-" *"Related Rules:".length)"
                write-line "`t`None"
            }
            write-line ""

        }
}

Export-ModuleMember -Function write-report