function initialize($WorkDirectory ="C:\temp") {

    # Create Work Directory
    if (![System.IO.Directory]::Exists($WorkDirectory)) {
        New-Item -ItemType Directory -Path $WorkDirectory -Force
    }

    # Create Report File
    $Global:OutputFile = New-Item -ItemType File -Path "$OutputFolder\$($mp_ID).txt" -Force
}

function write-line($text) {
    
    "$text" | Out-File -FilePath $Global:OutputFile -Append
    
}

function write-report {
    Param (
        [object]$ParsedMP
    )
        
        write-line "$mp_Name"
        write-line "$('=' * $mp_Name.Length)"
        write-line ""

        write-line "Dependencies"
        write-line "$('-' * 12)"

        $mp_dependencies | ForEach-Object {
            write-line "$($_.ID),$($_.Version)"
        }
        write-line ""
        write-line ""


        write-line "Classes"
        write-line "$('-' * 7)"
        $i = 1
        foreach ($class in $mp_classes) {
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
                printHirarchy -Node $class -Mode Discovery -BaseLevel 1
            } else {
                write-line "`tDiscovery:"
                write-line "`t$("-" *"Discovery:".length)"
                write-line "`tNone"
            }
            write-line ""

            if (($mp_Monitors | where-object {$_.target -eq $class.ID -and $_.Type -like "*Unit*"}).Count -ne 0 ) {
                printHirarchy -Node ($mp_Monitors | where-object {$_.target -eq $class.ID}) -Mode Monitor -BaseLevel 1
            }
            else {
                write-line "`tRelated Monitors:"
                write-line "`t$("-" *"Related Monitors:".length)"
                write-line "`t`None"
            }
            write-line ""
    
            if (($mp_Rules | where-object {$_.target -eq $class.ID}).Count -ne 0 ) {

                printHirarchy -Node ($mp_Rules | where-object {$_.target -eq $class.ID}) -Mode Rule -BaseLevel 1
            }
            else {
                write-line "`tRelated Rules:"
                write-line "`t$("-" *"Related Rules:".length)"
                write-line "`t`None"
            }
            write-line ""

        }
}

<#if ($Mode -eq "Report") {
        $OutputFile = New-Item -ItemType File -Path "$OutputFolder\$($mp_ID).txt" -Force

        write-report "$mp_Name"
        write-report "$('=' * $mp_Name.Length)"
        write-report ""

        write-report "Dependencies"
        write-report "$('-' * 12)"

        $mp_dependencies | ForEach-Object {
            write-report "$($_.ID),$($_.Version)"
        }
        write-report ""
        write-report ""


        write-report "Classes"
        write-report "$('-' * 7)"
        $i = 1
        foreach ($class in $mp_classes) {
            if ($class.IsAbstract -eq "True")
            {
                write-report "$i.`tName: $($class.DisplayName)"
                write-report "$(' ' * ("$i".Length))  ID: $($class.ID)"
                write-report "$(' ' * ("$i".Length))  Abstract: $($class.IsAbstract)"
                $i++
                write-report ""
                continue
            }
            write-report "$i. Name: $($class.DisplayName)"
            write-report "$(' ' * ("$i".Length))  ID: $($class.ID)"
            $i++
            write-report ""
            if ($class.Discovery.count -ne 0) {
                printHirarchy -Node $class -Mode Discovery -BaseLevel 1
            } else {
                write-report "`tDiscovery:"
                write-report "`t$("-" *"Discovery:".length)"
                write-report "`tNone"
            }
            write-report ""

            if (($mp_Monitors | where-object {$_.target -eq $class.ID -and $_.Type -like "*Unit*"}).Count -ne 0 ) {
                printHirarchy -Node ($mp_Monitors | where-object {$_.target -eq $class.ID}) -Mode Monitor -BaseLevel 1
            }
            else {
                write-report "`tRelated Monitors:"
                write-report "`t$("-" *"Related Monitors:".length)"
                write-report "`t`None"
            }
            write-report ""
    
            if (($mp_Rules | where-object {$_.target -eq $class.ID}).Count -ne 0 ) {

                printHirarchy -Node ($mp_Rules | where-object {$_.target -eq $class.ID}) -Mode Rule -BaseLevel 1
            }
            else {
                write-report "`tRelated Rules:"
                write-report "`t$("-" *"Related Rules:".length)"
                write-report "`t`None"
            }
            write-report ""

        }
    } elseif ($Mode -eq "Table") {
        $ChecklistFolder = New-Item -ItemType Directory -Path "$OutputFolder\$($mp_ID)" -Force

        if ($mp_Monitors.Count -ne 0) {
            $OutputFile = New-Item -ItemType File -Path "$ChecklistFolder\$($mp_ID).monitors.csv" -Force
            $mp_Monitors | select-object @{NAme="ManagementPack";Expression={$($mp_ID)}},displayName,target,Enabled,Alerting,'Alert Priority','Alert Severity' | convertto-csv -NoTypeInformation | Out-File -FilePath $OutputFile -Force
        }

        if ($mp_Rules.Count -ne 0) {
            $OutputFile = New-Item -ItemType File -Path "$ChecklistFolder\$($mp_ID).rules.csv" -Force
            foreach ($rule in $mp_Rules) {
                if ($rule.WriteActions.type -like "*GenerateAlert") {
                    $rule | Add-Member -MemberType NoteProperty -Name Alerting -Value "true"
                    $rule | Add-Member -MemberType NoteProperty -Name 'Alert Priority' -Value $rule.WriteActions.Configuration.Priority
                    $rule | Add-Member -MemberType NoteProperty -Name 'Alert Severity' -Value $rule.WriteActions.Configuration.Severity
                }
                else {
                    $rule | Add-Member -MemberType NoteProperty -Name Alerting -Value "false"
                }
            }
            $mp_Rules | Select-Object  @{NAme="ManagementPack";Expression={$($mp_ID)}},displayName,target,Enabled,Alerting,'Alert Priority','Alert Severity' | convertto-csv -NoTypeInformation | Out-File -FilePath $OutputFile -Force
        }
    
    } elseif ($Mode -eq "CheckList") {
        $ChecklistFolder = New-Item -ItemType Directory -Path "$OutputFolder\$($mp_ID)" -Force

        if ($mp_Monitors.Count -ne 0) {
            $OutputFile = New-Item -ItemType File -Path "$ChecklistFolder\$($mp_ID).monitors.csv" -Force
            $mp_Monitors | select-object -Property displayName,Enabled,Alerting,'Alert Priority','Alert Severity','Status' | convertto-csv -NoTypeInformation | Out-File -FilePath $OutputFile -Force
        }

        if ($mp_Rules.Count -ne 0) {
            $OutputFile = New-Item -ItemType File -Path "$ChecklistFolder\$($mp_ID).rules.csv" -Force
            foreach ($rule in $mp_Rules) {
                if ($rule.WriteActions.type -like "*GenerateAlert") {
                    $rule | Add-Member -MemberType NoteProperty -Name Alerting -Value "true"
                    $rule | Add-Member -MemberType NoteProperty -Name 'Alert Priority' -Value $rule.WriteActions.Configuration.Priority
                    $rule | Add-Member -MemberType NoteProperty -Name 'Alert Severity' -Value $rule.WriteActions.Configuration.Severity
                }
                else {
                    $rule | Add-Member -MemberType NoteProperty -Name Alerting -Value "false"
                }
            }
            $mp_Rules | select-object -Property displayName,Enabled,Alerting,'Alert Priority','Alert Severity','Status' | convertto-csv -NoTypeInformation | Out-File -FilePath $OutputFile -Force
        }
    }#>

Export-ModuleMember -Function write-report