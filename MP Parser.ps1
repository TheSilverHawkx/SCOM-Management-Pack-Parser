Param (
    [Parameter(Valuefrompipeline)]
    [string[]]$File,
    [string]$Folder,
    [string]$OutputFolder = "C:\temp\",
    [Parameter(Mandatory)]
    [ValidateSet("Report","Table","CheckList")]
    [string]$Mode = "Report"
)
function parseExpression {
    Param (
        [System.Xml.XmlElement[]]$Node,
        [string]$logicOperand,
        [string]$output = ""
    )

    #write-host $Node.LocalName
    if ($Node.FirstChild.LocalName -in @("And","Or")) {
        $output += "("
        $Node.FirstChild.ChildNodes | % {
            $output = (parseExpression -Node $_ -logicOperand $Node.FirstChild.LocalName -output $output)
        }
        if ($output -match ".*$($Node.FirstChild.LocalName) $") {
            $output = $output.Substring(0,$output.LastIndexOf(" $($Node.FirstChild.LocalName)"))
        }
        $output += ")"
        return $output
    }
    elseif ($Node.LocalName -eq "Expression") {
        $output += "("
        $output += (parseExpression -Node $Node.FirstChild -logicOperand $logicOperand -output $output)
        $output += ") $logicOperand "
        
        return $output
    }
    elseif ($Node.LocalName -eq "Contains") {
        $node.ChildNodes | % {
            $output += "$($Node.LocalName) ($($_.LocalName)) $($_.innerText)"
        }
        return $output
    }
    else {
        if ($node.SelectSingleNode("./Operator") -ne $null) {
            $operator = $Node.Operator 
        }
        else {
            $operator = $node.FirstChild.Operator
        }
        $output = $Node.InnerText -replace "$operator"," $operator "
        
        return $output
    }

}

function parseModule {
    Param (
        [Parameter(mandatory)]
        [ValidateSet('Datasource','ProbeAction','ConditionDetection','WriteAction')]
        [string]$ModuleType,
        [System.Xml.XmlElement[]]$Location
    )
    $module_list = New-Object System.Collections.ArrayList 

    if ($ModuleType -eq 'ConditionDetection') {
        $node = New-Object object
        $node | Add-Member -MemberType NoteProperty -Name "Type" -Value $Location.TypeID

        $configuration = @{}
        foreach ($config in $Location.ChildNodes) {
            if (isSpecialCase($config.LocalName))
            {
                handleSpecialCases -Configuration $configuration -Location $config
            }
            else {
                $configuration.Add($config.LocalName,$($config.InnerXml -replace "><",">`n<"))
            }
        }
        $node | Add-Member -MemberType NoteProperty -Name "Configuration" -Value $configuration
        $module_list.Add($node) >$null 2>&1
    }
    else {
        foreach ($module in $Location.ChildNodes) {
            $node = New-Object object
            $node | Add-Member -MemberType NoteProperty -Name "Type" -Value $module.TypeID

            $configuration = @{}
            foreach ($config in $module.ChildNodes) {
                if (isSpecialCase($config.LocalName))
                {
                    handleSpecialCases -Configuration $configuration -Location $config
                }
                else {
                    $configuration.Add($config.LocalName,$($config.InnerXml -replace "><",">`n<"))
                }
            }
            $node | Add-Member -MemberType NoteProperty -Name "Configuration" -Value $configuration
            $module_list.Add($node) >$null 2>&1
        }
    }
    return $module_list
}

function parseMembershipRule {
    Param (
        [System.Xml.XmlElement[]]$Rule
        
    )
    $configuration = @{}

    foreach ($setting in $Rule.ChildNodes) {
        if (isSpecialCase($setting.localname)) {
            handleSpecialCases -Configuration $Configuration -Location $setting
        }
        else {
            $configuration.Add($setting.localname,$setting.innerText)
        }
    }

    return $configuration
}

function isSpecialCase($name) {

    if ($name -like "*Expression*") {
        return $true
    }
    elseif ($name -in ("InstanceSettings","Suppression","Consolidator","AlertParameters","MembershipRules","RegistryAttributeDefinitions","Scheduler")) {
        return $true
    }
    else {
        return $false
    }
}

function handleSpecialCases {
    Param (
        [Hashtable]$Configuration = @{},
        [System.Xml.XmlElement[]]$Location
    )
    $settings = @{}
    if ($Location.LocalName -eq "Consolidator") {
        foreach ($setting in $Location.ChildNodes) {
            $settings.add($setting.LocalName,$($setting.InnerXml -replace "><","> <"))
        }
        $configuration.add($Location.LocalName,$settings)
    }
    elseif ($Location.LocalName -eq "InstanceSettings") {
        foreach ($setting in $Location.Settings.ChildNodes) {
            $settings.add($setting.Name,$setting.Value)
        }
        $Configuration.add($Location.LocalName,$settings)
    }
    elseif ($Location.LocalName -eq "AlertParameters" -or $Location.LocalName -eq "Scheduler") {
        foreach ($setting in $Location.ChildNodes) {
            $settings.Add($setting.LocalName,$($setting.InnerXml -replace "><",">`t<"))
        }
        $configuration.add($Location.LocalName,$settings)
    }
    elseif ($location.LocalName -eq "Supperssion") {
        $i = 1
        foreach ($setting in $Location.ChildNodes) {
            $settings.Add($setting.LocalName + "$i",$($setting.InnerXml -replace "><",">`t<"))            
            $i++
        }
        $configuration.Add($location.LocalName.LocalName,$settings)
    }
    elseif ($location.LocalName -like "*Expression*") {
        $configuration.Add($Location.LocalName,$(parseExpression -Node $location))
    }
    elseif ($location.LocalName -eq "MembershipRules") {
        $rules = New-Object System.Collections.ArrayList
        foreach ($setting in $location.ChildNodes) {
            $rules.add((parseMembershipRule -Rule $setting -Array $settings)) > $null 2>&1
        }
        $Configuration.Add($location.LocalName,$rules)
    }
    elseif ($Location.LocalName -eq "RegistryAttributeDefinitions") {
        $rules = New-Object System.Collections.ArrayList
        foreach ($setting in $location.ChildNodes) {
            $rules.add((parseMembershipRule -Rule $setting -Array $settings)) > $null 2>&1
        }
        $Configuration.Add($location.LocalName,$rules)
    }
    else {
        $configuration.Add($location.LocalName,"Not Implemented")
    }
}

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

                $discovery.Configuration.keys | % {
                    if ($_ -eq "Files") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$discovery.Configuration["$_"]).File.Name)"
                    } elseif ($_ -eq "InstanceSettings") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                        $a = $_

                        $offset++
                        $Discovery.Configuration["$_"].keys | % {
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
                        
                            $rule.keys | % {
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
                $monitor.Configuration.keys | % {
                    if ($_ -eq "Files") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$monitor.Configuration["$_"]).File.Name)"
                    } elseif ($_ -eq "InstanceSettings") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                        $a = $_
                        $offset++
                        $monitor.Configuration["$a"].keys | % {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $($monitor.Configuration["$a"]["$_"])"
                        }
                        $offset--

                    } elseif ($_ -eq "Consolidator") {
                        write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                        $offset++
                        $a = $_
                        $monitor.Configuration["$a"].keys | % {
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
                    $ds.Configuration.Keys | % {
                        if ($_ -eq "Files") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$ds.Configuration["$_"]).File.Name)"
                        } elseif ($_ -eq "InstanceSettings") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $offset++
                            $rule.Configuration["$a"].keys | % {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"]) "
                            }
                            $offset--
                        } elseif ($_ -eq "Consolidator") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $ds.Configuration["$a"].keys | % {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($ds.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -like "*Expression*") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $(($ds.Configuration["$_"]).trimEnd()) "
                        } elseif ($_ -eq "Scheduler"){
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $ds.Configuration["$a"].keys | % {
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

                if ($rule.ConditionDetection -ne $null) {
                    write-report "$("`t" * ($BaseLevel + $offset))ConditionDetection:"
                    $offset++
                    write-report "$("`t" * ($BaseLevel + $offset))1. Type: $($rule.ConditionDetection.Type)"
                    $offset++
                    $rule.ConditionDetection.Configuration.Keys | % { 
                        if ($_ -eq "Files") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_): $(([xml]$rule.ConditionDetection.Configuration["$_"]).File.Name)"
                        } elseif ($_ -eq "InstanceSettings") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $Offset++
                            $rule.Configuration["$_"].keys | % {
                                write-report "$("`t" * ($BaseLevel + $offset))$($_): $($rule.ConditionDetection.Configuration["$a"]["$_"])"
                            }
                            $offset--
                        } elseif ($_ -eq "Consolidator") {
                            write-report "$("`t" * ($BaseLevel + $offset))$($_):"
                            $a = $_
                            $offset++
                            $rule.ConditionDetection.Configuration["$a"].keys | % {
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

$FilesToParse = New-Object System.Collections.ArrayList

if ($File -ne $null) {
    foreach ($f in $File) {
        $FilesToParse.Add((Get-ChildItem -Path $f)) > $null 2>&1
    }
}
elseif ($($Folder.length) -ne 0) {
    foreach($f in $(Get-ChildItem -Path $Folder -Filter '*.xml')) {
        $FilesToParse.Add($f.FullName)  > $null 2>&1
    }
}
else {
    write-host "No input file specified" -ForegroundColor Red
    exit 1
}

foreach ($file in $FilesToParse) {
    Write-Host "Working on $($file)..."


    $doc = [xml](Get-Content -Path $File)
    $mp = $doc.ManagementPack
    

    #--------------------------------Collect Name---------------------------------#
    $mp_ID = $mp.Manifest.Identity.ID
    $mp_Name = $mp.Manifest.Name
    #-----------------------------------------------------------------------------#

    #-----------------------------Collect dependencies----------------------------#
    $mp_dependencies = New-Object System.Collections.ArrayList
    $mp.Manifest.References.ChildNodes | % {
        $a = New-Object System.Object
        $a | Add-Member -Name "ID" -MemberType NoteProperty -Value $_.ID
        $a | Add-Member -Name "Version" -MemberType NoteProperty -Value $_.Version

        $mp_dependencies.Add($a)  >$null 2>&1
    }
    #-----------------------------------------------------------------------------#

    #-------------------------------Collect Classes-------------------------------#
    $mp_classes = New-Object System.Collections.ArrayList
    $mp.TypeDefinitions.EntityTypes.ClassTypes.ChildNodes | % {
        $class = New-Object object
        $class | Add-Member -Name ID -MemberType NoteProperty -Value $($_.ID)
        $class | Add-Member -Name IsAbstract -MemberType NoteProperty -Value $($_.Abstract)
        $class | Add-Member -Name IsHosted -MemberType NoteProperty -Value $($_.Hosted)
        $class | Add-Member -Name IsSingleton -MemberType NoteProperty -Value $($_.Singleton)
        $class | Add-Member -Name Discovery -MemberType NoteProperty -Value (New-Object System.Collections.ArrayList)
        $mp_classes.Add($class)  >$null 2>&1
    }
    #-----------------------------------------------------------------------------#

    #-----------------------------Collect Discoveries-----------------------------#
        $mp.Monitoring.Discoveries.ChildNodes | % {
        $discovery = New-Object object
        $discovery | Add-Member -MemberType NoteProperty -Name ID -Value $_.ID
        $discovery | Add-Member -MemberType NoteProperty -Name Enabled -Value $_.Enabled
        $discovery | Add-Member -MemberType NoteProperty -Name Type -Value $_.DataSource.TypeID
        $discovery | Add-Member -MemberType NoteProperty -Name Target -Value $_.Target

        $configuration = @{}
        foreach ($conf in $_.Datasource.ChildNodes) {

            if (isSpecialCase($conf.LocalName))
            {
                handleSpecialCases -Configuration $configuration -Location $conf
            }
            else {
                $configuration.Add($conf.LocalName,$($conf.InnerXml -replace "><",">`n<"))
            }
        }
        $discovery | Add-Member -MemberType NoteProperty -Name "Configuration" -Value $configuration

        foreach ($i in $_.DiscoveryTypes.DiscoveryClass.TypeID) {

            $mp_classes | ? {$_.ID -eq $i} | % {$_.discovery.add($discovery)} > $null 2>&1
        
        }
    }
    #-----------------------------------------------------------------------------#

    #-------------------------------Collect Monitors------------------------------#
    $mp_Monitors = New-Object System.Collections.ArrayList
    $monitors = $mp.Monitoring.Monitors.ChildNodes
    foreach ($id in $mp_classes.id) {
        foreach ($mon in ($monitors | ? {$_.Target -eq $id})){
            $monitor = New-Object object

            $monitor |Add-Member -MemberType NoteProperty -Name ID -Value $mon.ID
            $monitor |Add-Member -MemberType NoteProperty -Name Enabled -Value $mon.Enabled
            $monitor |Add-member -MemberType NoteProperty -Name Type -Value $mon.LocalName
            $monitor |Add-Member -MemberType NoteProperty -Name MonitorType -Value $mon.TypeID
            $monitor |Add-Member -MemberType NoteProperty -Name Category -Value $mon.Category
            $monitor |Add-Member -MemberType NoteProperty -Name Target -Value $mon.Target

        
            # Collect Alert Information
            if ($mon.AlertSettings.AlertOnState -ne $null) {
                $monitor |Add-Member -MemberType NoteProperty -Name Alerting -Value "true"
                $monitor |Add-Member -MemberType NoteProperty -Name "Alert On State" -Value $mon.AlertSettings.AlertOnState
                $monitor |Add-Member -MemberType NoteProperty -Name "Alert Priority" -Value $mon.AlertSettings.AlertPriority
                $monitor |Add-Member -MemberType NoteProperty -Name "Alert Severity" -Value $mon.AlertSettings.AlertSeverity
            }
            else {
                $monitor |Add-Member -MemberType NoteProperty -Name Alerting -Value "false"
            }

            # Collect Configuration
            $configuration  = @{}
            foreach ($config in $mon.Configuration.ChildNodes) {
                if (isSpecialCase($config.LocalName)) {
                    handleSpecialCases -Configuration $configuration -Location $config
                } else {
                    $configuration.Add($config.LocalName,$($config.InnerXml -replace "><",">`n<"))
                }
            }
            $monitor | Add-Member -MemberType NoteProperty -Name Configuration -Value $configuration
            $mp_Monitors.Add($monitor) >$null 2>&1
        }

    }
    #-----------------------------------------------------------------------------#

    #------------------------------Collect Rules----------------------------------#
    $mp_Rules = New-Object System.Collections.ArrayList
    $rules = $mp.Monitoring.Rules.ChildNodes
    foreach ($id in $mp_classes.id) {
        foreach ($rul in ($rules | ? {$_.Target -eq $id})){
            $rule = New-Object object

            $rule |Add-Member -MemberType NoteProperty -Name ID -Value $rul.ID
            $rule |Add-Member -MemberType NoteProperty -Name Enabled -Value $rul.Enabled
            $rule |Add-Member -MemberType NoteProperty -Name Category -Value $rul.Category
            $rule |Add-Member -MemberType NoteProperty -Name Target -Value $rul.Target

            # Collect Datasources
            $datasources = parseModule -ModuleType Datasource -Location $rul.DataSources
            $rule | Add-Member -MemberType NoteProperty -Name DataSources -Value $datasources
        
            if ($rul.ProbeActions -ne $null) {
                $probeactions = parseModule -ModuleType ProbeAction -Location $rul.ProbeActions
                $rule | Add-Member -MemberType NoteProperty -Name ProbeActions -Value $probeactions
            }

            # Collect Condition Detection
            if ($rul.ConditionDetection -ne $null) {
                $conditiondetection = parseModule -ModuleType ConditionDetection -Location $rul.ConditionDetection
                $rule | Add-Member -MemberType NoteProperty -Name ConditionDetection -Value $conditiondetection        
            }
        
            # Collect Write Actions
            $writeactions = parseModule -ModuleType WriteAction -Location $rul.WriteActions
            $rule | Add-Member -MemberType NoteProperty -Name WriteActions -Value $writeactions

            $mp_Rules.add($rule) >$null 2>&1
        }
    }
    #-----------------------------------------------------------------------------#
    #-------------------------Enrich From LanguagePacks---------------------------#
    $displaystrings = $mp.LanguagePacks.LanguagePack.DisplayStrings.ChildNodes | ? {$_.SubElementID -eq $nul}

    foreach ($class in $mp_classes) {
        $class | add-member -MemberType NoteProperty -Name DisplayName -Value $(($displaystrings | ? {$_.ElementID -eq $class.ID}).Name)
    }

    foreach ($monitor in $mp_Monitors) {
        $monitor | add-member -MemberType NoteProperty -Name DisplayName -Value $(($displaystrings | ? {$_.ElementID -eq $monitor.ID}).Name)
    }

    foreach ($rule in $mp_Rules) {
        $rule | add-member -MemberType NoteProperty -Name DisplayName -Value $(($displaystrings | ? {$_.ElementID -eq $rule.ID}).Name)
    }

    #-----------------------------------------------------------------------------#
    if ($Mode -eq "Report") {
        $OutputFile = New-Item -ItemType File -Path "$OutputFolder\$($mp_ID).txt" -Force

        write-report "$mp_Name"
        write-report "$('=' * $mp_Name.Length)"
        write-report ""

        write-report "Dependencies"
        write-report "$('-' * 12)"

        $mp_dependencies | % {
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

            if (($mp_Monitors | ? {$_.target -eq $class.ID -and $_.Type -like "*Unit*"}).Count -ne 0 ) {
                printHirarchy -Node ($mp_Monitors | ? {$_.target -eq $class.ID}) -Mode Monitor -BaseLevel 1
            }
            else {
                write-report "`tRelated Monitors:"
                write-report "`t$("-" *"Related Monitors:".length)"
                write-report "`t`None"
            }
            write-report ""
    
            if (($mp_Rules | ? {$_.target -eq $class.ID}).Count -ne 0 ) {

                printHirarchy -Node ($mp_Rules | ? {$_.target -eq $class.ID}) -Mode Rule -BaseLevel 1
            }
            else {
                write-report "`tRelated Rules:"
                write-report "`t$("-" *"Related Rules:".length)"
                write-report "`t`None"
            }
            write-report ""

        }
    } elseif ($Mode -eq "Table") {
        $OutputFile = New-Item -ItemType File -Path "$OutputFolder\$($mp_ID).csv" -Force

        foreach ($class in $mp_classes) {
            $class

        }
    } elseif ($Mode -eq "CheckList") {
        $ChecklistFolder = New-Item -ItemType Directory -Path "$OutputFolder\$($mp_ID)" -Force

        if ($mp_Monitors.Count -ne 0) {
            $OutputFile = New-Item -ItemType File -Path "$ChecklistFolder\$($mp_ID).monitors.csv" -Force
            $mp_Monitors | select -Property displayName,Enabled,Alerting,'Alert Priority','Alert Severity','Status' | convertto-csv -NoTypeInformation | Out-File -FilePath $OutputFile -Force
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
            $mp_Rules | select -Property displayName,Enabled,Alerting,'Alert Priority','Alert Severity','Status' | convertto-csv -NoTypeInformation | Out-File -FilePath $OutputFile -Force
        }
    }
    
}