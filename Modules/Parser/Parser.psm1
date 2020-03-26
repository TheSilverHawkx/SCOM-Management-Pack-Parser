function Parse-Expression {
    Param (
        [System.Xml.XmlElement[]]$Node,
        [string]$logicOperand,
        [string]$output = ""
    )

    if ($Node.FirstChild.LocalName -in @("And","Or")) {
        $output += "("
        $Node.FirstChild.ChildNodes | ForEach-Object {
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
        $node.ChildNodes | ForEach-Object {
            $output += "$($Node.LocalName) ($($_.LocalName)) $($_.innerText)"
        }
        return $output
    }
    else {
        if ($null -ne $node.SelectSingleNode("./Operator")) {
            $operator = $Node.Operator 
        }
        else {
            $operator = $node.FirstChild.Operator
        }
        $output = $Node.InnerText -replace "$operator"," $operator "
        
        return $output
    }

}

function Parse-TwoStepNode {
    Param (
        [System.Xml.XmlElement[]]$RootNode
        
    )
    $configurations = @{}

    foreach ($ChildNode in $RootNode.ChildNodes) {
        if (Check-SpecialCase $ChildNode) {
            Parse-SpecialCase -configurations $configurations -Node $ChildNode
        }
        else {
            $configurations.Add($ChildNode.localname,$ChildNode.innerText)
        }
    }

    return $configurations
}

function Check-SpecialCase {
    param (
        [System.Xml.XmlElement]$Node
    )

    if ($Node.LocalName -in ("InstanceSettings","Suppression","Consolidator","AlertParameters","MembershipRules","RegistryAttributeDefinitions","Scheduler")) {
        return $true
    }
    elseif ($node.LocalName -like "*Expression*" -or $Node.FirstChild.localName -like "*Expression*") {
        return $true  
    }
    else {
        return $false
    }
    
}

function Parse-SpecialCase {
    param (
        [hashtable]$configurations = @{},
        [System.Xml.XmlElement]$Node
    )

    $subConfigurations = @{}

    # Cases that have 1 level of depth
    if ($Node.LocalName -in ("Consolidator","AlertParameters","Scheduler")) {
        foreach ($subConfiguration in $Node.ChildNodes) {
            $subConfigurations.add($subConfiguration.LocalName,$($subConfiguration.InnerXml -replace "><","> <"))
        }

        $configurations.add($Node.LocalName,$subConfigurations)
    }
    # Cases that have 1 level of depth + counter
    elseif ($locNodeation.LocalName -in ("Supperssion")) {
        $Counter = 1
        foreach ($subConfiguration in $Node.ChildNodes) {
            $subConfigurations.Add($subConfiguration.LocalName + "$Counter",$($subConfiguration.InnerXml -replace "><",">`t<"))            
            $Counter++
        }
        $configurations.Add($Node.LocalName.LocalName,$subConfigurations)
    }
    # Cases that have one sub-element and then configuration child nodes
    elseif ($Node.LocalName -in ("InstanceSettings")) {
        foreach ($subConfiguration in $Node.FirstChild.ChildNodes) {
            $subConfigurations.add($subConfiguration.Name,$subConfiguration.Value)
        }
        $configurations.add($Node.LocalName,$subConfigurations)
    }
    # Cases of expression clause
    elseif ($Node.LocalName -like "*Expression*" -or $Node.FirstChild.LocalName -like "*Expression*") {
        $configurations.Add($Node.LocalName,$(Parse-Expression -Node $Node))
    }
    elseif ($Node.FirstChild.LocalName -like "*Expression*") {
        $configurations.Add($Node.LocalName,$(Parse-Expression -Node $Node.FirstChild))
    }
    # Cases that have 2 level depth
    elseif ($Node -in ("MembershipRules","RegistryAttributeDefinitions")) {
        $list = New-Object System.Collections.ArrayList
        foreach ($subConfiguration in $Node.ChildNodes) {
            $list.add((parseMembershipRule -Rule $subConfiguration -Array $subConfigurations)) > $null 2>&1
        }
        $configurations.Add($Node.LocalName,$list) > $null 2>&1
    }
    else {
        $configurations.Add($Node.LocalName,"Not Implemented")
    }
}
function Parse-Rule {
    Param (
        [System.Xml.XmlElement]$Node
    )
    
    $Rule = New-Object -TypeName System.Object
    $Rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $Node.ID
    $Rule | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $Node.Enabled
    $Rule | Add-Member -MemberType NoteProperty -Name "Target" -Value $Node.Target
    $Rule | Add-Member -MemberType NoteProperty -Name "ConfirmDelivery" -Value $Node.ConfirmDelivery
    $Rule | Add-Member -MemberType NoteProperty -Name "Remotable" -Value $Node.Remotable
    $Rule | Add-Member -MemberType NoteProperty -Name "Category" -Value $Node.Category

    $Rule | Add-Member -MemberType NoteProperty -Name "Datasources" -Value (New-Object System.Collections.ArrayList)
    $Rule | Add-Member -MemberType NoteProperty -Name "ConditionDetection"  -Value (New-Object System.Collections.ArrayList)
    $Rule | Add-Member -MemberType NoteProperty -Name "WriteActions" -Value (New-Object System.Collections.ArrayList)

    foreach ($moduleType in @("DataSources","ConditionDetection","WriteActions")) {
        foreach ($moduleInstance in $Node.$moduleType.ChildNodes) {
            
            $Module = New-Object object
            $Module | Add-Member -MemberType NoteProperty -Name "Type" -Value $moduleInstance.TypeID
    
            $configurations = @{}
            if ($moduleType -eq "ConditionDetection") {
                if (Check-SpecialCase $moduleInstance) {
                    Parse-SpecialCase -configurations $configurations -Node $moduleInstance
                }
                else {
                    $configurations.Add($moduleInstance.LocalName,$($moduleInstance.InnerXml -replace "><",">`n<"))
                }
            }
            else {
                foreach ($configuration in $moduleInstance.childNodes) {
                    if (Check-SpecialCase $configuration) {
                        Parse-SpecialCase -configurations $configurations -Node $configuration
                    }
                    else {
                        $configurations.Add($configuration.LocalName,$($configuration.InnerXml -replace "><",">`n<"))
                    }
                    
                }
            }
            $Module | Add-Member -MemberType NoteProperty -Name "Configuration" -Value $configurations
    
            $Rule.$moduleType.Add($Module) > $null 2>&1
        }
    }
    return $Rule
}

function Parse-Monitor {
    param (
        [System.Xml.XmlElement]$Node
    )

    $Monitor = New-Object object
    $Monitor | Add-Member -MemberType NoteProperty -Name ID -Value $Node.ID
    $Monitor | Add-Member -MemberType NoteProperty -Name Enabled -Value $Node.Enabled
    $Monitor | Add-member -MemberType NoteProperty -Name Type -Value $Node.LocalName
    $Monitor | Add-member -MemberType NoteProperty -Name ParentMonitor -Value $Node.ParentMonitorID
    $Monitor | Add-Member -MemberType NoteProperty -Name MonitorType -Value $Node.TypeID
    $Monitor | Add-Member -MemberType NoteProperty -Name Category -Value $Node.Category
    $Monitor | Add-Member -MemberType NoteProperty -Name Target -Value $Node.Target
        
    # Collect Alert Information
    if ($null -ne $Node.AlertSettings.AlertOnState) {
        $Monitor | Add-Member -MemberType NoteProperty -Name Alerting -Value "True"
        $Monitor | Add-Member -MemberType NoteProperty -Name "Alert On State" -Value $Node.AlertSettings.AlertOnState
        $Monitor | Add-Member -MemberType NoteProperty -Name "Alert Priority" -Value $Node.AlertSettings.AlertPriority
        $Monitor | Add-Member -MemberType NoteProperty -Name "Alert Severity" -Value $Node.AlertSettings.AlertSeverity
    }
    else {
        $Monitor |Add-Member -MemberType NoteProperty -Name Alerting -Value "False"
    }

    # Collect Configuration
    $configurations  = @{}
    foreach ($configuration in $Node.Configuration.ChildNodes) {
        if (Check-SpecialCase $configuration) {
            Parse-SpecialCase -configurations $configurations -Node $configuration
        } else {
            $configurations.Add($configuration.LocalName,$($configuration.InnerXml -replace "><",">`n<"))
        }
    }
    $Monitor | Add-Member -MemberType NoteProperty -Name Configuration -Value $configurations

    return $Monitor
}

function Parse-Class {
    Param (
        [System.Xml.XmlElement]$Node
    )

    $Class = New-Object object
    $class | Add-Member -Name ID -MemberType NoteProperty -Value $($Node.ID)
    $class | Add-Member -Name ParentClass -MemberType NoteProperty -Value $($Node.base)
    $class | Add-Member -Name IsAbstract -MemberType NoteProperty -Value $($Node.Abstract)
    $class | Add-Member -Name IsHosted -MemberType NoteProperty -Value $($Node.Hosted)
    $class | Add-Member -Name IsSingleton -MemberType NoteProperty -Value $($Node.Singleton)
    $class | Add-Member -Name Discovery -MemberType NoteProperty -Value (New-Object System.Collections.ArrayList)

    if ($null -ne $Node.Property) {
        $propertyList = New-Object System.Collections.ArrayList
        foreach ($propertyNode in $Node.Property)
        {
            $Property = New-Object System.Object

            foreach ($attribute in $propertyNode.attributes.Name) {
                $Property | Add-Member -Name $attribute -MemberType NoteProperty -Value $propertyNode.$attribute
            }
            $propertyList.Add($Property) > $null 2>&1
        }
        $Class | Add-Member -Name Properties -MemberType NoteProperty -Value $propertyList
    }

    return $Class
}

function Parse-Discovery {
    param (
        [System.Xml.XmlElement]$Node
    )

    $Discovery = New-Object object
    $Discovery | Add-Member -MemberType NoteProperty -Name ID -Value $Node.ID
    $Discovery | Add-Member -MemberType NoteProperty -Name Enabled -Value $Node.Enabled
    $Discovery | Add-Member -MemberType NoteProperty -Name Type -Value $Node.DataSource.TypeID
    $Discovery | Add-Member -MemberType NoteProperty -Name Target -Value $Node.Target
    $Discovery | Add-Member -MemberType NoteProperty -Name Remotable -Value $Node.Remotable
    $Discovery | Add-Member -MemberType NoteProperty -Name ConfirmDelivery -Value $Node.ConfirmDelivery
    $Discovery | Add-Member -MemberType NoteProperty -Name Priority -Value $Node.Priority

    $configurations = @{}
    foreach ($configuration in $Node.Datasource.ChildNodes) {

        if (Check-SpecialCase $configuration)
        {
            Parse-SpecialCase -configurations $configurations -Node $configuration
        }
        else {
            $configurations.Add($configuration.LocalName,$($configuration.InnerXml -replace "><",">`n<"))
        }
    }
    $Discovery | Add-Member -MemberType NoteProperty -Name "Configuration" -Value $configurations
    
    return $Discovery
}

function Parse-Manifest {
    param (
        [System.Xml.XmlElement]$Node
    )

    $Dependencies = New-Object System.Collections.ArrayList

    foreach ($dependencyNode in $Node.References.childNodes) {
        $Dependency = New-Object Object


        $Dependency | Add-Member -MemberType NoteProperty -Name "ID" -Value $dependencyNode.ID
        $Dependency | Add-Member -MemberType NoteProperty -Name "Version" -Value $dependencyNode.Version
        $Dependency | Add-Member -MemberType NoteProperty -Name "Alias" -Value $dependencyNode.Alias

        $Dependencies.Add($Dependency) > $null 2>&1
    }

    return $Dependencies
}

function Add-DisplayNames {
    param (
        [System.Xml.XmlElement[]]$DisplayStrings,
        [System.Object[]]$ListOfObjects
    )
    foreach ($object in $ListOfObjects) {
        $object | Add-Member -MemberType NoteProperty -Name DisplayName -Value ($DisplayStrings | where-object {$_.ElementID -eq $object.ID}).Name
    }
    
}

Export-ModuleMember -Function Parse-Manifest
Export-ModuleMember -Function Parse-Class
Export-ModuleMember -Function Parse-Discovery
Export-ModuleMember -Function Parse-Rule
Export-ModuleMember -Function Parse-Monitor
Export-ModuleMember -Function Add-DisplayNames
