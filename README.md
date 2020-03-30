# Microsoft Operations Manager Management Pack Parser
Management Pack parser for Microsoft's System Center Operations Manager Management Packs.

This parser is made for technical people who are already familiar with Management Pack authoring.

# Prerequisites
To begin you must first export your Management Packs in the from of Unsealed Management Packs
## Exporting Management Packs
Here I will explain about the various methods of exporting Management Packs:

#### 1. Via Operations Manager Console
1. Open your Operations Console
2. Choose 'Administration' at the bottom left panel
3. Under 'Management Packs' select 'Installed Management Packs'
4. Select your desired Management Pack to export and click 'Export Management Pack' in the right-side panel.
5. Save your Unsealed Management Pack to your work directory

#### 2. Via Powershell
1. Open Powershell CLI
2. Import Operations Manager Module *(Not needed when working from management sever)*
3. Use the combination of Get-SCOMManagementPack with Export-SCOMManagementPack as following:

    

> Get-SCOMManagementPack -DisplayName "[display name of your script]" |
> Export-SCOMManagementPack -Path [Path to your work directory]

*I prefer this method because it allows you to export multiple Management Packs with one command*


# Getting Started
After exporting 'MP Parser.ps1' to your work directory we can begin with parsing a Management Pack

## How To Use
The parser requires 3 parameters:
1. Input file / directory - Unsealed Management Packs or a directory containing them.
2. Mode - One of three: "Report", "Table", "CheckList". they will explain later on.
3. Output Folder - A directory to output your files to.

By default you can provide only a Management Pack and it will be parsed to a Report and saved to C:\temp\.

### Documentation
#### -File <string[]>
One or more unsealed Management Pack files.

Example:

    & 'MP Parser.ps1' -File "C:\Microsoft.windows.library.xml","C:\MPs\Foo.Bar.xml"

#### -Folder <string\>
Path (absolute or relative) to a directory containing unsealed Management Packs.

Example:

    & 'MP Parser.ps1' -Folder "C:\MPs"

Note that only -File **or** -Folder could be present

#### -Mode <string\>
Also known as Output Module, refers to how to output your parsed Management Pack.
Currently there are 3 modes:

 - **Report**: Creates a formatted text file (refer to 'Report.txt' under Output Examples)
 - **Table**:  Creates a CSV file of all parsed monitors and rules separately (refer to 'Table Outputs' under Output Examples)
 - **Checklist**: Creates a CSV file of all parsed monitors and rules. Although similar to **Table** mode, this mode is targeted to review existing monitors along with the **Report** output in order to document which alerts are generated and if your costumers actually need them.

Examlples:

    Generate a report:
    & 'MP Parser.ps1' -Folder "C:\MPs" -Mode Report
    
    Generate tables:
    & 'MP Parser.ps1' -Folder "C:\MPs" -Mode Table
    
    Generate Checklist:
    & 'MP Parser.ps1' -Folder "C:\MPs" -Mode Checklist

#### -OutputFolder <string\>
Path (absolute or relative) to a directory in which the output file will be written.
By default the path is 'C:\temp\'.

Example:

    & 'MP Parser.ps1' -Folder "C:\MPs" -Mode Report -OutputFolder C:\MPs\Parsed

## Usage Suggestions
Here I will list ways I intended to use this parser:

### Piping Management Pack Paths

    Get-ChildItem -Path C:\MPs -Filter '*.xml' | & 'MP Parser.ps1' -Mode Report -OutputFolder C:\MPs\Parsed

### Monitors Amendment
While working for various clients you often run into "noisy" environments with SCOM's robust Management Packs.
In order to mitigate this problem (provided it's a long term client) I'd generate a report and a checklist of their monitors and ask them to tell me if what they have is necessary.
This can only work when your clients are IT personnel since the report requires technical understanding of what is monitoring and the various way your can monitor.

What I recommend is to export all management packs (even out-of-the-box ones) and parse them into reports and checklists. After all the Management Packs are parsed you can simply send the reports to the various IT teams and ask them to fill the checklists.

Here's the process:

    Import-Module OperationsManager
    
    Get-SCOMManagementPack | Export-SCOMManagementPack -Path C:\MPs
    & 'MP Parser.ps1' -Folder C:\MPs -Mode Report -OutputFolder C:\MPs\Parsed
    & 'MP Parser.ps1' -Folder C:\MPs -Mode Checklist -OutputFolder C:\MPs\Parsed
This Process can take up to an hour or so (took 40 minutes for 350 Management Packs).

## Known Bugs
None, please report if you find something.

## Creating Your Own Output Modules
Since v2 I have refactored the script be much more modular.
Each piece of code has it's own module and therefore you can integrate your own modules.

To create your own module:
1. Create a function named "write-[action]" which receive 2 parameters:
   1. [object]$Managementpack - Management Pack Object
   2. [string]$WorkDirectory - Output Folder variable

2.  Write your function, you can look that the existing modules under "Output Modules" for reference.
3. Add the following code under your function:

    Export-ModuleMember  -Function write-[action]

4. Save you function under your local "Output Modules" directory with the name [action].psm1

Afterwards run the script as following:

    & 'MP Parser.ps1' -Folder C:\MPs -Mode [action] -OutputFolder C:\MPs\Parsed

Feel free to contact me if you run into problems.
