# PowerShell

Function Cleanup-DriveC {
    <#
    .SYNOPSIS
       Automate cleaning up a C:\ drive with low disk space

    .DESCRIPTION
       Cleans the C: drive's Window Temperary files, Windows SoftwareDistribution folder,
       the local users Temperary folder, IIS logs(if applicable) and empties the recycle bin.
       All deleted files will go into a log transcript in $Env:TEMP. By default this
       script leaves files that are newer than 7 days old however this variable can be edited.

    .EXAMPLE
       PS C:\> .\Cleanup-DriveC.ps1
       Save the file to your hard drive with a .PS1 extention and run the file from an elavated PowerShell prompt.

    .NOTES
       This script will typically clean up anywhere from 1GB up to 15GB of space from a C: drive.

    .FUNCTIONALITY
       PowerShell v3+
    #>

    ## Allows the use of -WhatIf
    [CmdletBinding(SupportsShouldProcess = $True)]

    Param (
        ## Delete data older then $daystodelete
        [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True, Position = 0)]
        $DaysToDelete = 7,

        ## LogFile path for the transcript to be written to
        [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True, Position = 1)]
        $LogFile = ("C:\TEMP\" + ($MyInvocation.MyCommand.Name.Split(".")[0]) + '.log'),
        #$LogFile = ("$Env:TEMP\" + (Get-Date -Format "yyyyMMdd_HHmmss") + '.log'),

        ## All verbose outputs will get logged in the transcript($logFile)
        [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True, Position = 2)]
        $VerbosePreference = "Continue",

        ## All errors should be withheld from the console
        [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True, Position = 3)]
        $ErrorActionPreference = "SilentlyContinue"
    )

    # Get-ChildItem Env:
    # $Env:SystemDrive C:
    # $Env:SystemRoot  C:\Windows
    # $Env:TEMP        C:\Users\A-ZIK0~1\AppData\Local\Temp\2

    $ScriptName = $MyInvocation.MyCommand.Name.Split(".")[0]
    Write-Host "PowerShell Script ($ScriptName) Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor 'Green'

    ## Begin the timer
    $Starters = (Get-Date)

    ## Check $VerbosePreference variable, and turns -Verbose on
    Function Global:Write-Verbose ([String]$Message) {
        If ($VerbosePreference -Ne 'SilentlyContinue') {
            Write-Host "$Message" -ForegroundColor 'Green'
        }
    }

    ## Tests if the log file already exists and renames the old file if it does exist
    If (Test-Path $LogFile) {
        ## Renames the log to be .old
        Rename-Item $LogFile $LogFile.old -Verbose -Force
    } 
    Else {
        ## Starts a transcript in C:\Temp so you can see which files were deleted
        Write-Host (Start-Transcript -Path $LogFile) -ForegroundColor Green
    }

    #$OsVersion = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Version
    
    ## Writes a verbose output to the screen for user information
    Write-Host "Retrieving current disk percent free for comparison once the script has completed." -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "

    ## Gathers the amount of disk space used before running the script
    $Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -Eq "3" } | Select-Object `
        SystemName,
        @{Name = "Drive";          Expression = {($_.DeviceID)}},
        @{Name = "Size (GB)";      Expression = {"{0:N1}" -f ($_.Size / 1GB)}},
        @{Name = "FreeSpace (GB)"; Expression = {"{0:N1}" -f ($_.Freespace / 1GB)}},
        @{Name = "PercentFree";    Expression = {"{0:P1}" -f ($_.FreeSpace / $_.Size)}} |
        Format-Table -AutoSize |
        Out-String

    ## Stops the Windows Update service so that C:\Windows\SoftwareDistribution can be cleaned up
    Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Verbose

    ## Sets the SCCM cache size to 1 GB if it exists.
    If ((Get-WmiObject -NameSpace root\ccm\SoftMgmtAgent -Class CacheConfig) -Ne "$Null") {
        # If data is returned and sccm cache is configured it will shrink the size to 1024MB.
        $Cache = Get-WmiObject -NameSpace root\ccm\SoftMgmtAgent -Class CacheConfig
        $Cache.Size = 1024 | Out-Null
        $Cache.Put() | Out-Null
        Restart-Service -Name CcmExec -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }

    ## Deletes the contents of Windows Software Distribution.
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue | 
        Remove-Item -Recurse -ErrorAction SilentlyContinue -Verbose
    Write-Host "The Contents of Windows SoftwareDistribution have been removed successfully!" -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "


    ## Deletes the contents of the Windows Temp folder.
    Get-ChildItem "C:\Windows\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -Lt $(Get-Date).AddDays( - $DaysToDelete)) } | 
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Verbose
    Write-Host "The Contents of Windows Temp have been removed successfully!" -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "

    ## Deletes all files and folders in user's Temp folder older then $DaysToDelete
    Get-ChildItem "C:\Users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {($_.CreationTime -Lt $(Get-Date).AddDays( - $DaysToDelete))} |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Verbose
    Write-Host "The contents of `$Env:TEMP have been removed successfully!" -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "

    ## Removes all files and folders in user's Temporary Internet Files older then $DaysToDelete
    Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" `
        -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
        Where-Object {($_.CreationTime -Lt $(Get-Date).AddDays( - $DaysToDelete))} |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Verbose
    Write-Host "All Temporary Internet Files have been removed successfully!" -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "

    ## Removes all files and folders in user's Web Cache Files older then $DaysToDelete
    Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\*" `
        -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
        Where-Object {($_.CreationTime -Lt $(Get-Date).AddDays( - $DaysToDelete))} |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Verbose
    Write-Host "All Web Cache Files have been removed successfully!" -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "

    ## Removes *.log from C:\windows\CBS
    If (Test-Path C:\Windows\logs\CBS\) {
        Get-ChildItem "C:\Windows\logs\CBS\*.log" -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Verbose
        Write-Host "All CBS logs have been removed successfully!" -ForegroundColor Green
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        Write-Host " "
    } 
    Else {
        Write-Host "C:\inetpub\logs\LogFiles\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans IIS Logs older then $DaysToDelete
    If (Test-Path C:\inetpub\logs\LogFiles\) {
        Get-ChildItem "C:\inetpub\logs\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -Lt $(Get-Date).AddDays(-60)) } | 
            Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
        Write-Host "All IIS Logfiles over $DaysToDelete days old have been removed Successfully!" -ForegroundColor Green
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        Write-Host " "
    }
    Else {
        Write-Host "C:\Windows\logs\CBS\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Removes C:\Config.Msi
    If (Test-Path C:\Config.Msi) {
        Remove-Item -Path C:\Config.Msi -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Config.Msi does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Removes c:\Intel
    If (Test-Path C:\Intel) {
        Remove-Item -Path C:\Intel -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Intel does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Removes c:\PerfLogs
    If (Test-Path C:\PerfLogs) {
        Remove-Item -Path c:\PerfLogs -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\PerfLogs does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Removes $Env:windir\memory.dmp
    If (Test-Path $Env:windir\memory.dmp) {
        Remove-Item $Env:windir\memory.dmp -Force -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Windows\memory.dmp does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Removes rouge folders
    Write-Host "Deleting Rouge Folders" -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "

    ## Removes Windows Error Reporting files
    If (Test-Path C:\ProgramData\Microsoft\Windows\WER) {
        Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER -Recurse | 
            Remove-Item -force -recurse -Verbose -ErrorAction SilentlyContinue
        Write-Host "Deleting Windows Error Reporting files" -ForegroundColor Green
        Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
        Write-Host " "
    } 
    Else {
        Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
    }

    ## Removes System and User Temp Files - lots of access denied will occur.
    ## Cleans up C:\Windows\Temp
    If (Test-Path $Env:windir\Temp\) {
        Remove-Item -Path "$Env:windir\Temp\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Windows\Temp does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Minidump
    If (Test-Path $Env:windir\minidump\) {
        Remove-Item -Path "$Env:windir\minidump\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "$Env:windir\minidump\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Prefetch
    If (Test-Path $Env:windir\Prefetch\) {
        Remove-Item -Path "$Env:windir\Prefetch\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "$Env:windir\Prefetch\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    # Windows 2003:
    #    C:\Documents and Settings\a-zct51531\Local Settings\Temp
    #    C:\Program Files\Microsoft SQL Server\100\Setup Bootstrap\Update Cache

    ## Cleans up each users Temp folder
    If (Test-Path "C:\Users\*\AppData\Local\Temp\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Temp\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Temp\ does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up all users Windows Error Reporting
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\WER\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\ProgramData\Microsoft\Windows\WER does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up users Temporary Internet files
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\ does not exist." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Internet Explorer cache
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\ does not exist." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Internet Explorer cache
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\ does not exist." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Internet Explorer download history
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\ does not exist." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Internet Cache
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\ does not exist." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Internet Cookies
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\ does not exist." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Cleans up Terminal Server cache
    If (Test-Path "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\") {
        Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\ does not exist." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    Write-Host "Removing System and User Temp Files..." -ForegroundColor Green
    Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host " "

    ## Removes the hidden Recycle Bin.
    If (Test-path 'C:\$Recycle.Bin') {
        Remove-Item 'C:\$Recycle.Bin' -Recurse -Force -Verbose -ErrorAction SilentlyContinue
    } 
    Else {
        Write-Host "C:\`$Recycle.Bin does not exist, there is nothing to cleanup." -ForegroundColor DarkGray
        Write-Host "[WARNING]" -ForegroundColor DarkYellow -BackgroundColor Black
        Write-Host " "
    }

    ## Turns errors back on
    $ErrorActionPreference = "Continue"

    ## Checks the version of PowerShell
    ## If PowerShell version 4 or below is installed the following will process
    If ($PSVersionTable.PSVersion.Major -Le 4) {
        ## Empties the Recycle Bin, the desktop Recycle Bin
        $Recycler = (New-Object -ComObject Shell.Application).NameSpace(0xa)
        $Recycler.Items() | ForEach-Object {
            ## If PowerShell version 4 or below is installed the following will process
            Remove-Item -Include $_.Path -Force -Recurse -Verbose
            Write-Host "The Recycle Bin has been cleaned up successfully!" -ForegroundColor Green
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            Write-Host " "
        }
    } 
    ElseIf ($PSVersionTable.PSVersion.Major -Ge 5) {
         ## If PowerShell version 5 is running on the machine the following will process
         Clear-RecycleBin -DriveLetter C:\ -Force -Verbose
         Write-Host "The Recycle Bin has been cleaned up successfully!" -ForegroundColor Green
         Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
         Write-Host " "
    }

    ## Starts Disk Cleanup Wizard (CleanMgr.exe)
    Function Start-CleanMGR {
        Try {
            Write-Host "Windows Disk Cleanup is running..." -ForegroundColor Green
            Start-Process -FilePath CleanMgr -ArgumentList '/sagerun:1' -Wait -Verbose
            Write-Host "[DONE]" -ForegroundColor Green -BackgroundColor Black
            Write-Host " "
        }
        Catch [System.Exception] {
            Write-Host "CleanMgr is not installed! To use this portion of the script you must install the following windows features: " -ForegroundColor Red
            Write-Host "[ERROR]" -ForegroundColor Red -BackgroundColor Black
            Write-Host " "
        }
    } Start-CleanMGR

    # Cleanup C:\Windows\WinSxS\ using Deployment Image Servicing and Management tool (DISM):
    #    https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/dn251565(v=win.10)
    #    https://www.saotn.org/windows-server-2012-r2-disk-cleanup-dism/
    #       Dism.exe /Online /Cleanup-Image /SpSuperseded
    #       Dism.exe /Online /Cleanup-Image /StartComponentCleanup
    #       Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase    # This is extreme!

    # Cleanup C:\Windows\ccmcache:
    #   Control Panel -> Configuration Manager -> Cache -> Configure Settings -> Delete Files
    #   https://gallery.technet.microsoft.com/scriptcenter/Deleting-the-SCCM-Cache-da03e4c7

    ## Gathers disk usage after running the cleanup cmdlets.
    $After = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -Eq "3"} | Select-Object `
        SystemName,
        @{Name = "Drive";          Expression = {( $_.DeviceID )}},
        @{Name = "Size (GB)";      Expression = {"{0:N1}" -f ($_.Size / 1GB)}},
        @{Name = "FreeSpace (GB)"; Expression = {"{0:N1}" -f ($_.Freespace / 1GB)}},
        @{Name = "PercentFree";    Expression = {"{0:P1}" -f ($_.FreeSpace / $_.Size)}} |
        Format-Table -AutoSize | Out-String

    ## Restarts the Windows Update service, wuauserv
    Get-Service -Name wuauserv | Start-Service -ErrorAction SilentlyContinue

    ## Stop timer
    $Enders = (Get-Date)

    ## Calculate amount of seconds your code takes to complete.
    Write-Verbose "Elapsed Time: $(($Enders - $Starters).TotalSeconds) Seconds"
    Write-Host " "

    ## Sends hostname to the console for ticketing purposes.
    Write-Host (Hostname) -ForegroundColor Green
    Write-Host " "

    ## Sends the date and time to the console for ticketing purposes.
    Write-Host (Get-Date | Select-Object -ExpandProperty DateTime) -ForegroundColor Green
    Write-Host " "

    ## Sends the disk usage before running the cleanup script to the console for ticketing purposes.
    Write-Verbose "Before: $Before"
    Write-Host " "

    ## Sends the disk usage after running the cleanup script to the console for ticketing purposes.
    Write-Verbose "After: $After"
    Write-Host " "


    ## Prompt to scan for large ISO, VHD, VHDX files.
<#
    While (-Not (($Choice = (Read-Host "Would you like to scan $ScanPath for ISOs or VHD(X) files?")) -Match "y|n")) {"Y or N ?"}
    Switch ($Choice) {
        "y" {
            Write-Host "Scanning $ScanPath for any large .ISO and or .VHD\.VHDX files per the Administrators request." -ForegroundColor Green
            Write-Verbose (Get-ChildItem -Path $ScanPath -Include *.iso, *.vhd, *.vhdx -Recurse -ErrorAction SilentlyContinue |
                Sort-Object Length -Descending | Select-Object `
                    Name, 
                    Directory,
                    @{Name = "Size (GB)"; Expression = {"{0:N2}" -f ($_.Length / 1GB)}} | Format-Table | Out-String -Verbose 
            )
        }
        "n" {
            Write-Host "The Administrator chose to not scan $ScanPath for large files." -ForegroundColor DarkYellow -Verbose
        }
    }
#>
    Function PromptForScan {
        Param (
            $ScanPath,
            $Title   = (Write-Host "Search for large files" -ForegroundColor Green),
            $Message = (Write-Host "Would you like to scan $ScanPath for ISOs or VHD(X) files?" -ForegroundColor Green)
        )
        $Yes     = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Scans $ScanPath for large files."
        $No      = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Skips scanning $ScanPath for large files."
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)
        $Prompt  = $Host.UI.PromptForChoice($Title, $Message, $Options, 0)
        Switch ($Prompt) {
            0 {
                Write-Host "Scanning $ScanPath for any large .ISO and or .VHD\.VHDX files per the Administrators request." -ForegroundColor Green
                Write-Verbose (Get-ChildItem -Path $ScanPath -Include *.iso, *.vhd, *.vhdx -Recurse -ErrorAction SilentlyContinue |
                    Sort-Object Length -Descending | Select-Object `
                        Name, 
                        Directory,
                        @{Name = "Size (GB)"; Expression = {"{0:N2}" -f ($_.Length / 1GB)}} | Format-Table | Out-String -Verbose 
                )
            }
            1 {
                Write-Host "The Administrator chose to not scan $ScanPath for large files." -ForegroundColor DarkYellow -Verbose
            }
        }
        Write-Host " "
    }
    PromptForScan -ScanPath C:\  # end of function

    ## Completed Successfully!
    Write-Host (Stop-Transcript) -ForegroundColor Green
    Write-Host " "
    Write-Host "PowerShell Script ($ScriptName) Ended at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host " "
}

Cleanup-DriveC

If (Test-Path "Clean-CMClientCache.ps1") {.\Clean-CMClientCache.ps1}
