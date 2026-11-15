# PowerShell script to collect Windows Event Logs and export to CSV
# Run this as Administrator: Right-click PowerShell and select "Run as Administrator", then:
#   powershell -ExecutionPolicy Bypass -File collect_windows_logs.ps1

param(
    [string]$OutputPath = "",
    [int]$MaxEventsPerLog = 500,
    [string]$SelectedChannels = ""
)

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot "data\logs\windows_events_admin.csv"
}

# Create output directory if needed
$OutputDir = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# List of Windows Event Channels to collect
if ([string]::IsNullOrWhiteSpace($SelectedChannels)) {
    $Channels = @(
        "System",
        "Application",
        "Security",
        "Microsoft-Windows-Windows Defender/Operational",
        "ForwardedEvents"
    )
} else {
    $Channels = $SelectedChannels -split "\|"
}

# Initialize array to hold all events
$AllEvents = @()

Write-Host "Collecting Windows Event Logs as Administrator..." -ForegroundColor Green

foreach ($Channel in $Channels) {
    Write-Host "  Collecting from channel: $Channel"
    
    try {
        # Try using Get-WinEvent (requires Admin for some channels)
        $Events = @(Get-WinEvent -LogName $Channel -MaxEvents $MaxEventsPerLog -ErrorAction SilentlyContinue)
        
        if ($Events.Count -gt 0) {
            foreach ($Event in $Events) {
                $AllEvents += [PSCustomObject]@{
                    timestamp = $Event.TimeCreated.ToString("o")
                    event_id = $Event.Id
                    level = $Event.LevelDisplayName
                    source = $Event.ProviderName
                    message = $Event.Message -replace "`r?`n", " "
                    computer = $Event.MachineName
                    log_type = $Channel
                    ingest_method = "Get-WinEvent"
                }
            }
            Write-Host "    -> Collected $($Events.Count) events" -ForegroundColor Green
        } else {
            Write-Host "    -> No events found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    -> Error reading channel: $_" -ForegroundColor Red
    }
}

if ($AllEvents.Count -gt 0) {
    $AllEvents | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nSuccessfully exported $($AllEvents.Count) events to: $OutputPath" -ForegroundColor Green
    Write-Host "The dashboard will now read from this file." -ForegroundColor Cyan
} else {
    Write-Host "`nNo events were collected. Check that you are running as Administrator." -ForegroundColor Red
}
