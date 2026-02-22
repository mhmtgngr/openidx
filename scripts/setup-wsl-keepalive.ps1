$action = New-ScheduledTaskAction -Execute 'wsl.exe' -Argument '-u root -- bash -c "nohup sleep infinity &"'
$trigger = New-ScheduledTaskTrigger -AtLogon
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'WSL_KeepAlive' -Action $action -Trigger $trigger -Settings $settings -Description 'Keep WSL running so Docker and OpenIDX stay alive' -RunLevel Highest -Force
Write-Host "WSL_KeepAlive scheduled task created successfully"
