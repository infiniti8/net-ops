# Import the Posh-SSH module
Import-Module Posh-SSH

# Define the path to the file containing hostnames
$hostnameFile = "PATH_TO_TXT_FILE_WITH_TARGET_DEVICES"

# Define the SSH credentials
$username = "smelkov@rencap.com"
$encryptedPassword = "ENCRYPTED_PASSWORD" # About encrypted strings: https://www.pdq.com/blog/secure-password-with-powershell-encrypting-credentials-part-2/
$password = ConvertTo-SecureString -String $encryptedPassword
$credentials= New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, (Get-Content $password | ConvertTo-SecureString)

# Read hostnames from the file
$hostnames = Get-Content $hostnameFile

# Iterate through each hostname
foreach ($hostname in $hostnames) {
    # Define the SSH connection information
    $sshConnection = New-SSHSession -ComputerName $switch -Credential $credentials -AcceptKey:$true

    # Specify the command to get DHCP bindings
    $dhcpBindingsCommand = "show ip dhcp binding"

    # Execute the command on the Cisco device
    $dhcpBindingsOutput = Invoke-SSHCommand -SessionId $sshConnection.SessionId -Command $dhcpBindingsCommand

    # Extract IP and MAC addresses from the DHCP binding output
	$ipMacClientList = $dhcpBindingsOutput.Output | Select-String -Pattern '(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]+)' | ForEach-Object {
        $matches = $_.Matches[0]
        $ip = $matches.Groups[1].Value
        $mac = $matches.Groups[0].Value -replace '[-:]', ''
        $clientIdentifier = $matches.Groups[4].Value
        $macFromClientIdentifier = ConvertFrom-HexString $clientIdentifier
        "$ip,$mac$macFromClientIdentifier"
    }

    # Define the output file path for the current switch
    $outputFilePath = "PATH_TO_TXT_FILE_WITH_OUTPUT"

    # Save the IP:MAC list to the file
    $ipMacClientList | Out-File -FilePath $outputFilePath -Force

    # Display a message indicating the output file path
    Write-Output "IP:MAC addresses for $hostname saved to $outputFilePath"

    # Close the SSH session
    Remove-SSHSession -SessionId $sshConnection.SessionId
}

# Function to convert hexadecimal string to MAC address
function ConvertFrom-HexString {
    param (
        [string]$hex
    )
    $mac = -join ($hex -split "(..)" | Where-Object {$_})
    $mac -join ':'
}
