$fn = $($MyInvocation.MyCommand.Name)
$name = $fn -replace "(.*)\.ps1$", '$1'
Register-ArgumentCompleter -Native -CommandName $name -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $other = "$wordToComplete --generate-shell-completion"
    Invoke-Expression $other | ForEach-Object {
        $parts = $_.Split(':', 2)
        if ($parts.Count -eq 2) {
            $completion = $parts[0].Trim()
            $description = $parts[1].Trim()
            [System.Management.Automation.CompletionResult]::new($completion, $completion, 'ParameterValue', $description)
        } else {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}