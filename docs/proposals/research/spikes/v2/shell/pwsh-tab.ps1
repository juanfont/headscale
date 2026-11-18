# Loads the candidate's script and prints what TabExpansion2 offers for every line.
# usage: pwsh -NoProfile -File pwsh-tab.ps1 <script.ps1> <lines.txt>
# A completer that throws is printed as THROWS (the interactive console would show nothing).
param($Script, $Lines)
. $Script
foreach ($line in Get-Content $Lines) {
  if (-not $line -or $line.StartsWith('#')) { continue }
  "LINE: $line"
  try {
    $r = TabExpansion2 -inputScript $line -cursorColumn $line.Length -ErrorAction Stop
    $m = @($r.CompletionMatches | ForEach-Object { '[' + $_.CompletionText + ']' })
    "  " + ($m -join ' ')
  } catch {
    "  THROWS " + ($_.Exception.Message -replace "`n", ' ')
  }
}
