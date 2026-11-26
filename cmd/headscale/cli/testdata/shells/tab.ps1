# Loads the completion script and prints what TabExpansion2 offers for each
# line. A completer that throws is printed as THROWS: the interactive
# console would show nothing.
# usage: pwsh -NoProfile -File tab.ps1 <script.ps1> <lines>
param($Script, $Lines)
. $Script
foreach ($row in Get-Content $Lines) {
  $line = $row.Substring(0, $row.Length - 1)
  "LINE: $row"
  try {
    $r = TabExpansion2 -inputScript $line -cursorColumn $line.Length -ErrorAction Stop
    $m = @($r.CompletionMatches | ForEach-Object { '[' + $_.CompletionText + ']' })
    if ($m.Count -eq 0) { "  (none)" } else { "  " + ($m -join ' ') }
  } catch {
    "  THROWS " + ($_.Exception.Message -replace "`n", ' ')
  }
}
