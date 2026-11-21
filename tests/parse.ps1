param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Files)
$bad = 0
foreach ($f in $Files) {
  $t = $null; $e = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f), [ref]$t, [ref]$e)
  if ($e.Count) { $bad++; "PARSE ERRORS in ${f}:"; $e | ForEach-Object { "  line $($_.Extent.StartLineNumber): $($_.Message)" } } else { "parse OK: $f" }
}
exit $bad
