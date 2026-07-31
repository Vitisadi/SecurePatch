# Run all 42 off-diagonal v2 fix pipelines
# Groups by fixer column (6 parallel per group) to avoid overwhelming any single provider

$harness = "C:\Users\liakht\Dropbox\PC\Documents\GitHub\SecurePatch\harness"
$results = "$harness\results"
$log = "$results\v2_fix_runs_log.md"

$detectors = @{
    sonnet = @{ provider = "anthropic"; model = "claude-sonnet-4-6" }
    opus   = @{ provider = "anthropic"; model = "claude-opus-4-8" }
    haiku  = @{ provider = "anthropic"; model = "claude-haiku-4-5-20251001" }
    gpt55  = @{ provider = "openai";    model = "gpt-5.5" }
    mini   = @{ provider = "openai";    model = "gpt-4.1-mini" }
    gemini = @{ provider = "gemini";    model = "gemini-2.5-flash" }
    ollama = @{ provider = "ollama";    model = "qwen2.5-coder:7b" }
}

$fixers = @{
    sonnet = @{ provider = "anthropic"; model = "claude-sonnet-4-6" }
    opus   = @{ provider = "anthropic"; model = "claude-opus-4-8" }
    haiku  = @{ provider = "anthropic"; model = "claude-haiku-4-5-20251001" }
    gpt55  = @{ provider = "openai";    model = "gpt-5.5" }
    mini   = @{ provider = "openai";    model = "gpt-4.1-mini" }
    gemini = @{ provider = "gemini";    model = "gemini-2.5-flash" }
    ollama = @{ provider = "ollama";    model = "qwen2.5-coder:7b" }
}

$detLabels  = @("sonnet","opus","haiku","gpt55","mini","gemini","ollama")
$fixLabels  = @("sonnet","opus","haiku","gpt55","mini","gemini","ollama")

function Wait-ForFiles($files, $label) {
    Write-Host "Waiting for $label batch to complete..."
    while ($true) {
        $done = $true
        foreach ($f in $files) {
            if (-not (Test-Path $f)) { $done = $false; break }
            $lines = (Get-Content $f -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
            if ($lines -lt 56) { $done = $false; break }
        }
        if ($done) { break }
        Start-Sleep -Seconds 20
    }
    Write-Host "$label batch complete."
}

# Run one fixer column at a time (6 runs in parallel per batch)
foreach ($fix in $fixLabels) {
    $fixer = $fixers[$fix]
    $batchFiles = @()

    foreach ($det in $detLabels) {
        if ($det -eq $fix) { continue }  # skip diagonal

        $outFile = "$results\fix_${det}_${fix}_v2.jsonl"
        if (Test-Path $outFile) {
            $lines = (Get-Content $outFile -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
            if ($lines -ge 56) {
                Write-Host "SKIP $det->$fix (already done)"
                continue
            }
        }

        $detectJsonl = "$results\${det}_detect_v2.jsonl"
        $cmd = "cd '$harness'; python -m securepatch_bench fix --detect-jsonl '$detectJsonl' --detect-label ${det}_v2 --provider $($fixer.provider) --model $($fixer.model) --record '$outFile'"
        Start-Process powershell -ArgumentList "-NoProfile -Command `"$cmd`"" -WindowStyle Hidden
        Write-Host "STARTED $det -> $fix"
        $batchFiles += $outFile
    }

    if ($batchFiles.Count -gt 0) {
        Wait-ForFiles $batchFiles "fixer=$fix"
        Add-Content $log "- Batch fixer=$fix completed $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    }
}

Write-Host "ALL 42 RUNS COMPLETE"
Add-Content $log "- ALL DONE $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
