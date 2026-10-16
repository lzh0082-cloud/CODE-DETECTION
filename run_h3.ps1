# H3 runs (preregistration/H3_multimodel.md): one process per model, in parallel. Rerunning resumes from the cache.
Set-Location $PSScriptRoot
$models = "glm-5.2", "kimi-k2.6", "kimi-k3", "qwen3.7-plus", "qwen3.7-max", "qwen3.7-flash", "ds-v4.1-flash"
$procs = foreach ($m in $models) {
    Start-Process python -ArgumentList "-m", "sgv.evidence", "--pairs", "0", "--models", $m, "--conditions", "C2,C4,C5",
        "--presentation", "plain", "--workers", "6", "--out", "results/h3_$m" `
        -RedirectStandardOutput "results/h3_$m.log" -RedirectStandardError "results/h3_$m.err" -NoNewWindow -PassThru
}
$procs | Wait-Process
foreach ($m in $models) { "== $m"; Get-Content "results/h3_$m.log" -Tail 2 }
