$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$branch = (& git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or -not $branch) {
    throw "Could not determine the current Git branch."
}

$lastStatus = $null
$changedAt = Get-Date

while ($true) {
    $status = (@(& git status --porcelain --untracked-files=all) -join "`n").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read Git status."
    }

    if ($status -ne $lastStatus) {
        $lastStatus = $status
        $changedAt = Get-Date
    }

    if ($status -and ((Get-Date) - $changedAt).TotalSeconds -ge 5) {
        & git add -A
        if ($LASTEXITCODE -ne 0) {
            throw "Could not stage project changes."
        }

        $stagedFiles = @(& git diff --cached --name-only)
        if ($LASTEXITCODE -ne 0) {
            throw "Could not inspect staged changes."
        }

        if ($stagedFiles.Count -gt 0) {
            $commitMessage = "Auto-sync $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            & git commit -m $commitMessage
            if ($LASTEXITCODE -ne 0) {
                throw "Could not commit changes. Review the Git output and resolve the issue."
            }

            & git push origin $branch
            if ($LASTEXITCODE -ne 0) {
                throw "Could not push to GitHub. Check your connection, GitHub access, and whether the remote branch has new commits."
            }

            Write-Host "Changes committed and pushed to origin/$branch."
        }

        $lastStatus = (@(& git status --porcelain --untracked-files=all) -join "`n").Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "Could not confirm the repository status after syncing."
        }
        $changedAt = Get-Date
    }

    Start-Sleep -Seconds 2
}
