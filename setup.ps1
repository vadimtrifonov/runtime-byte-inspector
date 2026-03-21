$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPath = Join-Path $projectRoot ".venv"
$python = "python"

Push-Location $projectRoot
try {
    if (-not (Test-Path $venvPath)) {
        & $python -m venv $venvPath
    }

    $venvPython = Join-Path $venvPath "Scripts/python.exe"
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install -r (Join-Path $projectRoot "requirements.txt")
} finally {
    Pop-Location
}
