# build.ps1
# Builds the GitSin standalone executable using PyInstaller.
# Requires the project dependencies and uv to be set up.

Write-Host "[*] Installing PyInstaller into the virtual environment..."
uv pip install pyinstaller

Write-Host "[*] Compiling GitSin..."
# We bundle gitleaks_bin and threat_rules.json directly into the executable so it can be extracted at runtime
uv run pyinstaller --name gitsin --onefile --clean --add-data "gitleaks_bin;gitleaks_bin" --add-data "gitsin/threat_rules.json;gitsin" gitsin_runner.py

Write-Host "[+] Build complete. The standalone binary is located at: dist\gitsin.exe"
