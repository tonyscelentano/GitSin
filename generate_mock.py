import subprocess
import os
from pathlib import Path
import shutil

def run_cmd(cmd, cwd=None):
    print(f"Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True, cwd=cwd)

def generate_fixture():
    target_dir = Path(r"C:\RepoReckoning\GitSin-Mock-Vulnerable")
    if target_dir.exists():
        # Hard remove
        run_cmd(f'rmdir /s /q "{target_dir}"')
    
    target_dir.mkdir(parents=True)
    print(f"Generating Git fixture in: {target_dir}")
    
    run_cmd("git init", cwd=target_dir)
    run_cmd('git config user.name "Alice Architect"', cwd=target_dir)
    run_cmd('git config user.email "alice@corp.com"', cwd=target_dir)
    
    # 1. Safe commit
    readme_path = target_dir / "README.md"
    readme_path.write_text("# Project Phoenix\nNext-gen payments architecture.")
    run_cmd("git add README.md", cwd=target_dir)
    run_cmd('git commit -m "Initial commit"', cwd=target_dir)
    
    # 2. AWS Key (High Risk)
    run_cmd('git config user.name "Bob Backend"', cwd=target_dir)
    run_cmd('git config user.email "bob@corp.com"', cwd=target_dir)
    aws_path = target_dir / "aws_config.py"
    aws_path.write_text("AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\nAWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
    run_cmd("git add aws_config.py", cwd=target_dir)
    run_cmd('git commit -m "Add AWS S3 bucket config"', cwd=target_dir)

    # 3. RSA Private Key (Critical)
    run_cmd('git config user.name "Charlie DevOps"', cwd=target_dir)
    run_cmd('git config user.email "charlie@corp.com"', cwd=target_dir)
    ssh_dir = target_dir / ".ssh"
    ssh_dir.mkdir()
    rsa_path = ssh_dir / "id_rsa_prod"
    rsa_path.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----")
    run_cmd("git add .ssh/id_rsa_prod", cwd=target_dir)
    run_cmd('git commit -m "Adding prod SSH keys for pipeline deploy"', cwd=target_dir)

    # 4. Stripe Key (Financial Exposure)
    run_cmd('git config user.name "Alice Architect"', cwd=target_dir)
    run_cmd('git config user.email "alice@corp.com"', cwd=target_dir)
    stripe_path = target_dir / "payments.js"
    stripe_path.write_text("const stripeKey = 'sk_live_51Nxabc1234567890abcdef';\n")
    run_cmd("git add payments.js", cwd=target_dir)
    run_cmd('git commit -m "Hotfix: Hardcoded stripe live key for testing"', cwd=target_dir)
    
    # 5. Supply Chain (OSV hit)
    # We will simulate a malicious package. For our OSV adapter, it triggers on certain known bad packages if the adapter is running. 
    # But just the cryptographic sins will light up the dashboard beautifully.
    
    print("\nFixture generated successfully. Ready to scan!")

if __name__ == "__main__":
    generate_fixture()
