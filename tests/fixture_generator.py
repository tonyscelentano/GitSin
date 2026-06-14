import subprocess
import tempfile
import os
from pathlib import Path

def run_cmd(cmd, cwd=None):
    subprocess.run(cmd, shell=True, check=True, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def generate_fixture():
    # 1. Create a temporary directory
    target_dir = tempfile.mkdtemp(prefix="gitsin_sandbox_")
    print(f"Generating Git fixture in: {target_dir}")
    
    # 2. Init git
    run_cmd("git init", cwd=target_dir)
    
    # 3. Configure mock author
    run_cmd('git config user.name "Sinner Dev"', cwd=target_dir)
    run_cmd('git config user.email "sinner@example.com"', cwd=target_dir)
    
    # 4. Generate commits over a fake timeline
    
    # Safe commit
    readme_path = Path(target_dir) / "README.md"
    readme_path.write_text("# Safe Project\nNothing to see here.")
    run_cmd("git add README.md", cwd=target_dir)
    run_cmd('git commit -m "Initial commit"', cwd=target_dir)
    
    # Sin 1: AWS Key
    aws_path = Path(target_dir) / "aws_config.py"
    aws_path.write_text("AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n")
    run_cmd("git add aws_config.py", cwd=target_dir)
    run_cmd('git commit -m "Add AWS config"', cwd=target_dir)
    
    # Sin 2: Stripe Key
    stripe_path = Path(target_dir) / "payments.js"
    stripe_path.write_text("const stripeKey = 'sk_test_51Nxabc123';\n")
    run_cmd("git add payments.js", cwd=target_dir)
    run_cmd('git commit -m "Add Stripe integration"', cwd=target_dir)
    
    print("Fixture generated successfully with seeded high-entropy secrets.")
    return target_dir

if __name__ == "__main__":
    generate_fixture()
