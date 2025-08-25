# 🧰 Helper (run commands etc.)
import subprocess
import os

def run(cmd):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return proc.returncode == 0, proc.stdout + proc.stderr
    except Exception as e:
        return False, str(e)