from pathlib import Path
import re
b=Path.cwd()
install=(b/'docs/install.md').read_text()
win=(b/'docs/windows.md').read_text()
run=(b/'docs/RUN.md').read_text()
readme=(b/'README.md').read_text()
checks={
 'published Setup asset in install and README':all('PatchTrace-Windows-x64-Setup.exe' in s for s in (install,readme)),
 'known example asset names shell safe':all('<version>' not in block for block in re.findall(r'```(?:powershell|bash)\n(.*?)```',install,re.S)),
 'CLI Linux runtime location': '~/.local/share/patchtrace/runtimes' in install,
 'registry and Apps uninstall instructions': 'Windows Apps' in install or 'Installed apps' in install,
 'docs match pin file': 'are still unresolved placeholders' not in install,
 'Windows docs install release extras': ".[dev,search,rules]" in win,
 'PowerShell smoke scratch and user profile': 'RUNNER_TEMP' in win and ('test account' in win or 'disposable' in win),
 'self-contained CLI first-run and backup': all(s in run for s in ('project sample --project', 'project backup', 'project info')),
}
for k,v in checks.items():print('PASS' if v else 'FAIL',k)
raise SystemExit(not all(checks.values()))
