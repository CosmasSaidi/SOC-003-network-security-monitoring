#!/usr/bin/env python3
"""SOC-003 Phase 3D helper: run PowerShell on a lab guest over the pre-existing
SOC-002 WinRM (NTLM) channel and pull files back over HTTP.

Reads WINRM_USER / WINRM_PASS from the environment. Never prints credentials.
"""
import base64, os, sys, winrm

def sess(host):
    u = os.environ.get("WINRM_USER"); p = os.environ.get("WINRM_PASS")
    if not u or not p: sys.exit("MISSING CREDENTIALS")
    return winrm.Session(f"http://{host}:5985/wsman", auth=(u, p), transport="ntlm",
                         server_cert_validation="ignore", read_timeout_sec=300,
                         operation_timeout_sec=280)

def run_ps(host, script):
    r = sess(host).run_ps(script)
    out = r.std_out.decode("utf-8", "replace")
    err = r.std_err.decode("utf-8", "replace")
    # strip CLIXML progress noise
    if err.strip().startswith("#< CLIXML"):
        err = "\n".join(l for l in err.splitlines() if not l.strip().startswith("<Objs"))
    return r.status_code, out, err

def push_b64(host, local, remote, chunk=1200):
    data = open(local, "rb").read()
    b64 = base64.b64encode(data).decode()
    run_ps(host, f"Remove-Item '{remote}' -ErrorAction SilentlyContinue; "
                 f"Remove-Item '{remote}.b64' -ErrorAction SilentlyContinue")
    for i in range(0, len(b64), chunk):
        part = b64[i:i+chunk]
        rc, out, err = run_ps(host, "$f='%s.b64'\nAdd-Content -Path $f -Value '%s' -NoNewline" % (remote, part))
        if rc != 0: sys.exit(f"chunk {i} failed: {err}")
    script = ("$s=(Get-Content '%s.b64' -Raw)\n"
              "$b=[Convert]::FromBase64String($s)\n"
              "[IO.File]::WriteAllBytes('%s',$b)\n"
              "Remove-Item '%s.b64' -ErrorAction SilentlyContinue\n"
              "(Get-FileHash '%s' -Algorithm SHA256).Hash" % (remote, remote, remote, remote))
    rc, out, err = run_ps(host, script)
    return rc, out.strip().splitlines()[-1] if out.strip() else err

def pull_b64(host, remote, out_path, chunk=2500):
    rc, out, err = run_ps(host, "if(Test-Path '%s'){[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))}else{'MISSING'}" % (remote, remote))
    if rc != 0: sys.exit(f"read failed: {err}")
    b64 = "".join(l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith("[RC]"))
    if b64 == "MISSING": sys.exit(f"{remote} missing on {host}")
    data = base64.b64decode(b64)
    open(out_path, "wb").write(data)
    return len(data)

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "verify":
        host, p, expect = sys.argv[2], sys.argv[3], sys.argv[4]
        rc, out, err = run_ps(host, "(Get-FileHash '%s' -Algorithm SHA256).Hash" % p)
        print(f"remote={out.strip()} expected={expect.upper()} match={out.strip().upper()==expect.upper()}")
    elif cmd == "push":
        host, local, remote = sys.argv[2], sys.argv[3], sys.argv[4]
        rc, h = push_b64(host, local, remote); print(f"rc={rc} remote_sha={h}")
    elif cmd == "pull":
        host, remote, out = sys.argv[2], sys.argv[3], sys.argv[4]
        n = pull_b64(host, remote, out); print(f"wrote {out} ({n} bytes)")
    elif cmd == "run":
        host = sys.argv[2]; script = open(sys.argv[3]).read()
        rc, out, err = run_ps(host, script)
        sys.stdout.write(out)
        if err.strip(): sys.stdout.write("\n[STDERR]\n" + err)
        print(f"\n[RC]={rc}")
