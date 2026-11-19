#!/usr/bin/env python3
"""selftest.py -- checks that the two self-check scripts work AND that they only read.

  python3 selftest.py

What it proves:
  1. wifi_selfcheck.sh parses, and its ro() guard refuses state-changing commands.
  2. The monitor-mode parser and the "who can write this file?" check give the right answers
     on fixtures (a fake iw output and temporary files with known permissions).
  3. wifi_selfcheck.sh runs to completion on this machine (read-only) and prints a summary.
  4. A static scan finds no state-changing, capture or attack commands in either script.
  5. wifi_selfcheck.ps1 parses, if PowerShell is installed here.
Standard library only. Prints SELFTEST PASS at the end, or exits non-zero.
"""
import os, re, shutil, stat, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SH = os.path.join(HERE, "wifi_selfcheck.sh")
PS = os.path.join(HERE, "wifi_selfcheck.ps1")
BASH = shutil.which("bash")
fails = []


def check(name, cond, detail=""):
    print("  %s  %s%s" % ("ok  " if cond else "FAIL", name, (" -- " + detail) if (detail and not cond) else ""))
    if not cond:
        fails.append(name)


def bash(script, timeout=60):
    r = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


# Pull the helper functions out of the script so they can be tested on their own.
SRC = open(SH, encoding="utf-8").read()
def func(name):
    m = re.search(r"^%s\(\)\s+\{.*$" % re.escape(name), SRC, re.M)
    if not m:
        return ""
    if m.group(0).rstrip().endswith("}"):          # one-line function
        return m.group(0) + "\n"
    end = SRC.find("\n}\n", m.start())              # multi-line: up to the closing brace at column 0
    return SRC[m.start():end + 3]
HELPERS = "\n".join(func(n) for n in ("ro", "rd", "say", "ok", "info", "flag", "monitor_support", "check_node"))
HELPERS = "set -u\nexport LC_ALL=C\nFLAGS=0\n" + HELPERS

print("1. syntax and the read-only guard")
if BASH:
    rc, out = bash("%s -n %s" % (BASH, SH))
    check("wifi_selfcheck.sh parses", rc == 0, out)
    for bad in ("iw dev wlan0 set type monitor", "iw phy phy0 interface add mon0 type monitor",
                "iw dev wlan0 scan", "iw dev wlan0 del", "ip link set wlan0 down",
                "tcpdump -i wlan0", "rm -rf /tmp/x"):
        rc, out = bash(HELPERS + "\nro %s; echo rc=$?" % bad)
        check("ro() refuses '%s'" % bad, "rc=99" in out, out)
    for good in ("id -u", "iw dev"):
        rc, out = bash(HELPERS + "\nro %s >/dev/null; echo rc=$?" % good)
        check("ro() allows '%s'" % good, "rc=99" not in out, out)
else:
    print("  SKIP  bash not found (fine on Windows); runtime checks of the .sh are skipped")

print("2. parsers and permission checks on fixtures")
if BASH:
    with_monitor = "Wiphy phy0\\n\\tSupported interface modes:\\n\\t\\t * IBSS\\n\\t\\t * managed\\n\\t\\t * monitor\\n\\tBand 1:\\n"
    without = "Wiphy phy0\\n\\tSupported interface modes:\\n\\t\\t * managed\\n\\t\\t * AP\\n\\tBand 1:\\n" \
              "\\tsoftware interface modes (can always be added):\\n\\t\\t * monitor\\n"
    rc, out = bash(HELPERS + "\niw() { printf '%s'; }\nmonitor_support phy0" % with_monitor)
    check("monitor_support says yes when the driver lists monitor", out.strip() == "yes", out)
    rc, out = bash(HELPERS + "\niw() { printf '%s'; }\nmonitor_support phy0" % without)
    check("monitor_support ignores the 'software modes' list", out.strip() == "no", out)
    tmp = tempfile.mkdtemp()
    try:
        wide, tight = os.path.join(tmp, "wide"), os.path.join(tmp, "tight")
        open(wide, "w").close(); open(tight, "w").close()
        os.chmod(wide, 0o666); os.chmod(tight, 0o600)
        rc, out = bash(HELPERS + "\nMYUID=$(id -u)\ncheck_node %s fixture; echo FLAGS=$FLAGS" % wide)
        check("a world-writable file is FLAGGED", "[FLAG]" in out and "FLAGS=1" in out, out)
        rc, out = bash(HELPERS + "\nMYUID=99999\ncheck_node %s fixture; echo FLAGS=$FLAGS" % tight)
        check("an owner-only file is not flagged", "[FLAG]" not in out and "FLAGS=0" in out, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

print("3. a real, read-only run on this machine")
if BASH and sys.platform.startswith("linux"):
    r = subprocess.run([BASH, SH], capture_output=True, text=True, timeout=120)
    check("wifi_selfcheck.sh exits 0 or 3", r.returncode in (0, 3), "rc=%s %s" % (r.returncode, r.stderr[-300:]))
    check("it prints a summary", "== Summary" in r.stdout and "FLAGS:" in r.stdout, r.stdout[-300:])
    check("its guard was never tripped", "ro: refused" not in r.stderr, r.stderr[-300:])
else:
    print("  SKIP  not Linux")

print("4. static scan: nothing that changes, captures or attacks")
SH_DENY = [r"\b(airmon-ng|aireplay-ng|aircrack-ng|airodump-ng|mdk[34]|bettercap|hcxdumptool|reaver|wifite|tshark)\b",
           r"\b(tcpdump|dumpcap)\s+-", r"\b(sudo|modprobe|rmmod|insmod|setcap|chmod|chown|nmcli|wpa_cli|iwconfig|ifconfig|curl|wget)\b",
           r"\brfkill\s+(block|unblock)", r"\bip\s+(link|addr|route)\s+(set|add|del)",
           r"\biw\s+(dev|phy)\s+\S+\s+(set|del|connect|disconnect|scan|interface)\b", r">\s*/(sys|proc)/", r">\s*/dev/(?!null)"]
PS_DENY = [r"\b(Set|New|Remove|Enable|Disable|Restart|Stop|Start|Install|Uninstall|Rename|Add|Clear|Reset|Suspend|Resume)-[A-Za-z]+",
           r"\bInvoke-(WebRequest|RestMethod|Expression|Command)\b", r"\bOut-File\b", r"\bWlanHelper\b", r"\bpktmon\b",
           r"\bnetsh\s+\S+\s+(?!show\b)\w+", r"\b(reg|sc)(\.exe)?\s+(add|delete|config|stop|start|create)\b",
           r"\b(bcdedit|devcon|pnputil)\b"]

def code_lines(path, ps=False):
    text = open(path, encoding="utf-8").read()
    if ps:
        text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]

def scan(lines, pats):
    return [(l.strip(), p) for l in lines for p in pats if re.search(p, l)]

check("the scanner itself catches a planted bad line",
      bool(scan(["sudo iw dev wlan0 set type monitor"], SH_DENY)) and bool(scan(["Set-NetAdapter -Name x"], PS_DENY)))
hits = scan(code_lines(SH), SH_DENY)
check("wifi_selfcheck.sh has no state-changing commands", not hits, str(hits[:3]))
hits = scan(code_lines(PS, ps=True), PS_DENY)
check("wifi_selfcheck.ps1 has no state-changing commands", not hits, str(hits[:3]))
check("wifi_selfcheck.ps1 is plain ASCII (Windows PowerShell 5.1 safe)", all(ord(c) < 128 for c in open(PS, encoding="utf-8").read()))

print("5. PowerShell syntax")
pwsh = shutil.which("pwsh") or shutil.which("powershell") or shutil.which("powershell.exe")
if pwsh:
    cmd = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput("
           "[Console]::In.ReadToEnd(), [ref]$null, [ref]$e); 'PARSE_ERRORS=' + $e.Count")
    r = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], input=open(PS, encoding="utf-8").read(),
                       capture_output=True, text=True, timeout=120)
    check("wifi_selfcheck.ps1 parses", "PARSE_ERRORS=0" in r.stdout, (r.stdout + r.stderr)[-300:])
else:
    print("  SKIP  no PowerShell on this machine")

if fails:
    print("SELFTEST FAIL (%d): %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("SELFTEST PASS")
