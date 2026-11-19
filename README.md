<img src="cover.png" alt="WiFi Capture Reality Check" width="100%">

# WiFi Capture Reality Check

A free, read-only self-check for your own laptop or PC, plus a plain-English guide to how WiFi packet capture really works.

You may have seen a reel claiming that an AI tool "reverse engineered" a laptop's WiFi driver and turned it into a packet sniffer: "a real 802.11 capture", with the device "wide open, read/write, no admin", and a "comment this keyword" call to action at the end.

This repo is the calm version. What is actually going on, how real capture is done with standard tools on hardware you own, and two small scripts that tell you whether **your** machine lets ordinary, non-admin users capture packets or write to the WiFi adapter.

## Run it

**Linux**, as your normal user (root is not needed):

```bash
bash wifi_selfcheck.sh
```

**Windows**, in a normal PowerShell window (admin is not needed):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\wifi_selfcheck.ps1
```

`-ExecutionPolicy Bypass` applies to that one run only. Read the script before you run it; it is short.

**Check the checker** (Python 3, standard library only):

```bash
python3 selftest.py
```

It proves the Linux script's guard refuses state-changing commands, tests its parsers on fixtures, runs it once read-only, scans both scripts for anything that changes, captures or attacks, and parses the PowerShell script if PowerShell is installed.

Both scripts exit `0` when nothing is flagged and `3` when at least one `[FLAG]` line was printed.

## What the self-check looks at

| | Linux (`wifi_selfcheck.sh`) | Windows (`wifi_selfcheck.ps1`) |
|---|---|---|
| Who is running it | user, groups, root, Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) | user, elevated or not, Administrators membership |
| Your wireless adapters | driver, bus (PCI / USB / SDIO), current mode | driver, version, status |
| Monitor-mode support | "Supported interface modes" from `iw phy <phy> info` | "Network monitor mode" from `netsh wlan show wirelesscapabilities` |
| Who can capture without admin | file capabilities or setuid on `dumpcap` / `tcpdump`, and who may run them | Npcap installed? `AdminOnly`? `Dot11Support`? Old WinPcap? |
| Can ordinary users write to the device | permissions and ACLs of the USB device node or PCI sysfs files, world-writable sysfs files, `/dev/rfkill`, WiFi debugfs | any custom security descriptor (SDDL) on the adapter device, translated to plain English |

Every external program the Linux script runs goes through one function, `ro()`, which only allows `id`, `stat`, `readlink`, `getcap`, `getfacl` and the read-only forms of `iw` (`iw dev`, `iw dev <if> info`, `iw phy <phy> info`). Anything else is refused. The Windows script only uses `Get-*` cmdlets, `whoami` and `netsh wlan show`.

Example summary (Linux, a Raspberry Pi's built-in WiFi):

```
== Summary
  Wireless interfaces: 1
    - wlan0 (brcmfmac, sdio): mode managed, monitor support no
  This account can capture packets: no
  Device files writable by every account: none found
  FLAGS: 0
```

How to read the results:

- **Monitor mode: SUPPORTED** means your driver can do it. That is a normal feature, not a vulnerability. Switching to it needs root or admin.
- **This account can capture packets: yes (via dumpcap, group 'wireshark')** means someone chose the "let non-root users capture" option when installing Wireshark. Fine if that was you.
- **Npcap is NOT restricted to administrators** (Windows) means any program run by any user on that PC can capture. That is the Npcap installer's default, and you can change it.
- **[FLAG]** means a real weakening of the defaults: a USB device node writable by every account, a capture tool every user can run with capture privileges, an old WinPcap install, or a device security descriptor that gives Everyone write access. Fix it locally. If it shipped that way from a vendor, report it to them.

## How real 802.11 capture works

### Managed mode and monitor mode

- **Managed mode** is what your adapter does all day. It joins one network and hands your computer only the frames meant for it (plus broadcast and multicast), already decrypted and converted to look like Ethernet. Capturing in managed mode shows you **your own** traffic.
- **Monitor mode** tells the radio to pass up every 802.11 frame it hears on the channel it is tuned to, from every nearby network, with a radiotap header (signal strength, data rate, channel). While a radio is in monitor mode it is not a normal network connection, so you usually add a separate monitor interface or use a second adapter.
- Whether you get monitor mode depends on the chipset, the driver and the firmware. It is not unlocked by software tricks. It has been part of Linux WiFi drivers for over twenty years; tools like Kismet were built on it in the early 2000s. Many USB adapters support it on Linux. Many laptop drivers on Windows do not.

### Linux, with standard tools, on your own network

```bash
# 1. What does my card support? (read-only)
iw list | grep -A 10 "Supported interface modes"

# 2. Add a monitor interface next to your normal one (needs root)
sudo iw phy phy0 interface add mon0 type monitor
sudo ip link set mon0 up
sudo iw dev mon0 set channel 6          # the channel YOUR access point uses

# 3. Capture
sudo tcpdump -i mon0 -w my-network.pcap  # or open mon0 in Wireshark

# 4. Clean up
sudo iw dev mon0 del
```

- aircrack-ng's `airmon-ng start wlan0` does step 2 in one command, and `airmon-ng check` lists processes (such as NetworkManager) that may fight you for the card.
- Wireshark can do it from the GUI: Capture, Options, tick "Monitor Mode" on the interface. On the command line that is `dumpcap -I -i wlan0`.
- To capture without typing `sudo`, Debian and Ubuntu's Wireshark package asks "Should non-superusers be able to capture packets?". Yes gives `dumpcap` the `cap_net_raw` and `cap_net_admin` capabilities and lets only the `wireshark` group run it. That is the documented, deliberate "no admin" capture path, and it is exactly what `wifi_selfcheck.sh` reports in section 3.

### Windows, with standard tools

- Run `netsh wlan show wirelesscapabilities` and look for **Network monitor mode : Supported**.
- Install **Wireshark**, which installs **Npcap**. In the Npcap installer:
  - tick **"Support raw 802.11 traffic (and monitor mode) for wireless adapters"** if you want monitor-mode capture;
  - consider ticking **"Restrict Npcap driver's access to Administrators only"**. If it stays unticked (the default), any program run by any local user can capture. That is the Windows version of "no admin" capture, by design.
- Switch an adapter to monitor mode, as administrator, with Npcap's helper: `WlanHelper.exe "Wi-Fi" mode monitor`, pick a channel with `WlanHelper.exe "Wi-Fi" channel 6`, and go back with `WlanHelper.exe "Wi-Fi" mode managed`. Wireshark's "Monitor Mode" checkbox does the same when the driver supports it.
- Windows' built-in `pktmon` and `netsh trace` capture your own PC's traffic (admin required). They are not monitor-mode tools.

### What you can and cannot see

In monitor mode, on the one channel your radio is tuned to:

- **You can see** network names and beacons, which devices are around (by MAC address; modern phones randomize theirs), probe requests, signal strengths, frame sizes and timing, and the management traffic of every network in range.
- **You cannot read** the contents of WPA2 or WPA3 traffic without that network's keys. To decrypt **your own** WPA2-Personal network in Wireshark you need the passphrase **and** a capture of each device's 4-way handshake as it connects. WPA3-Personal (SAE) gives every session its own key, so knowing the password is not enough to decrypt a recording.
- Even decrypted, most traffic today is HTTPS. You see which servers a device talks to, not what it says.
- Open, unencrypted networks are the exception: anyone in range can read them. That is exactly why capturing them without permission can be a crime.

### The law

Only capture on networks and devices you own, or that you have written permission to test. Intercepting other people's communications is illegal in many countries, including on open networks. A few examples, not legal advice:

- **US:** the federal Wiretap Act. In *Joffe v. Google* (9th Cir. 2013) the court held that payload data collected from unencrypted home WiFi networks was not exempt just because the networks were open.
- **Germany:** section 202b of the Criminal Code (StGB), intercepting data.
- **UK:** the Investigatory Powers Act 2016 (unlawful interception).

Check the rules where you live.

## Why the reel is misleading

This is not about the person who posted it. AI assistants say confident things, and it is easy to get excited. The claims just do not hold up the way they are presented:

1. **"Turned it into a packet sniffer."** There was nothing to turn. Packet capture and 802.11 monitor mode are built-in, documented features of WiFi drivers and operating systems. If your driver supports monitor mode, standard tools switch it on in one command. If it does not, no amount of AI chat changes the firmware.
2. **"A real 802.11 capture."** Free tools have done that for over twenty years. See the commands above.
3. **"Wide open, read/write, no admin."** On a default system that would be a driver security bug, and the right move is a private report to the vendor. Much more often, "no admin" capture works because somebody enabled it: Wireshark's non-superuser option on Linux, or Npcap without "admin only" on Windows. And being able to **open** a device is not the same as being able to **capture** with it. The self-check in this repo tells you which situation your machine is in.
4. **"Comment the keyword."** A real security finding names the driver and its version and comes with a vendor advisory or a CVE. "Comment a keyword and I will message you" is an engagement funnel: it boosts the post and opens a private channel to sell something. That is marketing, which is fine. It is just not a security disclosure.

## What it is not

- **Not a sniffer.** It never captures a packet.
- **Not an attack tool.** No scanning, no deauthentication, no injection, no cracking, no access to anyone else's network or device.
- **Not a scanner for other machines.** It only looks at the machine it runs on.
- **Not an "unlock".** It changes nothing. It reports.

## The honest limits

- It reports what the operating system says: permissions, capabilities, driver-advertised modes. A driver can still have bugs inside it that no permission check will reveal. Finding those takes the vendor or a proper audit.
- "Monitor mode supported" comes from the driver. Some drivers advertise it but deliver only some frames, or none on some bands. The only real test is trying it on your own network.
- Linux: without the `iw` package, monitor support shows as "unknown". Without `getcap` or `getfacl`, the capability and ACL details are skipped. It checks the usual locations of `dumpcap` and `tcpdump`, not every program on the disk.
- Windows: monitor-mode support is read from `netsh wlan show wirelesscapabilities`, which may show "unknown" on older Windows versions or some display languages. It reads per-device security overrides; a driver's built-in defaults are not visible without opening the device, which this script deliberately does not do. Tested on Windows 10 with Windows PowerShell 5.1.
- macOS is not covered. Apple ships its own monitor-mode capture in Wireless Diagnostics (Window, Sniffer).

## License

MIT. See [LICENSE](LICENSE).

---

Built and released free by **Warboy**. No tier, no wall, no "comment a keyword".
More free rebuilds of the things the hype reels sell: https://github.com/warboy176 · https://www.patreon.com/warboy176
