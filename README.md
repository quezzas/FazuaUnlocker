```
___________                           ____ ___      .__                 __
\_   _____/____  __________ _______  |    |   \____ |  |   ____   ____ |  | __ ___________
 |    __) \__  \ \___   /  |  \__  \ |    |   /    \|  |  /  _ \_/ ___\|  |/ // __ \_  __ \
 |   \     / __ \_/    /|  |  // __ \|    |  /   |  \  |_(  <_> )  \___|    <\  ___/|  | \/
 \__ /    (____  /_____ \____/(____  /______/|___|  /____/\____/ \___  >__|_ \\___  >__|
    \/         \/      \/          \/             \/                 \/     \/    \/
```

# FazuaUnlocker

Standalone CLI tool to read and change the `bikeMaxSpeed` parameter on a **Fazua RIDE 50** e-bike drive unit over USB HID.

**[Download Fazua Drivepack Firmware 2.04](https://drive.google.com/file/d/124NSCiMsA1Ju4hCl6iEvJOVDUez64W_u/view?usp=sharing)** — required firmware version for this tool.

## What it does

The Fazua RIDE 50 stores a `bikeMaxSpeed` value in its drive unit configuration. This tool reads and writes that value over the bike's USB HID interface (VID `0x10C4` / PID `0x1001`), using an XMODEM-framed protocol.

- **Read** the current config: shaft offset, wheel length, max speed, unit tag, log period
- **Write** a new max speed (5 - 75 km/h) with CRC validation and post-write verification
- **Dry-run** mode to inspect the write packet without sending it

## Requirements

- **Windows** (uses Win32 HID via `CreateFile` / `WriteFile` / `ReadFile`)
- **Python 3.8+**
- **USB cable** connected to the bike's diagnostic port

### Compatibility

| Model | Status |
|-------|--------|
| RIDE 50 EVATION | Tested and verified |
| RIDE 50 TRAIL | Should work (same drive unit, untested) |
| RIDE 50 STREET | Should work (same drive unit, untested) |

Requires **Drivepack firmware 2.04**. If your bike is on firmware 2.50, downgrade to 2.04 first, run the tool, then update back to 2.50 if desired.


## Usage

### Read current config (safe, no writes)

```bash
python -m venv venv
venv\Scripts\pip install -r requirements.txt
venv\Scripts\python fazua_unlock.py --read-only
```

### Change max speed

```bash
# Interactive mode (prompts before writing)
venv\Scripts\python fazua_unlock.py

# Direct mode with confirmation prompt
venv\Scripts\python fazua_unlock.py 35

# Dry-run (shows packet, does not send)
venv\Scripts\python fazua_unlock.py 35 --dry-run

# Skip confirmation prompt
venv\Scripts\python fazua_unlock.py 35 --force

# Verbose protocol trace
venv\Scripts\python fazua_unlock.py --read-only --verbose
```


## Safety features

- Refuses to run if another process is holding the Fazua HID handle
- Prompts for explicit `yes` before any write (unless `--force`)
- Validates CRC-16-XMODEM on every packet sent and received
- Re-reads config after write and verifies the new value matches
- Allowed speed range is clamped to 5 - 75 km/h

## Protocol overview

The Fazua RIDE 50 EVATION communicates over USB HID using 38-byte XMODEM-framed reports:

| Bytes | Field |
|-------|-------|
| 0 | HID report ID (always `0x00`) |
| 1 | Status/control byte |
| 2-3 | XMODEM sequence / complement |
| 4-5 | Command (`03 02` = read, `03 01` = write) |
| 6-35 | Payload (config values) |
| 36-37 | CRC-16-XMODEM over bytes 4-35, big-endian |

### Key config offsets (within the 38-byte packet)

| Offset | Size | Field |
|--------|------|-------|
| 6-7 | u16 LE | Shaft Offset |
| 14-15 | u16 LE | Wheel Length (mm) |
| 16 | u8 | Unit Tag (`0x05` = km/h) |
| 17-18 | u16 LE | bikeMaxSpeed (raw = km/h / 0.036) |
| 30-31 | u16 LE | Logs Period |
| 33-34 | 2 bytes | Write-auth key (write packets only) |

### Connection sequence

1. **Wake**: spam `0x21` control packets until the bike replies `0x22` (ready)
2. **Query**: send `03 02` read command, receive ACK + data response
3. **Write**: send `03 01` write block 1 + block 2, receive ACKs
4. **Verify**: re-read config to confirm the write took effect

## Disclaimer

**This software is provided for educational and research purposes only.**

- This software is provided "as is", without warranty of any kind, express or implied.
- The author(s) accept no liability for any damage to your e-bike, drive unit, battery, controller, or any other hardware resulting from the use of this software.
- The author(s) accept no responsibility for any personal injuries or accidents caused by use of this software.
- Using this software may void your manufacturer's warranty.
- A modified e-bike may not be legal for use on public roads, cycle paths, or any public space. Use only on private property with the owner's permission.
- It is your responsibility to consult and comply with the laws and regulations of your jurisdiction before using this software.
- This project does not encourage or endorse any illegal activity.

### EU regulatory notice

Under EN 15194 / Regulation (EU) 168/2013, a pedelec that provides motor assistance above 25 km/h is legally reclassified as a motor vehicle (L1e-A/B category). Riding a modified e-bike on public roads in most EU member states:

- Is an administrative or criminal offence
- Voids insurance coverage
- Voids manufacturer type approval and warranty
- Shifts product liability to whoever made the modification

**By using this software, you acknowledge that you have read and understood this disclaimer and accept full responsibility for any consequences arising from its use.**

## License

MIT
