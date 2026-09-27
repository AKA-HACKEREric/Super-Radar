# Super Radar - Quick Reference

## Run

```powershell
cd "C:\Users\b8654\OneDrive\桌面\CODE\BLE-Sonar-Radar"
python .\Super-Radar.py
```

Or double-click:

```text
Super-Radar.bat
```

## Requirements

- Python 3.8+
- `bleak`
- Tkinter, included with most Python installs
- Bluetooth adapter enabled

Install dependency:

```powershell
python -m pip install bleak
```

## Controls

| Control | Action |
| --- | --- |
| F11 | Toggle fullscreen |
| ESC | Exit fullscreen |
| Click device dot | Copy device details to clipboard |
| Top-right mode dropdown | Switch view mode |
| Power icon | Close app |

## Mode Switching

- Mode changes are instant.
- After switching, the mode selector shows a Minecraft-style cooldown shade.
- During cooldown, choosing another mode shows `MODE COOLDOWN: X.Xs remaining`.
- A short `DISPLAY BUS RESET` flash clears old graphics before the next mode paints.

## Modes

| Mode | Purpose |
| --- | --- |
| BLE Radar | 360-degree BLE radar sweep |
| Wi-Fi Networks | Nearby Wi-Fi listing |
| Heatmap | BLE signal strength visualization |
| Timeline | Recent BLE sightings |
| Radio Scanner | Simulated UHF/VHF/FM activity panel |

## Alert Colors

| Color | Meaning |
| --- | --- |
| Green | Normal device |
| Yellow | Development board or lower-risk hardware |
| Red | Dual-use security/RF/pentest tool or spoofing risk |

## Main Alert Triggers

Red `ALERT` can trigger from:

- Flipper Zero
- Hak5 tools such as WiFi Pineapple, Rubber Ducky, Bash Bunny, OMG Cable
- HackRF, Ubertooth, Yard Stick One
- Proxmark, ChameleonUltra, ChameleonMini
- LimeSDR, RTL-SDR, SDRplay, bladeRF
- Pwnagotchi, ESP32 Marauder, Deauther, BLE spam patterns
- Multi-layer spoofing score at alert threshold

Yellow `DEV` can trigger from:

- ESP32 / ESP8266
- Arduino
- Raspberry Pi / Pico W
- M5Stack / M5Stick
- Meshtastic, LILYGO, Heltec
- Nordic nRF boards
- Adafruit, SparkFun, Seeed, DFRobot, STM32 boards

## Classification Sources

The device table includes:

| Column | Meaning |
| --- | --- |
| WARN | Alert level, if any |
| TYPE | Brand and/or device type |
| C | Classification confidence |
| SRC | Classification source |
| DEVICE NAME | Advertised BLE name |
| MAC | Device MAC address |
| RSSI | Signal strength |

`SRC` values:

- `NAME`: matched advertised name
- `MFG`: matched Bluetooth manufacturer/company ID
- `APP`: matched Bluetooth Appearance value
- `SVC`: matched GATT service UUID
- `OUI`: matched MAC vendor prefix
- `HEUR`: fallback heuristic

## Current Fingerprint Coverage

- 270 brand/tool keyword signatures
- 60 GATT service UUID mappings
- 51 Bluetooth Appearance category mappings
- 79 Bluetooth Appearance subtype mappings
- Logitech and development-board OUI fallback lists

## Notes

- Alerts are indicators, not proof of illegal activity.
- BLE devices can hide names, rotate MACs, or advertise incomplete data.
- Classification improves when a device exposes name, service UUIDs, company IDs, or Appearance values.
