# Super Radar

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Version-3.0-brightgreen)

A real-time Bluetooth Low Energy scanner visualized as an animated tactical radar interface.

Super Radar continuously scans for nearby BLE devices and maps them onto a radar-style display. Devices are classified by brand, type, Bluetooth metadata, service UUIDs, MAC/OUI hints, and behavior patterns. Suspicious dual-use tools and development boards can trigger visible warnings.

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Visualization Modes](#visualization-modes)
- [Threat & Tool Detection](#threat--tool-detection)
- [Supported Device Classification](#supported-device-classification)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Controls](#controls)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Notes & Limitations](#notes--limitations)
- [Security & Privacy](#security--privacy)
- [Contributing](#contributing)
- [License](#license)

---

## How It Works

The system operates in several stages:

1. **Scanning**
   - Uses `bleak` to scan for nearby BLE advertisements.
   - Uses Windows `netsh` for Wi-Fi network listing.
   - Includes a simulated UHF/VHF/FM radio scanner panel.

2. **Signal Processing**
   - Uses RSSI signal strength to estimate relative radar distance.
   - Stronger signal -> closer to center.
   - Weaker signal -> farther from center.

3. **Classification**
   - Matches advertised device names.
   - Reads Bluetooth manufacturer/company IDs.
   - Uses Bluetooth Appearance values.
   - Uses GATT service UUID hints.
   - Uses MAC/OUI fallback hints.
   - Applies behavior and spoofing checks.

4. **Visualization**
   - Devices are rendered as radar points.
   - Warnings use yellow/red visual states.
   - The side table shows warning state, type, confidence, source, name, MAC, and RSSI.

---

## Features

- Animated radar sweep with trailing glow effect
- Real-time BLE scanning
- Brand and device type classification
- 270+ brand/tool keyword signatures
- 60 GATT service UUID mappings
- 51 Bluetooth Appearance category mappings
- 79 Bluetooth Appearance subtype mappings
- Dual-use security/RF/pentest tool warning system
- Development board detection
- Device list sorted by warning priority and RSSI
- Click any device dot to copy detailed information
- Boot sequence animation on startup
- Display reset flash when switching modes
- Minecraft-style cooldown overlay on the mode selector
- Resizable window and fullscreen support
- Distance rings: ~2m / ~5m / ~10m / ~20m
- Power button UI to exit the application

---

## Visualization Modes

Use the top-right dropdown to switch modes.

| Mode | Description |
| --- | --- |
| BLE Radar | Classic 360-degree BLE radar with sweep line |
| Wi-Fi Networks | Nearby Wi-Fi list with signal strength |
| Heatmap | BLE signal strength heat-style display |
| Timeline | Recent BLE sightings in chronological order |
| Radio Scanner | Simulated UHF/VHF/FM channel activity panel |

Mode switching is instant when cooldown is ready. After a switch, the selector shows a Minecraft-style cooldown shade. A short `DISPLAY BUS RESET` flash clears old graphics before the next mode is drawn.

---

## Threat & Tool Detection

The radar can highlight suspicious or security-relevant hardware. Alerts are indicators, not proof of illegal activity.

### Red ALERT

Triggered by high-confidence dual-use or security-tool indicators, including:

- Flipper Zero
- Hak5 tools: WiFi Pineapple, Rubber Ducky, Bash Bunny, OMG Cable
- HackRF, Ubertooth, Yard Stick One
- Proxmark, ChameleonUltra, ChameleonMini
- LimeSDR, RTL-SDR, SDRplay, bladeRF
- Pwnagotchi
- ESP32 Marauder, Deauther, BLE spam-style names
- High spoofing-risk score from multi-layer checks

### Yellow DEV

Triggered by development boards and prototyping platforms, including:

- ESP32 / ESP8266
- Arduino
- Raspberry Pi / Pico W
- M5Stack / M5Stick
- Meshtastic, LILYGO, Heltec
- Nordic nRF boards
- Adafruit, SparkFun, Seeed, DFRobot, STM32 boards

### Warning Table Columns

| Column | Meaning |
| --- | --- |
| WARN | Alert level, such as `ALERT` or `DEV` |
| TYPE | Brand and/or device type |
| C | Classification confidence |
| SRC | Classification source |
| DEVICE NAME | Advertised BLE device name |
| MAC | Device MAC address |
| RSSI | Signal strength |

Classification source values:

- `NAME`: advertised name match
- `MFG`: Bluetooth company/manufacturer ID
- `APP`: Bluetooth Appearance value
- `SVC`: GATT service UUID
- `OUI`: MAC vendor prefix
- `HEUR`: heuristic fallback

---

## Supported Device Classification

| Category | Examples |
| --- | --- |
| Apple | iPhone, iPad, Mac, Apple Watch, AirPods, AirTag |
| Android Brands | Samsung, Xiaomi, Huawei, OPPO, Vivo, OnePlus, Realme, Google Pixel |
| Computers | ASUS, Lenovo, Dell, HP, Acer, MSI, Framework, Gigabyte |
| Input Devices | Logitech, FOXXRAY, Razer, Corsair, SteelSeries, Keychron, Ducky |
| Audio | Sony, JBL, Bose, Jabra, Sennheiser, Soundcore, QCY, TOZO |
| Wearables | Garmin, Fitbit, Polar, Amazfit, Suunto, Oura |
| Smart Home | Philips Hue, Govee, Aqara, Tuya, Shelly, SwitchBot, Ring, Wyze |
| Trackers & Beacons | AirTag, Tile, Chipolo, RuuviTag, Estimote, Kontakt.io |
| Vehicles & OBD | Tesla, BMW, Toyota, Ford, OBDLink, ELM327, Veepeak |
| Medical | Dexcom, Abbott, Omron, iHealth, Phonak, Oticon |
| Development Boards | ESP32, Arduino, Raspberry Pi, M5Stack, Meshtastic, Nordic |
| Security Tools | Flipper Zero, HackRF, Proxmark, WiFi Pineapple, Pwnagotchi |

If the brand cannot be identified, the radar still tries to show the device type directly, such as `Mouse`, `Keyboard`, `Sensor`, `Beacon`, `Dev Board`, or `BLE Device`.

---

## Requirements

- Windows 10 / 11
- Python 3.8+
- Bluetooth adapter
- `bleak`
- `tkinter` and `winsound`, usually included with Python on Windows
- `sonar_ping.wav` in the same folder as `Super-Radar.py`

---

## Getting Started

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/AKA-HACKEREric/Super-Radar.git
   cd Super-Radar
   ```

2. Install dependencies:

   ```bash
   python -m pip install bleak
   ```

3. Confirm the sound asset exists:

   ```text
   sonar_ping.wav
   ```

### Run the Application

**Option A: Quick Start**

Double-click:

```text
Super-Radar.bat
```

**Option B: Command Line**

```bash
python Super-Radar.py
```

**Option C: PowerShell Helper**

Open your PowerShell profile:

```powershell
notepad $PROFILE
```

Add a helper function and replace the path with your actual location:

```powershell
function run {
    param(
        [string]$arg1,
        [string]$arg2
    )

    if ($arg1 -eq "Super" -and $arg2 -eq "Radar") {
        Write-Host "Starting Super Radar..."
        python "C:\YourPath\Super-Radar.py"
    }
}
```

Then run:

```powershell
run Super Radar
```

---

## Controls

| Input | Action |
| --- | --- |
| F11 | Toggle fullscreen |
| ESC | Exit fullscreen |
| Top-right dropdown | Switch visualization mode |
| Click dot | Copy device info |
| Power button | Exit application |

---

## Configuration

You can customize behavior by editing constants in `Super-Radar.py`.

| Constant | Purpose |
| --- | --- |
| `DEVICE_TTL_SECONDS` | How long a stale BLE device remains visible |
| `TRAIL_STEPS` | Sweep trail smoothness |
| `TRAIL_SPREAD` | Sweep trail width |
| `DEVICE_OVERFLOW` | Max table rows before compact overflow text |
| `RINGS` | Radar distance ring labels |
| `SPOOFING_INDICATORS` | Anti-spoofing weights and thresholds |
| `self.mode_cooldown_seconds` | Mode switch cooldown duration |

---

## Troubleshooting

### No BLE devices detected

- Ensure Bluetooth is enabled.
- Check that nearby devices are broadcasting BLE.
- Close other BLE scanner apps.
- Restart the radar.
- Try toggling Bluetooth off and on in Windows settings.

### BLE scan error

The app retries automatically. Common causes:

- Bluetooth adapter temporarily busy
- Another scanner using the adapter
- Windows Bluetooth stack hiccup
- Bluetooth permissions or service disabled

### Wi-Fi scan not working

- On Windows, the app uses:

  ```powershell
  netsh wlan show networks mode=bssid
  ```

- Make sure Wi-Fi is enabled.
- Some adapters do not expose detailed BSSID data.

### Sound issues

- Verify `sonar_ping.wav` exists beside the Python script.
- Check system volume.
- Sound only plays in BLE Radar mode.

### Pylance warnings

The app guards optional imports such as `bleak`. If Pylance reports stale diagnostics, reload the VS Code window after saving.

---

## Notes & Limitations

- Distance estimation is approximate. RSSI is affected by walls, interference, antennas, and device power.
- Some devices rotate MAC addresses and may appear as new devices.
- Some devices hide their name or advertise incomplete metadata.
- Alerts are detection hints, not legal conclusions.
- Radio Scanner mode is a visual/simulated scanner unless real radio hardware is integrated later.
- This is not suitable for precise location tracking. Use UWB or dedicated positioning hardware for that.

---

## Security & Privacy

- **Local Operation:** The app runs locally. No data is sent to external servers.
- **MAC Address Collection:** The app displays nearby BLE MAC addresses. Use only where scanning is allowed.
- **Data Retention:** Device information is held in memory for the current session.
- **Clipboard Access:** Clicking a device copies details to your clipboard.
- **Bluetooth Privacy:** MAC randomization means an address may not identify one physical device over time.

---

## Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a feature branch:

   ```bash
   git checkout -b feature/your-feature
   ```

3. Commit your changes:

   ```bash
   git commit -m "Add your feature"
   ```

4. Push the branch:

   ```bash
   git push origin feature/your-feature
   ```

5. Submit a pull request.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
