import asyncio
import csv
import json
import math
import os
import random
import string
import subprocess
import threading
import time
import tkinter as tk
import urllib.request
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, filedialog

try:
    from bleak import BleakScanner, BleakClient
except ImportError:
    BleakScanner = None
    BleakClient = None

try:
    import winsound
except ImportError:
    winsound = None

# Cross-platform sound fallback
_sound_backend = None
if winsound is None:
    try:
        import pygame.mixer as _pygame_mixer
        _sound_backend = "pygame"
    except ImportError:
        _pygame_mixer = None
        try:
            from playsound import playsound as _playsound_func
            _sound_backend = "playsound"
        except ImportError:
            _playsound_func = None


APP_DIR = Path(__file__).resolve().parent
SOUND_FILE = APP_DIR / "sonar_ping.wav"
ALARM_SOUND_FILE = APP_DIR / "alarm_ping.wav"  # Alarm sound for suspicious devices

# GPS location cache
_gps_cache = {"lat": None, "lon": None, "city": None, "loading": False}

def get_gps_location():
    """Get GPS coordinates via Windows Geolocation API (real GPS only)."""
    if _gps_cache["lat"] is not None:
        return _gps_cache["lat"], _gps_cache["lon"], _gps_cache["city"]
    if _gps_cache["loading"]:
        return None, None, None
    _gps_cache["loading"] = True
    try:
        # Use Windows Runtime Geolocation API
        import ctypes
        from ctypes import wintypes

        # Try to use Windows.Location API via PowerShell
        ps_cmd = """
        Add-Type -AssemblyName System.Device
        $watcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $watcher.Start()
        Start-Sleep -Milliseconds 2000
        $coord = $watcher.Position.Location
        if ($coord.IsUnknown -eq $false) {
            Write-Output "$($coord.Latitude),$($coord.Longitude)"
        }
        $watcher.Stop()
        """
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        if result.returncode == 0 and "," in result.stdout:
            parts = result.stdout.strip().split(",")
            lat, lon = float(parts[0]), float(parts[1])
            if lat != 0.0 and lon != 0.0:
                _gps_cache["lat"] = lat
                _gps_cache["lon"] = lon
                _gps_cache["city"] = "GPS"
                return lat, lon, "GPS"
    except Exception:
        pass
    return None, None, None

DEVICE_TTL_SECONDS = 12
TRAIL_STEPS  = 18
TRAIL_SPREAD = 45

COL_BG       = "#050805"
COL_GRID     = "#115f1b"
COL_GRID_DIM = "#0e4615"
COL_SWEEP    = "#7cff8b"
COL_HIT      = "#7cff8b"
COL_FADE     = "#2fac44"
COL_TEXT     = "#e9ffe9"
COL_LABEL    = "#7cff8b"
COL_DIM_RING = "#1a7a26"
COL_WARN     = "#ffcf4a"
COL_ALERT    = "#ff4a4a"

RINGS = [
    (0.25, "~2m"),
    (0.50, "~5m"),
    (0.75, "~10m"),
    (1.00, "~20m"),
]

DEVICE_OVERFLOW = 5  # Hide labels when exceeding this number of devices

# ---- Runtime state (initialized in main, safe for import) ----
devices         = {}
devices_lock    = threading.Lock()
scanner_error   = None
scan_start_time = 0.0
peak_devices    = 0

scan_log        = []
scan_log_lock   = threading.Lock()

spoofing_suspect_db = {}
spoofing_lock = threading.Lock()

wifi_networks   = {}
wifi_lock       = threading.Lock()

radio_channels  = {}
radio_lock      = threading.Lock()

current_mode    = "BLE"
mode_lock       = threading.Lock()

# Device blacklist (MAC addresses to ignore)
device_blacklist = set()
blacklist_lock   = threading.Lock()

# RSSI history for signal strength graphs
rssi_history     = {}
rssi_history_lock = threading.Lock()

# Spoofing indicator weights (used for confidence scoring)
SPOOFING_INDICATORS = {
    "rapid_mac_change": {"weight": 35, "threshold": 3},      # Multiple MACs in short time
    "signal_instability": {"weight": 25, "threshold": 15},   # Abnormal RSSI fluctuations
    "name_mismatch": {"weight": 20, "threshold": 5},         # Name/type inconsistencies
    "suspicious_oui": {"weight": 15, "threshold": 1},        # Non-standard MAC OUI
    "pattern_anomaly": {"weight": 15, "threshold": 2},       # Unusual broadcast patterns
}

LOGITECH_OUIS = {
    "00:0D:44", "00:1F:20", "08:81:B2", "10:94:97", "34:88:5D",
    "38:F0:C8", "40:58:99", "44:71:B3", "44:73:D6", "88:C6:26",
    "94:02:30", "C0:28:8D", "C8:DB:26", "EC:81:93", "F4:73:35",
}

DEV_BOARD_OUI_TYPES = {
    "18:FE:34": "Espressif|Dev Board",
    "24:0A:C4": "Espressif|Dev Board",
    "30:AE:A4": "Espressif|Dev Board",
    "3C:71:BF": "Espressif|Dev Board",
    "50:02:91": "Espressif|Dev Board",
    "54:5A:A6": "Espressif|Dev Board",
    "60:01:94": "Espressif|Dev Board",
    "80:7D:3A": "Espressif|Dev Board",
    "84:0D:8E": "Espressif|Dev Board",
    "84:F3:EB": "Espressif|Dev Board",
    "A0:20:A6": "Espressif|Dev Board",
    "A4:7B:9D": "Espressif|Dev Board",
    "A4:CF:12": "Espressif|Dev Board",
    "B4:E6:2D": "Espressif|Dev Board",
    "BC:DD:C2": "Espressif|Dev Board",
    "C4:4F:33": "Espressif|Dev Board",
    "C8:2B:96": "Espressif|Dev Board",
    "DC:4F:22": "Espressif|Dev Board",
    "EC:FA:BC": "Espressif|Dev Board",
    "B8:27:EB": "Raspberry Pi|Dev Board",
    "DC:A6:32": "Raspberry Pi|Dev Board",
    "D8:3A:DD": "Raspberry Pi|Dev Board",
    "E4:5F:01": "Raspberry Pi|Dev Board",
}

HID_APPEARANCE_TYPES = {
    1: "Generic|Keyboard",
    2: "Generic|Mouse",
    3: "Generic|Joystick",
    4: "Generic|Gamepad",
    5: "Generic|Tablet",
    6: "Generic|Card Reader",
    7: "Generic|Pen",
    8: "Generic|Barcode Scanner",
}

APPEARANCE_CATEGORY_TYPES = {
    0x01: "Generic|Phone",
    0x02: "Generic|Computer",
    0x03: "Generic|Watch",
    0x04: "Generic|Clock",
    0x05: "Generic|Display",
    0x06: "Generic|Remote",
    0x07: "Generic|Eyewear",
    0x08: "Generic|Tracker",
    0x09: "Generic|Keyring",
    0x0A: "Generic|Media Player",
    0x0B: "Generic|Barcode Scanner",
    0x0C: "Generic|Thermometer",
    0x0D: "Generic|Heart Sensor",
    0x0E: "Generic|Blood Pressure",
    0x0F: "Generic|Mouse/Keyboard",
    0x10: "Generic|Glucose Meter",
    0x11: "Generic|Running Sensor",
    0x12: "Generic|Cycling Sensor",
    0x13: "Generic|Control Device",
    0x14: "Generic|Network Device",
    0x15: "Generic|Sensor",
    0x16: "Generic|Light",
    0x17: "Generic|Fan",
    0x18: "Generic|HVAC",
    0x19: "Generic|Air Conditioner",
    0x1A: "Generic|Humidifier",
    0x1B: "Generic|Heater",
    0x1C: "Generic|Access Control",
    0x1D: "Generic|Motorized Device",
    0x1E: "Generic|Power Device",
    0x1F: "Generic|Light Source",
    0x20: "Generic|Window Covering",
    0x21: "Generic|Speaker",
    0x22: "Generic|Microphone",
    0x23: "Generic|Vehicle",
    0x24: "Generic|Appliance",
    0x25: "Generic|Wearable Audio",
    0x26: "Generic|Aircraft",
    0x27: "Generic|AV Equipment",
    0x28: "Generic|Display Equipment",
    0x29: "Generic|Hearing Aid",
    0x2A: "Generic|Gaming",
    0x2B: "Generic|Signage",
    0x31: "Generic|Pulse Oximeter",
    0x32: "Generic|Scale",
    0x33: "Generic|Mobility Device",
    0x34: "Generic|Glucose Monitor",
    0x35: "Generic|Insulin Pump",
    0x36: "Generic|Medication Delivery",
    0x37: "Generic|Spirometer",
    0x51: "Generic|Outdoor Sports",
}

APPEARANCE_SUBTYPE_TYPES = {
    0x0301: "Generic|Sports Watch",
    0x0601: "Generic|Remote",
    0x0C01: "Generic|Ear Thermometer",
    0x0D01: "Generic|Heart Sensor",
    0x0E01: "Generic|Blood Pressure",
    0x1101: "Generic|Running Sensor",
    0x1201: "Generic|Cycling Computer",
    0x1202: "Generic|Cycling Speed Sensor",
    0x1203: "Generic|Cycling Cadence Sensor",
    0x1204: "Generic|Cycling Power Sensor",
    0x1301: "Generic|Switch",
    0x1302: "Generic|Multi Switch",
    0x1303: "Generic|Button",
    0x1304: "Generic|Slider",
    0x1305: "Generic|Rotary Switch",
    0x1306: "Generic|Touch Panel",
    0x1307: "Generic|Single Switch",
    0x1308: "Generic|Double Switch",
    0x1309: "Generic|Triple Switch",
    0x1401: "Generic|Access Point",
    0x1501: "Generic|Motion Sensor",
    0x1502: "Generic|Air Quality Sensor",
    0x1503: "Generic|Temperature Sensor",
    0x1504: "Generic|Humidity Sensor",
    0x1505: "Generic|Leak Sensor",
    0x1506: "Generic|Smoke Sensor",
    0x1507: "Generic|Occupancy Sensor",
    0x1508: "Generic|Contact Sensor",
    0x1509: "Generic|CO Sensor",
    0x150A: "Generic|CO2 Sensor",
    0x150B: "Generic|Light Sensor",
    0x150D: "Generic|Energy Sensor",
    0x150F: "Generic|Rain Sensor",
    0x1510: "Generic|Fire Sensor",
    0x1512: "Generic|Proximity Sensor",
    0x1518: "Generic|Energy Meter",
    0x1519: "Generic|Flame Detector",
    0x151A: "Generic|Tire Pressure Sensor",
    0x1617: "Generic|Bulb",
    0x1801: "Generic|Thermostat",
    0x1802: "Generic|Humidifier",
    0x1C01: "Generic|Door Lock",
    0x1C02: "Generic|Garage Door",
    0x1D01: "Generic|Motorized Gate",
    0x1D02: "Generic|Awning",
    0x1D03: "Generic|Blinds",
    0x1D04: "Generic|Curtain",
    0x2301: "Generic|Car",
    0x2302: "Generic|Large Vehicle",
    0x2303: "Generic|Drone",
    0x2401: "Generic|Refrigerator",
    0x2402: "Generic|Freezer",
    0x2403: "Generic|Oven",
    0x2404: "Generic|Microwave",
    0x2405: "Generic|Toaster",
    0x2406: "Generic|Washing Machine",
    0x2407: "Generic|Dryer",
    0x2408: "Generic|Coffee Maker",
    0x2409: "Generic|Cooker",
    0x240A: "Generic|Dishwasher",
    0x240B: "Generic|Kettle",
    0x240C: "Generic|Hob",
    0x240D: "Generic|Robot Vacuum",
    0x240E: "Generic|Air Purifier",
    0x2501: "Generic|Earbuds",
    0x2502: "Generic|Headset",
    0x2503: "Generic|Headphones",
    0x2701: "Generic|Amplifier",
    0x2702: "Generic|Receiver",
    0x2703: "Generic|Radio",
    0x2704: "Generic|Tuner",
    0x2705: "Generic|Turntable",
    0x2706: "Generic|CD Player",
    0x2707: "Generic|DVD Player",
    0x2708: "Generic|Blu-ray Player",
    0x2709: "Generic|Optical Disc Player",
    0x270A: "Generic|Set-top Box",
    0x2A01: "Generic|Game Console",
    0x2A02: "Generic|Controller",
}

SERVICE_UUID_TYPES = {
    "1800": "Generic|BLE Device",
    "1801": "Generic|BLE Device",
    "180a": "Generic|BLE Device",
    "180d": "Generic|Heart Sensor",
    "180e": "Generic|Phone",
    "180f": "Generic|Battery Device",
    "1810": "Generic|Blood Pressure",
    "1811": "Generic|Alert Device",
    "1812": "Generic|Mouse/Keyboard",
    "1813": "Generic|Scan Parameters",
    "1814": "Generic|Running Sensor",
    "1815": "Generic|Automation IO",
    "1816": "Generic|Cycling Sensor",
    "1818": "Generic|Cycling Sensor",
    "1819": "Generic|Location Sensor",
    "181a": "Generic|Sensor",
    "181b": "Generic|Body Sensor",
    "181c": "Generic|User Data Device",
    "181d": "Generic|Weight Scale",
    "181e": "Generic|Bond Management",
    "181f": "Generic|Continuous Glucose Monitor",
    "1820": "Generic|Internet Gateway",
    "1821": "Generic|Indoor Positioning",
    "1822": "Generic|Pulse Oximeter",
    "1823": "Generic|HTTP Proxy",
    "1824": "Generic|Transport Discovery",
    "1825": "Generic|Object Transfer",
    "1826": "Generic|Fitness Machine",
    "1827": "Generic|Mesh Provisioning",
    "1828": "Generic|Mesh Proxy",
    "1829": "Generic|Reconnection Config",
    "183a": "Generic|Insulin Pump",
    "183b": "Generic|Binary Sensor",
    "183e": "Generic|Physical Activity Monitor",
    "1843": "Generic|Audio",
    "1844": "Generic|Audio",
    "1845": "Generic|Audio",
    "1846": "Generic|Audio",
    "1847": "Generic|Audio",
    "1848": "Generic|Audio",
    "1849": "Generic|Audio",
    "184a": "Generic|Audio",
    "184b": "Generic|Broadcast Audio",
    "184c": "Generic|Audio",
    "184d": "Generic|Audio",
    "184e": "Generic|Audio",
    "184f": "Generic|Audio",
    "1850": "Generic|Audio",
    "1851": "Generic|Audio",
    "1852": "Generic|Audio",
    "1853": "Generic|Audio",
    "1854": "Generic|Hearing Aid",
    "1855": "Generic|Telephony",
    "1856": "Generic|Audio",
    "fe59": "Generic|Firmware Update",
    "fe95": "Xiaomi|Home",
    "fe9f": "Google|Fast Pair",
    "feaa": "Google|Beacon",
    "fdf5": "Apple|Find My",
    "fd6f": "Exposure Notification",
}

BRAND_KEYWORDS = [
    ("FOXXRAY", ["foxxray", "fox ray", "fxr"]),
    ("Flipper Zero", ["flipper zero", "flipper"]),
    ("Hak5", ["hak5", "wifi pineapple", "rubber ducky", "bash bunny", "packet squirrel", "lan turtle", "omg cable"]),
    ("Great Scott Gadgets", ["hackrf", "ubertooth", "yard stick one", "yardstick one"]),
    ("Proxmark", ["proxmark", "proxmark3"]),
    ("Lab401", ["chameleonultra", "chameleon ultra", "chameleonmini", "chameleon mini"]),
    ("Lime Microsystems", ["limesdr", "lime sdr"]),
    ("RTL-SDR", ["rtl sdr", "rtl-sdr"]),
    ("SDRplay", ["sdrplay"]),
    ("Nuand", ["bladerf", "blade rf"]),
    ("Pwnagotchi", ["pwnagotchi"]),
    ("Meshtastic", ["meshtastic"]),
    ("LILYGO", ["lilygo", "t beam", "t deck", "t echo", "t display", "t watch"]),
    ("Heltec", ["heltec", "wireless stick", "wifi lora"]),
    ("Pimoroni", ["pimoroni", "badger", "tiny 2040", "plasma 2040"]),
    ("Seeed", ["seeed", "xiao", "wio terminal", "reterminal"]),
    ("Adafruit", ["adafruit", "feather", "circuit playground", "clue", "qt py", "itsybitsy"]),
    ("SparkFun", ["sparkfun", "redboard", "thing plus"]),
    ("DFRobot", ["dfrobot", "firebeetle"]),
    ("Makeblock", ["makeblock", "mBot", "mcore"]),
    ("Sipeed", ["sipeed", "maix"]),
    ("Ruuvi", ["ruuvi", "ruuvitag"]),
    ("BlueCharm", ["bluecharm", "bc037", "bc011"]),
    ("Minew", ["minew"]),
    ("Kontakt.io", ["kontakt", "kontakt.io"]),
    ("Estimote", ["estimote"]),
    ("BlueCats", ["bluecats"]),
    ("Radius Networks", ["radbeacon", "radius networks"]),
    ("KBeacon", ["kbeacon", "k sensor"]),
    ("Shelly BLU", ["shelly blu"]),
    ("Logitech", ["logitech", "logicool", "logi", "mx master", "mx anywhere", "mx keys", "pebble mouse", "pop keys", "wave keys", "lift vertical"]),
    ("Razer", ["razer", "deathadder", "basilisk", "viper", "orochi", "blackwidow", "huntsman", "kraken"]),
    ("Corsair", ["corsair", "katar", "harpoon", "dark core", "k70", "k95", "virtuoso"]),
    ("SteelSeries", ["steelseries", "rival", "aerox", "apex pro", "arctis"]),
    ("HyperX", ["hyperx", "cloud alpha", "cloud ii", "pulsefire", "alloy origins"]),
    ("ROCCAT", ["roccat", "kone", "burst pro", "vulcan"]),
    ("Glorious", ["glorious", "model o", "model d", "gmmk"]),
    ("Cooler Master", ["cooler master", "mastermouse", "ck550", "sk622"]),
    ("Redragon", ["redragon", "k552", "k530", "m711"]),
    ("Rapoo", ["rapoo"]),
    ("Elecom", ["elecom"]),
    ("Kensington", ["kensington"]),
    ("Microsoft", ["microsoft", "surface", "xbox", "windows"]),
    ("Keychron", ["keychron", "k pro", "q pro", "v max"]),
    ("Akko", ["akko"]),
    ("AULA", ["aula"]),
    ("Ducky", ["ducky"]),
    ("Varmilo", ["varmilo"]),
    ("Leopold", ["leopold"]),
    ("Filco", ["filco"]),
    ("NuPhy", ["nuphy", "air75", "halo75"]),
    ("Royal Kludge", ["royal kludge", "rk61", "rk68", "rk84", "rk96"]),
    ("Apple", ["apple", "iphone", "ipad", "macbook", "imac", "mac mini", "mac studio", "apple watch", "airpods", "airtag", "beats"]),
    ("Samsung", ["samsung", "galaxy", "gear", "buds live", "buds pro", "buds2", "smarttag"]),
    ("Sony", ["sony", "xperia", "wh 1000", "wf 1000", "linkbuds", "walkman", "dualshock", "dualsense"]),
    ("Google", ["google", "pixel", "nest", "chromecast"]),
    ("Amazon", ["amazon", "echo", "alexa", "kindle", "fire tv", "blink"]),
    ("Xiaomi", ["xiaomi", "redmi", "poco", "black shark", "mi band", "mi smart", "mi home", "yeelight", "aqara", "roborock"]),
    ("Huawei", ["huawei", "honor", "freebuds", "matebook"]),
    ("OPPO", ["oppo", "reno", "find x", "enco"]),
    ("OnePlus", ["oneplus", "buds z", "buds pro"]),
    ("Vivo", ["vivo", "iqoo"]),
    ("Realme", ["realme", "narzo"]),
    ("Nothing", ["nothing", "nothing ear", "cmf"]),
    ("Motorola", ["motorola", "moto g", "moto edge"]),
    ("Nokia", ["nokia"]),
    ("HTC", ["htc"]),
    ("LG", ["lg", "tone free"]),
    ("ZTE", ["zte", "nubia", "redmagic"]),
    ("TCL", ["tcl", "alcatel"]),
    ("Sharp", ["sharp"]),
    ("Meizu", ["meizu"]),
    ("TECNO", ["tecno"]),
    ("Infinix", ["infinix"]),
    ("Fairphone", ["fairphone"]),
    ("ASUS", ["asus", "asustek", "rog", "tuf", "zenbook", "vivobook", "proart", "expertbook"]),
    ("Lenovo", ["lenovo", "thinkpad", "thinkbook", "ideapad", "yoga", "legion", "loq"]),
    ("Dell", ["dell", "xps", "alienware", "inspiron", "latitude", "precision", "vostro"]),
    ("HP", ["hp", "spectre", "envy", "omen", "pavilion", "elitebook", "probook", "zbook", "victus"]),
    ("Acer", ["acer", "predator", "nitro", "swift", "aspire", "spin", "chromebook"]),
    ("MSI", ["msi", "raider", "stealth", "katana", "pulse", "prestige", "claw"]),
    ("Framework", ["framework laptop", "framework"]),
    ("Gigabyte", ["gigabyte", "aorus", "aero laptop"]),
    ("Intel", ["intel nuc", "nuc"]),
    ("JBL", ["jbl", "partybox", "flip", "charge", "go 3"]),
    ("Bose", ["bose", "quietcomfort", "soundlink", "soundbar"]),
    ("Jabra", ["jabra", "elite 75", "elite 85"]),
    ("Sennheiser", ["sennheiser", "momentum"]),
    ("Anker", ["anker", "soundcore", "eufy"]),
    ("Skullcandy", ["skullcandy"]),
    ("Edifier", ["edifier"]),
    ("Marshall", ["marshall"]),
    ("Shure", ["shure"]),
    ("Audio-Technica", ["audio technica", "ath m", "ath c"]),
    ("AKG", ["akg"]),
    ("Bang & Olufsen", ["bang olufsen", "b&o", "beoplay"]),
    ("Bowers & Wilkins", ["bowers wilkins", "b&w", "px7", "pi7"]),
    ("Sonos", ["sonos"]),
    ("Harman Kardon", ["harman kardon"]),
    ("Yamaha", ["yamaha"]),
    ("Denon", ["denon"]),
    ("Pioneer", ["pioneer"]),
    ("Creative", ["creative", "sound blaster"]),
    ("Philips", ["philips", "hue"]),
    ("Tribit", ["tribit"]),
    ("EarFun", ["earfun"]),
    ("TOZO", ["tozo"]),
    ("QCY", ["qcy"]),
    ("Haylou", ["haylou"]),
    ("SoundPEATS", ["soundpeats"]),
    ("1MORE", ["1more"]),
    ("Baseus", ["baseus"]),
    ("UGREEN", ["ugreen"]),
    ("Rode", ["rode", "wireless go"]),
    ("Garmin", ["garmin"]),
    ("Fitbit", ["fitbit"]),
    ("Polar", ["polar"]),
    ("Amazfit", ["amazfit", "zepp"]),
    ("Suunto", ["suunto"]),
    ("Coros", ["coros"]),
    ("Withings", ["withings"]),
    ("WHOOP", ["whoop"]),
    ("Oura", ["oura"]),
    ("GoPro", ["gopro"]),
    ("Canon", ["canon"]),
    ("Nikon", ["nikon"]),
    ("DJI", ["dji", "osmo", "mavic", "ronin"]),
    ("Insta360", ["insta360"]),
    ("Fujifilm", ["fujifilm", "fuji"]),
    ("Panasonic", ["panasonic", "lumix"]),
    ("OM System", ["om system", "olympus"]),
    ("Tile", ["tile"]),
    ("Chipolo", ["chipolo"]),
    ("Pebblebee", ["pebblebee"]),
    ("Nintendo", ["nintendo", "joy con", "switch pro"]),
    ("PlayStation", ["playstation", "dualsense", "dualshock"]),
    ("Meta", ["meta quest", "oculus", "quest 2", "quest 3"]),
    ("HTC Vive", ["vive tracker", "vive controller", "htc vive"]),
    ("Valve", ["valve index", "index controller"]),
    ("Tesla", ["tesla"]),
    ("BMW", ["bmw"]),
    ("Toyota", ["toyota", "lexus"]),
    ("Ford", ["ford"]),
    ("Honda", ["honda", "acura"]),
    ("Nissan", ["nissan", "infiniti"]),
    ("Hyundai", ["hyundai", "genesis"]),
    ("Kia", ["kia"]),
    ("Mazda", ["mazda"]),
    ("Subaru", ["subaru"]),
    ("Mercedes-Benz", ["mercedes", "benz"]),
    ("Audi", ["audi"]),
    ("Volkswagen", ["volkswagen", "vw"]),
    ("Porsche", ["porsche"]),
    ("Volvo", ["volvo"]),
    ("TP-Link", ["tp link", "tplink", "kasa", "tapo"]),
    ("Govee", ["govee"]),
    ("LIFX", ["lifx"]),
    ("Nanoleaf", ["nanoleaf"]),
    ("Tuya", ["tuya", "smart life"]),
    ("Shelly", ["shelly"]),
    ("Sonoff", ["sonoff", "ewelink"]),
    ("SwitchBot", ["switchbot"]),
    ("Ring", ["ring doorbell", "ring cam", "ring chime"]),
    ("Wyze", ["wyze"]),
    ("Arlo", ["arlo"]),
    ("Ecobee", ["ecobee"]),
    ("Honeywell", ["honeywell"]),
    ("Yale", ["yale"]),
    ("August", ["august lock"]),
    ("Nuki", ["nuki"]),
    ("Schlage", ["schlage"]),
    ("Dyson", ["dyson"]),
    ("iRobot", ["irobot", "roomba"]),
    ("Ecovacs", ["ecovacs", "deebot"]),
    ("Dreame", ["dreame"]),
    ("Narwal", ["narwal"]),
    ("Brother", ["brother"]),
    ("Epson", ["epson"]),
    ("Zebra", ["zebra"]),
    ("Dymo", ["dymo", "labelwriter"]),
    ("Arduino", ["arduino"]),
    ("Espressif", ["esp32", "esp8266", "espressif"]),
    ("M5Stack", ["m5stack", "m5stick", "atom lite", "atom matrix"]),
    ("WEMOS", ["wemos", "lolin"]),
    ("Nordic", ["nrf52", "nrf528", "thingy"]),
    ("Raspberry Pi", ["raspberry", "rpi", "pico w"]),
    ("Seeed", ["seeed", "xiao"]),
    ("BBC", ["micro bit", "micro:bit"]),
    ("Adafruit", ["adafruit", "feather", "circuit playground"]),
    ("SparkFun", ["sparkfun", "redboard"]),
    ("LilyGO", ["lilygo", "t display", "t watch"]),
    ("Heltec", ["heltec"]),
    ("DFRobot", ["dfrobot"]),
    ("Particle", ["particle photon", "particle argon", "particle boron"]),
    ("Pycom", ["pycom", "wipy", "lopy"]),
    ("BeagleBoard", ["beaglebone", "beagleboard"]),
    ("PINE64", ["pine64", "pinecil", "pinetime"]),
    ("STMicroelectronics", ["stm32", "st nucleo", "st discovery"]),
    ("Texas Instruments", ["ti sensortag", "launchpad"]),
    ("Silicon Labs", ["silicon labs", "efr32", "xg24"]),
    ("Omron", ["omron"]),
    ("Dexcom", ["dexcom"]),
    ("Abbott", ["abbott", "freestyle libre"]),
    ("iHealth", ["ihealth"]),
    ("Roku", ["roku"]),
    ("NVIDIA", ["nvidia shield", "shield tv"]),
    ("Hisense", ["hisense"]),
    ("Vizio", ["vizio"]),
    ("Eve", ["eve room", "eve energy", "eve door", "eve weather", "eve aqua"]),
    ("Meross", ["meross"]),
    ("Leviton", ["leviton"]),
    ("Lutron", ["lutron", "caseta"]),
    ("GE Cync", ["cync", "ge cync"]),
    ("Wiz", ["wiz"]),
    ("IKEA", ["ikea", "tradfri", "trådfri"]),
    ("Aranet", ["aranet", "aranet4"]),
    ("SensorPush", ["sensorpush"]),
    ("ThermoPro", ["thermopro"]),
    ("Inkbird", ["inkbird"]),
    ("Qingping", ["qingping", "cleargrass"]),
    ("BlueMaestro", ["bluemaestro"]),
    ("Elitech", ["elitech"]),
    ("Ecowitt", ["ecowitt"]),
    ("Wahoo", ["wahoo", "kickr", "elemnt", "tickr"]),
    ("Bryton", ["bryton"]),
    ("Magene", ["magene"]),
    ("CooSpo", ["coospo"]),
    ("Favero", ["favero", "assioma"]),
    ("Tacx", ["tacx"]),
    ("Zwift", ["zwift"]),
    ("Peloton", ["peloton"]),
    ("Concept2", ["concept2", "pm5"]),
    ("Veepeak", ["veepeak"]),
    ("OBDLink", ["obdlink"]),
    ("ELM327", ["elm327", "obd ii", "obd2"]),
    ("Carly", ["carly"]),
    ("Socket Mobile", ["socket mobile", "socket scanner"]),
    ("Datalogic", ["datalogic"]),
    ("Square", ["square reader", "square terminal"]),
    ("SumUp", ["sumup"]),
    ("Clover", ["clover"]),
    ("Verifone", ["verifone"]),
    ("Ingenico", ["ingenico"]),
    ("Skydio", ["skydio"]),
    ("Autel", ["autel evo", "autel robotics"]),
    ("Parrot", ["parrot anafi", "parrot drone"]),
    ("Orbit", ["orbit tracker", "orbitkey"]),
    ("Nut", ["nut tracker", "nut find"]),
    ("TrackR", ["trackr"]),
    ("Cube Tracker", ["cube tracker"]),
    ("Kwikset", ["kwikset"]),
    ("Sesame", ["sesame lock"]),
    ("Lockly", ["lockly"]),
    ("Ultraloq", ["ultraloq"]),
    ("Level Lock", ["level lock"]),
    ("Poly", ["poly", "plantronics", "voyager", "backbeat"]),
    ("Turtle Beach", ["turtle beach"]),
    ("ASTRO", ["astro a", "astro gaming"]),
    ("Phonak", ["phonak"]),
    ("Oticon", ["oticon"]),
    ("ReSound", ["resound"]),
    ("Signia", ["signia"]),
    ("Widex", ["widex"]),
    ("Starkey", ["starkey"]),
    ("Beurer", ["beurer"]),
    ("Nonin", ["nonin"]),
    ("Bluefruit", ["bluefruit"]),
    ("CircuitPython", ["circuitpython"]),
    ("MicroPython", ["micropython"]),
    ("Zephyr", ["zephyr"]),
]

DUAL_USE_TOOL_KEYWORDS = [
    "flipper zero", "flipper", "wifi pineapple", "rubber ducky",
    "bash bunny", "packet squirrel", "lan turtle", "omg cable",
    "proxmark", "proxmark3", "hackrf", "ubertooth", "yard stick one",
    "yardstick one", "chameleonultra", "chameleon ultra",
    "chameleonmini", "chameleon mini", "limesdr", "lime sdr",
    "rtl sdr", "rtl-sdr", "sdrplay", "bladerf", "blade rf",
    "pwnagotchi", "marauder", "deauther", "evil portal",
    "evil twin", "wardriver", "wardriving", "ble spam", "badusb",
    "bad kb", "badkb", "nfc cloner", "rfid cloner", "icopy x",
]

DEV_TOOL_KEYWORDS = [
    "esp32", "esp8266", "arduino", "nrf52", "nrf528", "m5stack",
    "m5stick", "wemos", "lolin", "micro:bit", "micro bit",
    "raspberry", "pico w", "seeed", "xiao", "adafruit", "feather",
    "circuit playground", "sparkfun", "lilygo", "heltec", "dfrobot",
    "particle", "pycom", "beaglebone", "pinecil", "pinetime",
    "stm32", "nucleo", "launchpad", "efr32", "meshtastic",
    "t beam", "t deck", "t echo", "qt py", "itsybitsy",
    "thing plus", "firebeetle", "wio terminal", "reterminal",
    "badger", "tiny 2040", "plasma 2040", "maix",
]

BEACON_TOOL_KEYWORDS = [
    "ibeacon", "eddystone", "altbeacon", "ruuvitag", "ruuvi",
    "estimote", "kontakt", "radbeacon", "bluecharm", "minew",
    "bluecats", "kbeacon",
]

MANUFACTURER_BRANDS = {
    0: "Ericsson",
    1: "Nokia",
    2: "Intel",
    3: "IBM",
    4: "Toshiba",
    5: "3Com",
    6: "Microsoft",
    8: "Motorola",
    9: "Infineon",
    10: "Qualcomm",
    13: "Texas Instruments",
    15: "Broadcom",
    19: "Atmel",
    20: "Mitsubishi",
    29: "Qualcomm",
    34: "NEC",
    36: "Alcatel",
    37: "NXP",
    41: "Hitachi",
    42: "Symbol",
    46: "MediaTek",
    48: "STMicroelectronics",
    74: "Sony Ericsson",
    59: "Nordic",
    76: "Apple",
    89: "Nordic",
    117: "Samsung",
    224: "Google",
    301: "Sony",
    343: "Xiaomi",
    474: "Logitech",
    655: "Toshiba",
    741: "Bose",
    756: "Huawei",
    911: "Xiaomi",
    1110: "Garmin",
    1177: "Fitbit",
    1352: "Tile",
    1441: "OPPO",
    1521: "Vivo",
    2467: "Arduino",
}

# 狀態同步控制開關 (Sync Controllers)
cmd_ready        = False 
start_boot_event = threading.Event()  # 用來讓終端機控制視窗動畫起跑的訊號槍

# 警告隊列 (Warning Queue for popups)
warning_queue      = []
warning_queue_lock = threading.Lock()

def log_event(msg: str, mode: str = None):
    """Log an event. If *mode* is given, only print to terminal when that mode is active."""
    ts    = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"

    if cmd_ready:
        if mode is None or _active_mode() == mode:
            print(entry)

    with scan_log_lock:
        scan_log.append(entry)
        if len(scan_log) > 80:
            scan_log.pop(0)

def _active_mode():
    with mode_lock:
        return current_mode

def start_sound():
    if not SOUND_FILE.exists():
        return
    if winsound is not None:
        winsound.PlaySound(
            str(SOUND_FILE),
            winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_LOOP,
        )
    elif _sound_backend == "pygame":
        try:
            _pygame_mixer.init()
            _pygame_mixer.music.load(str(SOUND_FILE))
            _pygame_mixer.music.play(loops=-1)
        except Exception:
            pass
    elif _sound_backend == "playsound":
        threading.Thread(
            target=lambda: _playsound_func(str(SOUND_FILE)),
            daemon=True,
        ).start()

def stop_sound():
    if winsound is not None:
        winsound.PlaySound(None, winsound.SND_PURGE)
    elif _sound_backend == "pygame":
        try:
            _pygame_mixer.music.stop()
        except Exception:
            pass

def play_alarm_sound():
    """Play alarm sound for suspicious device detection."""
    sound_file = ALARM_SOUND_FILE if ALARM_SOUND_FILE.exists() else SOUND_FILE
    if not sound_file.exists():
        return
    if winsound is not None:
        # Play alarm sound asynchronously, repeat 2 times
        def _play():
            try:
                winsound.PlaySound(
                    str(sound_file),
                    winsound.SND_FILENAME | winsound.SND_ASYNC,
                )
                time.sleep(0.5)
                winsound.PlaySound(
                    str(sound_file),
                    winsound.SND_FILENAME | winsound.SND_ASYNC,
                )
            except Exception:
                pass
        threading.Thread(target=_play, daemon=True).start()
    elif _sound_backend == "pygame":
        try:
            _pygame_mixer.init()
            _pygame_mixer.music.load(str(sound_file))
            _pygame_mixer.music.play(loops=1)
        except Exception:
            pass

# ===== Blacklist Management =====

def blacklist_add(mac):
    """Add a MAC address to the blacklist."""
    with blacklist_lock:
        device_blacklist.add(mac.upper())
    log_event(f"BLACKLIST ADD: {mac}")
    if cmd_ready:
        print(f"  🔇 BLACKLISTED: {mac}")

def blacklist_remove(mac):
    """Remove a MAC address from the blacklist."""
    with blacklist_lock:
        device_blacklist.discard(mac.upper())
    log_event(f"BLACKLIST REMOVE: {mac}")
    if cmd_ready:
        print(f"  🔓 UNBLACKLISTED: {mac}")

def blacklist_is_blocked(mac):
    """Check if a MAC address is blacklisted."""
    with blacklist_lock:
        return mac.upper() in device_blacklist

def blacklist_get_all():
    """Get all blacklisted MAC addresses."""
    with blacklist_lock:
        return list(device_blacklist)

# ===== Export Functions =====

def export_csv(filepath):
    """Export current devices to CSV file."""
    with devices_lock:
        snapshot = dict(devices)
    if not snapshot:
        return False, "No devices to export"
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Name', 'Type', 'MAC', 'RSSI', 'Confidence', 'Source',
                           'Company IDs', 'Services', 'Warning', 'Randomized MAC'])
            for addr, data in snapshot.items():
                warning = data.get('warning')
                warning_str = f"{warning['level']}: {warning['label']}" if warning else ''
                writer.writerow([
                    data.get('device_name', data['name']),
                    data['type'],
                    data['mac'],
                    data['rssi'],
                    data.get('confidence', 0),
                    data.get('source', ''),
                    data.get('company_ids', ''),
                    data.get('services', ''),
                    warning_str,
                    'Yes' if data.get('randomized_mac') else 'No',
                ])
        if cmd_ready:
            print(f"  📁 EXPORTED CSV: {len(snapshot)} devices → {filepath.name}")
        return True, f"Exported {len(snapshot)} devices to {filepath}"
    except Exception as e:
        return False, f"Export failed: {e}"

def export_json(filepath):
    """Export current devices to JSON file."""
    with devices_lock:
        snapshot = dict(devices)
    if not snapshot:
        return False, "No devices to export"
    try:
        export_data = []
        for addr, data in snapshot.items():
            with rssi_history_lock:
                rssi_hist = rssi_history.get(addr, [])
            entry = {
                'name': data.get('device_name', data['name']),
                'type': data['type'],
                'mac': data['mac'],
                'rssi': data['rssi'],
                'confidence': data.get('confidence', 0),
                'source': data.get('source', ''),
                'company_ids': data.get('company_ids', ''),
                'services': data.get('services', ''),
                'warning': data.get('warning'),
                'randomized_mac': data.get('randomized_mac', False),
                'rssi_history': [{'time': t, 'rssi': r} for t, r in rssi_hist[-20:]],
            }
            export_data.append(entry)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        if cmd_ready:
            print(f"  📁 EXPORTED JSON: {len(snapshot)} devices → {filepath.name}")
        return True, f"Exported {len(snapshot)} devices to {filepath}"
    except Exception as e:
        return False, f"Export failed: {e}"

def clean_device_name(value):
    if value is None:
        return ""
    return str(value).strip()

def device_display_name(device, adv_data=None):
    for value in (
        getattr(device, "name", None),
        getattr(adv_data, "local_name", None),
    ):
        name = clean_device_name(value)
        if name:
            return name
    return ""

def device_label(device, adv_data=None):
    name = device_display_name(device, adv_data)
    address = getattr(device, "address", "unknown")
    return name or address[:8]

def normalize_mac(address):
    chars = "0123456789ABCDEF"
    compact = "".join(ch for ch in str(address or "").upper() if ch in chars)
    if len(compact) < 12:
        return ""
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))

def mac_oui(address):
    mac = normalize_mac(address)
    return mac[:8] if mac else ""

def is_randomized_mac(address):
    """Check if MAC address is locally administered (randomized).
    Bit 1 of first octet = 1 means locally administered (not burned-in).
    Apple, Android, Windows all use this for privacy."""
    mac = normalize_mac(address)
    if not mac:
        return False
    first_octet = int(mac[:2], 16)
    return bool(first_octet & 0x02)

def normalize_name_for_match(name):
    return " ".join(
        str(name or "")
        .lower()
        .replace("_", " ")
        .replace("-", " ")
        .replace("|", " ")
        .replace("/", " ")
        .split()
    )

def contains_keyword(name, keywords):
    padded = f" {name} "
    for key in keywords:
        key = normalize_name_for_match(key)
        if not key:
            continue
        if " " in key or len(key) <= 3:
            if name == key or padded.find(f" {key} ") >= 0:
                return True
        elif key in name:
            return True
    return False

def peripheral_kind_from_name(raw_name):
    name = normalize_name_for_match(raw_name)
    if not name:
        return ""

    if contains_keyword(name, DUAL_USE_TOOL_KEYWORDS):
        if contains_keyword(name, ["hackrf", "ubertooth", "yard stick one", "yardstick one", "limesdr", "lime sdr", "rtl sdr", "rtl-sdr", "sdrplay", "bladerf", "blade rf"]):
            return "RF Tool"
        if contains_keyword(name, ["proxmark", "proxmark3", "chameleonultra", "chameleon ultra", "chameleonmini", "chameleon mini"]):
            return "RFID Tool"
        if contains_keyword(name, ["wifi pineapple", "rubber ducky", "bash bunny", "packet squirrel", "lan turtle", "omg cable", "pwnagotchi", "marauder", "deauther", "evil portal"]):
            return "Pentest Tool"
        return "Security Tool"
    if contains_keyword(name, BEACON_TOOL_KEYWORDS):
        return "Beacon"
    if contains_keyword(name, ["iphone", "android phone", "galaxy s", "galaxy note", "pixel", "redmi", "poco", "xperia", "reno", "find x", "oneplus", "realme", "iqoo", "honor", "motorola", "moto", "nokia", "nothing phone", "htc one", "htc u", "htc desire", "zte", "nubia", "redmagic", "tecno", "infinix", "fairphone"]):
        return "Phone"
    if contains_keyword(name, ["ipad", "tablet", "galaxy tab", "surface go", "tab s", "lenovo tab", "xiaomi pad", "redmi pad"]):
        return "Tablet"
    if contains_keyword(name, ["watch", "band", "fitness", "garmin", "fitbit", "polar", "amazfit", "zepp", "suunto", "coros", "whoop", "oura", "pinetime", "smart ring"]):
        return "Wearable"
    if contains_keyword(name, ["macbook", "laptop", "notebook", "thinkpad", "thinkbook", "ideapad", "zenbook", "vivobook", "surface laptop", "xps", "latitude", "elitebook", "framework", "spectre", "envy", "omen", "pavilion", "victus", "predator", "nitro", "legion", "loq", "raider", "stealth", "katana", "prestige", "aorus", "aero laptop", "inspiron", "vostro", "precision"]):
        return "Laptop"
    if contains_keyword(name, ["desktop", "pc", "workstation", "imac", "mac mini", "mac studio", "surface studio", "nuc"]):
        return "Computer"
    if any(k in name for k in [
        "keyboard", "keychron", "mx keys", "keys to go", "pop keys",
        "wave keys", "ergo k", "k380", "k580", "k780", "k855",
        "blackwidow", "huntsman", "apex pro", "k70", "k95", "rk61",
        "rk68", "rk84", "rk96", "gmmk", "vulcan", "alloy origins",
        "ducky", "varmilo", "leopold", "filco", "nuphy",
    ]):
        return "Keyboard"
    if any(k in name for k in [
        "mouse", "mice", "mx master", "mx anywhere", "pebble mouse",
        "lift vertical", "ergo m", "m650", "m720", "m585", "m590",
        "g102", "g304", "g305", "g502", "g604", "g705", "g903",
        "superlight", "deathadder", "basilisk", "viper", "orochi",
        "rival", "aerox", "pulsefire", "harpoon", "katar", "model o",
        "model d", "kone", "burst pro", "m711",
    ]):
        return "Mouse"
    if any(k in name for k in ["trackpad", "touchpad", "trackball"]):
        return "Trackpad"
    if contains_keyword(name, ["remote", "remote control", "chromecast remote", "roku remote"]):
        return "Remote"
    if any(k in name for k in ["gamepad", "controller", "joystick", "joy con", "dualsense", "dualshock", "switch pro", "xbox wireless", "pro controller"]):
        return "Gamepad"
    if contains_keyword(name, ["hearing aid", "phonak", "oticon", "resound", "signia", "widex", "starkey"]):
        return "Hearing Aid"
    if any(k in name for k in ["headset", "headphone", "earbuds", "earbud", "airpods", "buds", "freebuds", "linkbuds", "quietcomfort", "arctis", "kraken", "soundcore", "beoplay", "momentum", "qcy", "tozo", "haylou", "soundpeats", "earfun", "wh 1000", "wf 1000", "tone free"]):
        return "Headset"
    if any(k in name for k in ["speaker", "soundbar", "partybox", "soundlink", "sonos", "homepod", "nest audio", "echo", "echo dot", "jbl flip", "jbl charge", "jbl go"]):
        return "Speaker"
    if contains_keyword(name, ["tv", "smart tv", "android tv", "fire tv", "chromecast", "roku", "shield tv", "hisense", "vizio"]):
        return "Smart TV"
    if contains_keyword(name, ["printer", "labelwriter", "zebra", "dymo"]):
        return "Printer"
    if contains_keyword(name, ["scanner", "barcode", "socket scanner", "datalogic", "honeywell scanner"]):
        return "Barcode Scanner"
    if contains_keyword(name, ["square reader", "square terminal", "sumup", "clover", "verifone", "ingenico", "pos terminal"]):
        return "POS Terminal"
    if contains_keyword(name, ["drone", "mavic", "phantom", "air 2s", "mini 3", "mini 4", "ronin"]):
        return "Drone"
    if contains_keyword(name, ["camera", "gopro", "canon", "nikon", "osmo", "insta360", "fujifilm", "fuji", "lumix", "olympus"]):
        return "Camera"
    if contains_keyword(name, ["beacon", "ibeacon", "eddystone", "altbeacon", "airtag", "tile", "smarttag", "chipolo", "pebblebee", "ruuvitag"]):
        return "Tracker"
    if contains_keyword(name, ["blood pressure", "glucose", "dexcom", "freestyle libre", "pulse oximeter", "oximeter", "omron"]):
        return "Medical"
    if contains_keyword(name, ["scale", "body scale", "smart scale"]):
        return "Scale"
    if contains_keyword(name, ["thermometer", "temperature", "humidity", "sensor", "sensortag", "motion sensor", "contact sensor", "co2", "air quality"]):
        return "Sensor"
    if contains_keyword(name, ["heart rate", "hrm", "tickr", "coospo", "magene", "wahoo"]):
        return "Heart Sensor"
    if contains_keyword(name, ["cadence", "speed sensor", "cycling sensor", "power meter", "assioma", "kickr", "tacx", "zwift"]):
        return "Cycling Sensor"
    if contains_keyword(name, ["lock", "smart lock", "yale", "august lock", "nuki", "schlage"]):
        return "Smart Lock"
    if contains_keyword(name, ["thermostat", "ecobee", "nest thermostat", "honeywell"]):
        return "Thermostat"
    if contains_keyword(name, ["vacuum", "roomba", "deebot", "robovac", "roborock", "dreame", "narwal"]):
        return "Robot Vacuum"
    if contains_keyword(name, ["microphone", "mic", "wireless go"]):
        return "Microphone"
    if contains_keyword(name, ["vr", "quest", "oculus", "htc vive", "vive tracker", "index controller"]):
        return "VR/AR"
    if contains_keyword(name, ["light", "bulb", "lamp", "strip", "plug", "switch", "curtain", "bot", "doorbell", "hue", "nest", "yeelight", "aqara", "mi home", "eufy", "govee", "lifx", "nanoleaf", "tuya", "shelly", "sonoff", "switchbot", "wyze", "arlo"]):
        return "Smart Home"
    if contains_keyword(name, ["obd", "obd2", "obd ii", "elm327", "obdlink", "veepeak", "carly"]):
        return "OBD Adapter"
    if contains_keyword(name, ["car", "auto", "phone key", "tesla", "bmw", "toyota", "lexus", "ford", "honda", "acura", "nissan", "infiniti", "hyundai", "genesis", "kia", "mazda", "subaru", "mercedes", "benz", "audi", "volkswagen", "vw", "porsche", "volvo"]):
        return "Vehicle"
    if contains_keyword(name, DEV_TOOL_KEYWORDS):
        return "Dev Board"
    return "Peripheral"

def kind_or_default(kind, default):
    return kind if kind and kind != "Peripheral" else default

def brand_from_name(raw_name):
    name = normalize_name_for_match(raw_name)
    if not name:
        return None
    for brand, keywords in BRAND_KEYWORDS:
        if contains_keyword(name, keywords):
            return brand
    return None

def display_type_label(dev_type):
    if not dev_type:
        return "BLE Device"
    if dev_type.startswith("Generic|"):
        return dev_type.split("|", 1)[1] or "BLE Device"
    if dev_type.startswith("Unknown|"):
        return dev_type.split("|", 1)[1] or "BLE Device"
    return dev_type

def default_kind_for_brand(brand):
    if brand in {
        "Flipper Zero", "Hak5", "Great Scott Gadgets", "Proxmark",
        "Lab401", "Lime Microsystems", "RTL-SDR", "SDRplay", "Nuand",
        "Pwnagotchi",
    }:
        return "Security Tool"
    if brand in {
        "FOXXRAY", "Logitech", "Razer", "Corsair", "SteelSeries", "HyperX",
        "ROCCAT", "Glorious", "Cooler Master", "Redragon", "Rapoo",
        "Elecom", "Kensington", "Keychron", "Akko", "AULA", "Ducky",
        "Varmilo", "Leopold", "Filco", "NuPhy", "Royal Kludge",
    }:
        return "HID"
    if brand in {
        "JBL", "Bose", "Jabra", "Sennheiser", "Anker", "Skullcandy",
        "Edifier", "Marshall", "Shure", "Audio-Technica", "AKG",
        "Bang & Olufsen", "Bowers & Wilkins", "Sonos", "Harman Kardon",
        "Yamaha", "Denon", "Pioneer", "Creative", "Tribit", "EarFun",
        "TOZO", "QCY", "Haylou", "SoundPEATS", "1MORE", "Baseus",
        "UGREEN", "Rode", "Poly", "Turtle Beach", "ASTRO",
    }:
        return "Audio"
    if brand in {"Garmin", "Fitbit", "Polar", "Amazfit", "Suunto", "Coros", "Withings", "WHOOP", "Oura"}:
        return "Wearable"
    if brand in {
        "Arduino", "Espressif", "M5Stack", "WEMOS", "Nordic",
        "Raspberry Pi", "Seeed", "BBC", "Adafruit", "SparkFun",
        "LilyGO", "LILYGO", "Heltec", "Pimoroni", "DFRobot",
        "Makeblock", "Sipeed", "Particle", "Pycom", "Meshtastic",
        "BeagleBoard", "PINE64", "STMicroelectronics",
        "Texas Instruments", "Silicon Labs",
    }:
        return "Dev Board"
    if brand in {"Ruuvi", "BlueCharm", "Minew", "Kontakt.io", "Estimote", "BlueCats", "Radius Networks", "KBeacon", "Shelly BLU"}:
        return "Beacon"
    if brand in {
        "TP-Link", "Govee", "LIFX", "Nanoleaf", "Tuya", "Shelly",
        "Sonoff", "SwitchBot", "Ring", "Wyze", "Arlo", "Ecobee",
        "Honeywell", "Yale", "August", "Nuki", "Schlage", "Kwikset",
        "Sesame", "Lockly", "Ultraloq", "Level Lock", "Dyson",
        "iRobot", "Ecovacs", "Dreame", "Narwal", "Philips", "Eve",
        "Meross", "Leviton", "Lutron", "GE Cync", "Wiz", "IKEA",
        "Qingping", "Ecowitt",
    }:
        return "Smart Home"
    if brand in {"Tile", "Chipolo", "Pebblebee", "Orbit", "Nut", "TrackR", "Cube Tracker"}:
        return "Tracker"
    if brand in {"GoPro", "Canon", "Nikon", "DJI", "Insta360", "Fujifilm", "Panasonic", "OM System", "Skydio", "Autel", "Parrot"}:
        return "Camera"
    if brand in {"Nintendo", "PlayStation"}:
        return "Gamepad"
    if brand in {"Meta", "HTC Vive", "Valve"}:
        return "VR/AR"
    if brand in {"Tesla", "BMW", "Toyota", "Ford", "Honda", "Nissan", "Hyundai", "Kia", "Mazda", "Subaru", "Mercedes-Benz", "Audi", "Volkswagen", "Porsche", "Volvo"}:
        return "Vehicle"
    if brand in {"Brother", "Epson", "Zebra", "Dymo"}:
        return "Printer"
    if brand in {"Omron", "Dexcom", "Abbott", "iHealth", "Beurer", "Nonin"}:
        return "Medical"
    if brand in {"Wahoo", "Bryton", "Magene", "CooSpo", "Favero", "Tacx", "Zwift", "Peloton", "Concept2"}:
        return "Cycling Sensor"
    if brand in {"Veepeak", "OBDLink", "ELM327", "Carly"}:
        return "OBD Adapter"
    if brand in {"Socket Mobile", "Datalogic"}:
        return "Barcode Scanner"
    if brand in {"Square", "SumUp", "Clover", "Verifone", "Ingenico"}:
        return "POS Terminal"
    if brand in {"Phonak", "Oticon", "ReSound", "Signia", "Widex", "Starkey"}:
        return "Hearing Aid"
    if brand in {"Aranet", "SensorPush", "ThermoPro", "Inkbird", "BlueMaestro", "Elitech"}:
        return "Sensor"
    if brand in {"Roku", "NVIDIA", "Hisense", "Vizio", "TCL"}:
        return "Smart TV"
    return "Device"

def device_warning(raw_name, dev_type, device=None, adv_data=None):
    """
    多層驗證警告系統，降低誤判率
    需要多個獨立驗證來源同意才能發出警告
    只有置信度 >= 70% 的警告才會被顯示
    """
    name = normalize_name_for_match(raw_name)
    dtype = normalize_name_for_match(dev_type)
    
    # 驗證來源追蹤
    verification_sources = []
    confidence = 0
    
    # ======== 階段1：名稱檢測 ========
    name_is_dual_use = contains_keyword(name, DUAL_USE_TOOL_KEYWORDS)
    name_is_dev_tool = contains_keyword(name, DEV_TOOL_KEYWORDS)
    dtype_is_security = contains_keyword(dtype, ["security tool", "pentest tool", "rf tool", "rfid tool"])
    dtype_is_dev = contains_keyword(dtype, ["dev board"])
    
    if name_is_dual_use or dtype_is_security:
        verification_sources.append(("NAME", "DUAL_USE", 90))
    if name_is_dev_tool or dtype_is_dev:
        verification_sources.append(("TYPE", "DEV_BOARD", 78))
    
    # ======== 階段2：廠商 ID 驗證 ========
    if device and adv_data:
        manuf = getattr(adv_data, "manufacturer_data", {}) or {}
        
        # 檢查已知的危險廠商 ID
        # Flipper Zero 可能使用的廠商 ID（如果有已知簽名）
        known_dangerous_mfg = {
            # 可根據實際情況添加已知工具的廠商 ID
        }
        
        for company_id in manuf:
            if company_id in known_dangerous_mfg:
                verification_sources.append(("MFG_ID", "DANGEROUS_VENDOR", 90))
    
    # ======== 階段3：MAC 地址 OUI 驗證 ========
    if device:
        address = getattr(device, "address", "")
        oui = mac_oui(address)
        
        # 已知安全工具的 OUI（如果知道的話）
        # 例如：某些開發板有固定的 OUI
        known_dangerous_oui = {
            # "00:AA:BB": "Known_Tool",
        }
        
        if oui in known_dangerous_oui:
            verification_sources.append(("OUI", known_dangerous_oui[oui], 85))
    
    # ======== 階段4：服務 UUID 驗證 ========
    if adv_data:
        uuids = service_uuids(adv_data)
        
        # 已知安全工具的特徵 UUID
        dangerous_uuids = {
            # "特徵uuid": ("工具名稱", 置信度),
        }
        
        for uuid in uuids:
            short = short_uuid(uuid)
            if short in dangerous_uuids:
                tool_name, conf = dangerous_uuids[short]
                verification_sources.append(("UUID", tool_name, conf))
    
    # ======== 終判：多源驗證 ========
    # 分類統計
    dual_use_count = sum(1 for src, type_, _ in verification_sources if type_ == "DUAL_USE")
    dev_board_count = sum(1 for src, type_, _ in verification_sources if type_ == "DEV_BOARD")
    dangerous_count = sum(1 for src, type_, _ in verification_sources if type_ in ["DANGEROUS_VENDOR", "Known_Tool"])
    
    # 預設值，避免 verification_sources 為空時 UnboundLocalError
    num_sources = 0
    confidence = 0

    # 計算置信度（多源驗證加分）
    if verification_sources:
        max_conf = max(c for _, _, c in verification_sources)
        num_sources = len(verification_sources)
        
        # 多個來源同意時增加置信度
        if num_sources >= 2:
            confidence = min(99, max_conf + (num_sources - 1) * 5)
        else:
            confidence = max_conf
    
    # 只有在高置信度且多源驗證時才發出警告
    # ALERT：需要至少 1 個高置信度危險信號
    if dangerous_count > 0 or (dual_use_count > 0 and confidence >= 80):
        return {
            "level": "ALERT",
            "label": "DUAL-USE TOOL",
            "message": "Dual-use security/RF tool nearby",
            "confidence": confidence,
            "sources": num_sources if verification_sources else 0,
        }
    
    # DEV：需要至少 2 個獨立來源確認或高置信度
    if (dev_board_count > 0 and confidence >= 75) or (num_sources >= 2 and dev_board_count > 0):
        return {
            "level": "DEV",
            "label": "DEV BOARD",
            "message": "Development board nearby",
            "confidence": confidence,
            "sources": num_sources if verification_sources else 0,
        }
    
    return None

def named_type_hint(raw_name):
    name = normalize_name_for_match(raw_name)
    if not name:
        return None

    kind = peripheral_kind_from_name(raw_name)
    brand = brand_from_name(raw_name)
    if brand:
        if kind == "Dev Board":
            return f"{brand}|Dev Board"
        return f"{brand}|{kind_or_default(kind, default_kind_for_brand(brand))}"

    # brand_from_name already covers FOXXRAY, Logitech, and dev-board keywords
    # via BRAND_KEYWORDS, so no duplicate checks needed here.

    if kind != "Peripheral":
        return f"Generic|{kind}"
    return None

def service_uuids(adv_data):
    return [str(uuid).lower() for uuid in (getattr(adv_data, "service_uuids", []) or [])]

def short_uuid(uuid):
    text = str(uuid).lower()
    if text.startswith("0000") and text.endswith("-0000-1000-8000-00805f9b34fb"):
        return text[4:8]
    if len(text) <= 6:
        return text.replace("0x", "").zfill(4)
    return text

def has_short_uuid(uuids, target_uuid):
    short = target_uuid.lower().replace("0x", "").zfill(4)
    full = f"0000{short}-0000-1000-8000-00805f9b34fb"
    return any(uuid == full or uuid == short for uuid in uuids)

def appearance_type_hint(device, adv_data):
    appearance = getattr(adv_data, "appearance", None) or getattr(device, "appearance", None)
    if appearance is None:
        return None
    cat = appearance >> 6
    sub = appearance & 0x3F
    full = (cat << 8) | sub
    if cat == 0x0F:
        return HID_APPEARANCE_TYPES.get(sub, "Generic|Mouse/Keyboard")
    return APPEARANCE_SUBTYPE_TYPES.get(full) or APPEARANCE_CATEGORY_TYPES.get(cat)

def service_type_hint(adv_data, raw_name):
    uuids = service_uuids(adv_data)
    if not uuids:
        return None

    if "6e400001-b5a3-f393-e0a9-e50e24dcca9e" in uuids:
        return "Nordic|Dev Board"
    for uuid in uuids:
        hint = SERVICE_UUID_TYPES.get(short_uuid(uuid))
        if hint:
            if hint == "Generic|Mouse/Keyboard":
                kind = peripheral_kind_from_name(raw_name)
                return f"Generic|{kind_or_default(kind, 'Mouse/Keyboard')}"
            if hint == "Generic|BLE Device":
                brand = brand_from_name(raw_name)
                kind = kind_or_default(peripheral_kind_from_name(raw_name), "BLE Device")
                return f"{brand}|{kind}" if brand else f"Generic|{kind}"
            return hint
    return None

def mac_type_hint(address, raw_name):
    oui = mac_oui(address)
    if not oui:
        return None
    if oui in LOGITECH_OUIS:
        kind = peripheral_kind_from_name(raw_name)
        return f"Logitech|{kind_or_default(kind, 'HID')}"
    return DEV_BOARD_OUI_TYPES.get(oui)

def manufacturer_type_hint(manuf, raw_name):
    if not manuf:
        return None
    kind = kind_or_default(peripheral_kind_from_name(raw_name), "Device")
    for company_id in manuf:
        brand = MANUFACTURER_BRANDS.get(company_id)
        if brand:
            if brand in ("Nordic", "Arduino") and kind == "Device":
                kind = "Dev Board"
            return f"{brand}|{kind}"
    return None

def compact_company_ids(manuf):
    if not manuf:
        return ""
    parts = []
    for company_id in sorted(manuf):
        brand = MANUFACTURER_BRANDS.get(company_id, "Unknown")
        parts.append(f"0x{company_id:04X}:{brand}")
    return ", ".join(parts)

def compact_services(adv_data, limit=6):
    uuids = [short_uuid(uuid) for uuid in service_uuids(adv_data)]
    if len(uuids) > limit:
        return ", ".join(uuids[:limit]) + ", ..."
    return ", ".join(uuids)

# ===== Anti-Spoofing Detection Module =====

def detect_mac_spoofing(address, raw_name=""):
    """
    Detect MAC address spoofing patterns including Flipper Zero signatures.
    Returns (risk_score, indicators_list)
    """
    indicators = []
    risk_score = 0
    
    oui = mac_oui(address)
    if not oui:
        return 0, indicators
    
    # Check for randomized MAC addresses (LSB of first octet = 1)
    first_octet = int(address.split(":")[0], 16)
    if first_octet & 0x02:  # Locally administered address
        indicators.append("randomized_mac")
        risk_score += 10
    
    # Check for suspicious OUI patterns (test/dev OUIs)
    if any(x in oui for x in ["00:00", "FF:FF", "AA:AA", "BB:BB", "CC:CC", "DD:DD"]):
        indicators.append("test_oui")
        risk_score += 15
    
    # Flipper Zero specific signatures
    flipper_indicators = detect_flipper_zero_signature(address, raw_name)
    if flipper_indicators:
        indicators.extend(flipper_indicators)
        risk_score += 25
    
    return risk_score, indicators

def detect_flipper_zero_signature(address, raw_name=""):
    """
    Detect known Flipper Zero device signatures and behaviors.
    """
    indicators = []
    name_lower = normalize_name_for_match(raw_name)
    
    # Known Flipper Zero patterns
    flipper_patterns = [
        "flipper", "flipp", "esp32s3", "marauder", "deauther",
        "portapak", "spectrum analyzer", "ble spam", "badusb",
    ]
    
    if any(p in name_lower for p in flipper_patterns):
        indicators.append("flipper_zero_pattern")
    
    # Flipper Zero MAC pattern (ESP32-S3 based, random generation)
    oui = mac_oui(address)
    if oui in ["48:E7:DA", "08:4C:A2", "EC:5C:89", "2C:1F:38", "34:36:3B"]:
        indicators.append("flipper_compatible_oui")
    
    return indicators

def detect_signal_instability(device_history):
    """
    Detect abnormal RSSI patterns indicating device spoofing or signal manipulation.
    Returns (anomaly_score, pattern_description)
    """
    if not device_history or len(device_history) < 3:
        return 0, ""
    
    rssi_values = device_history[-10:]  # Last 10 readings
    if len(rssi_values) < 3:
        return 0, ""
    
    anomaly_score = 0
    patterns = []
    
    # Check for unusually rapid RSSI changes
    rssi_changes = [abs(rssi_values[i] - rssi_values[i-1]) for i in range(1, len(rssi_values))]
    avg_change = sum(rssi_changes) / len(rssi_changes) if rssi_changes else 0
    max_change = max(rssi_changes) if rssi_changes else 0
    
    if max_change > 25:  # More than 25 dBm jump is suspicious
        anomaly_score += 15
        patterns.append(f"sudden_rssi_jump_{int(max_change)}dbm")
    
    if avg_change > 8:  # Average change > 8 dBm is unusual
        anomaly_score += 10
        patterns.append(f"unstable_signal_avg_{int(avg_change)}dbm")
    
    # Check for too-stable signal (possible replay/fake)
    rssi_variance = sum((x - sum(rssi_values)/len(rssi_values))**2 for x in rssi_values) / len(rssi_values)
    if rssi_variance < 0.5:
        anomaly_score += 12
        patterns.append("artificial_stability")
    
    return anomaly_score, "|".join(patterns)

def detect_name_spoofing(address, raw_name, adv_data=None):
    """
    Detect device name spoofing patterns (e.g., name/MAC mismatch, impersonation).
    """
    indicators = []
    risk_score = 0
    name_lower = normalize_name_for_match(raw_name)
    
    # Check for suspicious name patterns
    if not raw_name:
        indicators.append("no_name")
        risk_score += 5
    
    # Detects names that claim to be premium devices but use generic MACs
    premium_brands = ["apple", "samsung", "sony", "bose", "sennheiser"]
    generic_oui = mac_oui(address)
    
    if any(brand in name_lower for brand in premium_brands):
        if generic_oui in ["00:11:22", "33:44:55", "AA:BB:CC"]:
            indicators.append("brand_mac_mismatch")
            risk_score += 15
    
    # Check for tool-like names with legitimate device names
    if contains_keyword(raw_name, DUAL_USE_TOOL_KEYWORDS):
        indicators.append("tool_name_detected")
        risk_score += 30
    
    return risk_score, indicators

def detect_device_behavior_anomaly(address, scan_history):
    """
    Detect anomalous device behaviors (e.g., constant MAC changes, erratic appearances).
    """
    if not scan_history or len(scan_history) < 5:
        return 0, []
    
    anomalies = []
    risk_score = 0
    
    # Check for MAC rotation patterns
    unique_names = len(set(scan_history))
    if unique_names > len(scan_history) * 0.6:  # Device name/ID changes frequently
        anomalies.append("frequent_identity_changes")
        risk_score += 20
    
    # Check for irregular scan intervals
    intervals = []
    # (This would need timestamps in scan_history)
    
    return risk_score, anomalies

def assess_spoofing_risk(address, raw_name, rssi_history=None, adv_data=None):
    """
    Comprehensive spoofing risk assessment combining multiple detection vectors.
    Returns: (risk_level, confidence, details_dict)
    """
    with spoofing_lock:
        if address not in spoofing_suspect_db:
            spoofing_suspect_db[address] = {
                "rssi_history": [],
                "name_history": [],
                "seen_count": 0,
                "first_seen": time.monotonic(),
                "indicators": [],
            }
        
        suspect = spoofing_suspect_db[address]
        suspect["seen_count"] += 1
        if raw_name and raw_name not in suspect["name_history"]:
            suspect["name_history"].append(raw_name)
        if rssi_history:
            suspect["rssi_history"].append(rssi_history)
    
    total_score = 0
    all_indicators = []
    details = {}
    
    # 1. MAC Spoofing Detection
    mac_score, mac_indicators = detect_mac_spoofing(address, raw_name)
    total_score += mac_score
    all_indicators.extend(mac_indicators)
    details["mac_check"] = {"score": mac_score, "indicators": mac_indicators}
    
    # 2. Signal Analysis
    if rssi_history:
        signal_score, signal_pattern = detect_signal_instability(
            spoofing_suspect_db.get(address, {}).get("rssi_history", [rssi_history])
        )
        total_score += signal_score
        if signal_pattern:
            all_indicators.append(signal_pattern)
        details["signal_check"] = {"score": signal_score, "pattern": signal_pattern}
    
    # 3. Name Spoofing
    name_score, name_indicators = detect_name_spoofing(address, raw_name, adv_data)
    total_score += name_score
    all_indicators.extend(name_indicators)
    details["name_check"] = {"score": name_score, "indicators": name_indicators}
    
    # 4. Behavior Analysis
    if spoofing_suspect_db.get(address):
        behavior_score, behavior_anomalies = detect_device_behavior_anomaly(
            address, 
            spoofing_suspect_db[address]["name_history"]
        )
        total_score += behavior_score
        all_indicators.extend(behavior_anomalies)
        details["behavior_check"] = {"score": behavior_score, "anomalies": behavior_anomalies}
    
    # Normalize score to 0-100
    confidence = min(100, total_score)
    
    if confidence >= 75:
        risk_level = "ALERT"
    elif confidence >= 50:
        risk_level = "SUSPICIOUS"
    elif confidence >= 25:
        risk_level = "WARNING"
    else:
        risk_level = "NORMAL"
    
    return risk_level, confidence, {
        "all_indicators": all_indicators,
        "details": details,
        "suspect_db": spoofing_suspect_db.get(address),
    }

def classify_device(device, adv_data):
    raw_name = device_display_name(device, adv_data)
    address = getattr(device, "address", "")
    rssi = getattr(adv_data, "rssi", None)
    manuf = getattr(adv_data, "manufacturer_data", {}) or {}

    hints = []
    name_hint = named_type_hint(raw_name)
    mfg_hint = manufacturer_type_hint(manuf, raw_name)
    app_hint = appearance_type_hint(device, adv_data)
    svc_hint = service_type_hint(adv_data, raw_name)
    mac_hint = mac_type_hint(address, raw_name)

    final_type = get_device_type(device, adv_data)
    if name_hint:
        hints.append(("NAME", name_hint, 92 if "|" in name_hint else 78))
    if mfg_hint:
        hints.append(("MFG", mfg_hint, 84))
    elif manuf:
        hints.append(("MFG", final_type, 74))
    if app_hint:
        hints.append(("APP", app_hint, 72))
    if svc_hint:
        hints.append(("SVC", svc_hint, 68))
    if mac_hint:
        hints.append(("OUI", mac_hint, 62))

    if not hints:
        hints.append(("HEUR", final_type, 45 if raw_name else 30))

    sources = []
    confidence = 0
    for source, _hint, score in hints:
        if source not in sources:
            sources.append(source)
        confidence = max(confidence, score)

    if len(sources) >= 2:
        confidence = min(99, confidence + 5)
    if len(sources) >= 3:
        confidence = min(99, confidence + 3)

    warning = device_warning(raw_name, display_type_label(final_type), device, adv_data)
    if warning and warning["level"] == "ALERT":
        confidence = min(99, max(confidence, 95))

    # Perform anti-spoofing assessment
    spoofing_risk, spoofing_confidence, spoofing_details = assess_spoofing_risk(
        address, raw_name, rssi, adv_data
    )
    
    # Upgrade warning if spoofing detected
    if spoofing_risk in ["ALERT", "SUSPICIOUS"] and spoofing_confidence >= 50:
        if not warning or warning["level"] != "ALERT":
            warning = {
                "level": "ALERT" if spoofing_risk == "ALERT" else "DEV",
                "label": f"Possible Device Spoofing/Emulation",
                "message": f"Spoofing risk: {spoofing_risk} ({spoofing_confidence}% confidence). Indicators: {', '.join(spoofing_details['all_indicators'][:3])}",
                "confidence": spoofing_confidence,
            }

    return {
        "type": display_type_label(final_type),
        "confidence": confidence,
        "source": "+".join(sources),
        "company_ids": compact_company_ids(manuf),
        "services": compact_services(adv_data),
        "warning": warning,
    }

def get_device_type(device, adv_data):
    """
    Determines the brand and type of the Bluetooth device.
    Priority: Device Name -> Manufacturer ID -> Appearance -> Services -> MAC/OUI
    """
    raw_name = device_display_name(device, adv_data)
    name = raw_name.lower()
    address = getattr(device, "address", "")

    hint = named_type_hint(raw_name)
    if hint:
        return hint

    manuf = getattr(adv_data, "manufacturer_data", {}) or {}

    if 474 in manuf:
        kind = peripheral_kind_from_name(raw_name)
        return f"Logitech|{kind_or_default(kind, 'HID')}"

    if 89 in manuf:
        if any(k in name for k in ["nrf", "thingy", "dk", "dev", "uart"]):
            return "Nordic|Dev Board"
        return "Nordic|BLE Device"

    if 2467 in manuf:
        return "Arduino|Dev Board"

    # Apple (0x004C = 76)
    if 76 in manuf:
        payload = manuf[76]
        m_type  = payload[0] if payload else None

        if name:
            for model in ["iphone 16 pro max", "iphone 16 pro", "iphone 16 plus", "iphone 16",
                           "iphone 15 pro max", "iphone 15 pro", "iphone 15 plus", "iphone 15",
                           "iphone 14 pro max", "iphone 14 pro", "iphone 14 plus", "iphone 14",
                           "iphone 13 pro max", "iphone 13 pro", "iphone 13 mini", "iphone 13",
                           "iphone se"]:
                if model in name: return f"Apple|{model.title()}"
            if "iphone" in name: return "Apple|iPhone"
            if "ipad pro"   in name: return "Apple|iPad Pro"
            if "ipad air"   in name: return "Apple|iPad Air"
            if "ipad mini"  in name: return "Apple|iPad Mini"
            if "ipad"       in name: return "Apple|iPad"
            if "macbook pro" in name: return "Apple|MacBook Pro"
            if "macbook air" in name: return "Apple|MacBook Air"
            if "macbook"     in name: return "Apple|MacBook"
            if "mac mini"    in name: return "Apple|Mac Mini"
            if "mac studio"  in name: return "Apple|Mac Studio"
            if "mac pro"     in name: return "Apple|Mac Pro"
            if "imac"        in name: return "Apple|iMac"
            if "apple watch ultra" in name: return "Apple|Watch Ultra"
            if "apple watch se"    in name: return "Apple|Watch SE"
            if "apple watch"       in name: return "Apple|Watch"
            if "watch"             in name: return "Apple|Watch"

        if m_type == 0x07 and len(payload) >= 4:
            model_id = (payload[2] << 8) | payload[3]
            airpods_models = {
                0x2002: "AirPods 1st", 0x200F: "AirPods 2nd", 0x2013: "AirPods 3rd",
                0x200E: "AirPods Pro", 0x2014: "AirPods Pro 2nd", 0x2024: "AirPods Max",
                0x2003: "Powerbeats Pro", 0x200A: "Powerbeats3", 0x200B: "Beats X",
                0x200C: "Beats Solo3", 0x200D: "Beats Studio3", 0x2010: "Beats Flex",
                0x2011: "Beats Solo Pro",
            }
            label = airpods_models.get(model_id, "AirPods")
            return f"Apple|{label}"

        if m_type == 0x12:
            if len(payload) >= 3:
                acc_type = payload[2]
                if acc_type == 0x00: return "Apple|AirTag"
                if acc_type == 0x01: return "Apple|FindMy Item"
            return "Apple|AirTag"

        if m_type == 0x0F and len(payload) >= 3:
            status = payload[2]
            os_flag = (status >> 4) & 0x0F
            if os_flag in (0x1, 0x2, 0x3): return "Apple|iPhone"
            if os_flag in (0x4, 0x5):      return "Apple|iPad"
            if os_flag in (0x6, 0x7, 0x8): return "Apple|Mac"
            return "Apple|iPhone"

        if m_type in (0x0E, 0x10): return "Apple|iPhone"
        if m_type == 0x0C: return "Apple|Device"
        if m_type == 0x09: return "Apple|AirPlay"
        if m_type == 0x05: return "Apple|AirDrop"
        return "Apple|Device"

    if 6 in manuf:
        if "surface" in name: return "Microsoft|Surface"
        if "xbox"    in name: return "Microsoft|Xbox"
        return "Microsoft|Windows"

    if 117 in manuf:
        if any(k in name for k in ["galaxy watch", "gear"]): return "Samsung|Watch"
        if any(k in name for k in ["galaxy buds", "buds"])  : return "Samsung|Buds"
        if "galaxy" in name: return "Samsung|Galaxy"
        return "Samsung|Device"

    if 301 in manuf:
        if any(k in name for k in ["wh-", "wf-", "linkbuds"]): return "Sony|Headphones"
        if "xperia" in name: return "Sony|Xperia"
        return "Sony|Device"

    if 224 in manuf:
        if "pixel"  in name: return "Google|Pixel"
        if "nest"   in name: return "Google|Nest"
        return "Google|Device"

    if 343 in manuf or 911 in manuf:
        if any(k in name for k in ["redmi", "poco"]): return f"Xiaomi|{raw_name}" if raw_name else "Xiaomi|Redmi"
        if "mi band" in name or "mi smart" in name: return "Xiaomi|Mi Band"
        if "buds"    in name: return "Xiaomi|Buds"
        return "Xiaomi|Device"

    if 756 in manuf:
        if "watch"   in name: return "Huawei|Watch"
        if "freebuds"in name: return "Huawei|FreeBuds"
        if "matebook"in name: return "Huawei|MateBook"
        return "Huawei|Device"

    if 1441 in manuf:
        if "oneplus" in name: return "OnePlus|Device"
        if "enco"    in name: return "OPPO|Enco"
        return "OPPO|Device"

    if 1521 in manuf:
        return "Vivo|Device"

    hint = manufacturer_type_hint(manuf, raw_name)
    if hint:
        return hint

    hint = appearance_type_hint(device, adv_data)
    if hint:
        return hint

    hint = service_type_hint(adv_data, raw_name)
    if hint:
        return hint

    if "iphone"  in name: return "Apple|iPhone"
    if "ipad"    in name: return "Apple|iPad"
    if "macbook" in name: return "Apple|MacBook"
    if "airpod"  in name: return "Apple|AirPods"
    if "airtag"  in name: return "Apple|AirTag"
    if "apple"   in name: return "Apple|Device"
    if "pixel"          in name: return "Google|Pixel"
    if any(k in name for k in ["redmi", "poco"]): return f"Xiaomi|{raw_name}"
    if "xiaomi"         in name: return "Xiaomi|Device"
    if any(k in name for k in ["galaxy", "samsung"]): return "Samsung|Galaxy"
    if "huawei"         in name: return "Huawei|Device"
    if "oneplus"        in name: return "OnePlus|Device"
    if any(k in name for k in ["oppo", "reno", "find x"]): return "OPPO|Device"
    if "vivo"           in name: return "Vivo|Device"
    if any(k in name for k in ["realme", "narzo"]): return "Realme|Device"
    if "honor"          in name: return "Honor|Device"
    if "sony"           in name: return "Sony|Device"
    if "xperia"         in name: return "Sony|Xperia"

    if any(k in name for k in ["rog phone", "rog ally"]): return f"ASUS|{raw_name}" if raw_name else "ASUS|ROG"
    if any(k in name for k in ["rog ", "rog_", "republic of gamers"]): return "ASUS|ROG"
    if any(k in name for k in ["tuf gaming", "tuf-", "tuf_"]): return "ASUS|TUF"
    if any(k in name for k in ["zenbook", "zen book"]): return "ASUS|ZenBook"
    if any(k in name for k in ["vivobook", "vivo book"]): return "ASUS|VivoBook"
    if any(k in name for k in ["proart", "pro art"]): return "ASUS|ProArt"
    if any(k in name for k in ["expertbook", "expert book"]): return "ASUS|ExpertBook"
    if any(k in name for k in ["asus", "asustek"]): return "ASUS|Device"

    if any(k in name for k in ["thinkpad x", "thinkpad t", "thinkpad e", "thinkpad l", "thinkpad p"]):
        for series in ["x1", "x13", "x14", "t14", "t16", "e14", "e15", "l14", "l15", "p14", "p16"]:
            if series in name: return f"Lenovo|ThinkPad {series.upper()}"
        return "Lenovo|ThinkPad"
    if "thinkbook" in name: return "Lenovo|ThinkBook"
    if "ideapad"   in name: return "Lenovo|IdeaPad"
    if "yoga"      in name: return "Lenovo|Yoga"
    if "legion"    in name: return "Lenovo|Legion"
    if "loq"       in name: return "Lenovo|LOQ"
    if "lenovo"    in name: return "Lenovo|Device"

    if "xps"           in name: return "Dell|XPS"
    if "alienware"     in name: return "Dell|Alienware"
    if "inspiron"      in name: return "Dell|Inspiron"
    if "latitude"      in name: return "Dell|Latitude"
    if "precision"     in name: return "Dell|Precision"
    if "vostro"        in name: return "Dell|Vostro"
    if "g15"           in name: return "Dell|G15"
    if "dell"          in name: return "Dell|Device"

    if "spectre"       in name: return "HP|Spectre"
    if "envy"          in name: return "HP|Envy"
    if "omen"          in name: return "HP|Omen"
    if "pavilion"      in name: return "HP|Pavilion"
    if "elitebook"     in name: return "HP|EliteBook"
    if "probook"       in name: return "HP|ProBook"
    if "zbook"         in name: return "HP|ZBook"
    if "victus"        in name: return "HP|Victus"
    if any(k in name for k in ["hp ", "hp_"]): return "HP|Device"

    if "predator"      in name: return "Acer|Predator"
    if "nitro"         in name: return "Acer|Nitro"
    if "swift"         in name: return "Acer|Swift"
    if "aspire"        in name: return "Acer|Aspire"
    if "spin"          in name: return "Acer|Spin"
    if "chromebook"    in name: return "Acer|Chromebook"
    if "acer"          in name: return "Acer|Device"

    if any(k in name for k in ["msi ge", "msi gt", "msi gs", "msi gf", "msi gp"]): return "MSI|Gaming"
    if "raider"        in name: return "MSI|Raider"
    if "stealth"       in name: return "MSI|Stealth"
    if "katana"        in name: return "MSI|Katana"
    if "pulse"         in name: return "MSI|Pulse"
    if "creator"       in name: return "MSI|Creator"
    if "prestige"      in name: return "MSI|Prestige"
    if any(k in name for k in ["msi ", "msi_"]): return "MSI|Device"

    if "razer blade"   in name: return "Razer|Blade"
    if "razer"         in name: return "Razer|Device"

    if "galaxy book"   in name: return "Samsung|Galaxy Book"
    if "matebook"      in name: return "Huawei|MateBook"

    if "surface pro"   in name: return "Microsoft|Surface Pro"
    if "surface laptop"in name: return "Microsoft|Surface Laptop"
    if "surface book"  in name: return "Microsoft|Surface Book"
    if "surface go"    in name: return "Microsoft|Surface Go"
    if "surface"       in name: return "Microsoft|Surface"

    if any(k in name for k in ["desktop", "pc-", "-pc", "_pc"]): return "Generic|Desktop"
    if "laptop"        in name: return "Generic|Laptop"

    if any(k in name for k in ["airpod", "earpod"])  : return "Apple|AirPods"
    if any(k in name for k in ["wh-", "wf-", "linkbuds"]): return "Sony|Headphones"
    if any(k in name for k in ["buds", "earbuds"])   : return "Generic|Earbuds"
    if any(k in name for k in ["headphone", "headset"]): return "Generic|Headphones"
    if any(k in name for k in ["speaker", "soundbar"]): return "Generic|Speaker"
    if any(k in name for k in ["jbl", "bose", "beats", "jabra", "sennheiser"]):
        brand = next(k for k in ["JBL","Bose","Beats","Jabra","Sennheiser"] if k.lower() in name)
        return f"{brand}|Audio"

    if any(k in name for k in ["watch", "band", "fitness", "garmin", "fitbit", "polar"]): return "Generic|Wearable"
    if any(k in name for k in ["keyboard", "mouse", "trackpad"]): return "Generic|KB/Mouse"
    if any(k in name for k in ["tv", "smart tv", "android tv"]): return "Generic|SmartTV"
    if any(k in name for k in ["nest", "chromecast"])           : return "Google|Home"
    if any(k in name for k in ["echo", "alexa", "kindle"])      : return "Amazon|Device"
    if any(k in name for k in ["mi home", "yeelight", "aqara"]) : return "Xiaomi|Home"
    if any(k in name for k in ["car", "auto", "bmw", "tesla", "ford"]): return "Vehicle|BT"

    hint = mac_type_hint(address, raw_name)
    if hint:
        return hint

    kind = peripheral_kind_from_name(raw_name)
    return f"Generic|{kind_or_default(kind, 'BLE Device')}"

def remember_device(device, advertisement_data):
    rssi = getattr(advertisement_data, "rssi", None)
    if rssi is None or rssi < -100:
        return
    address = getattr(device, "address", None)
    if not address:
        return

    # Check blacklist
    with blacklist_lock:
        if address in device_blacklist:
            return

    label    = device_label(device, advertisement_data)
    adv_name = device_display_name(device, advertisement_data) or "(unnamed)"
    classification = classify_device(device, advertisement_data)
    dev_type = classification["type"]
    warning  = classification["warning"]

    # Track RSSI history
    now_mono = time.monotonic()
    with rssi_history_lock:
        if address not in rssi_history:
            rssi_history[address] = []
        rssi_history[address].append((now_mono, int(rssi)))
        # Keep last 120 readings (2 min at 1/sec)
        if len(rssi_history[address]) > 120:
            rssi_history[address] = rssi_history[address][-120:]

    with devices_lock:
        is_new = address not in devices
        devices[address] = {
            "name"   : label,
            "device_name": adv_name,
            "rssi"   : int(rssi),
            "mac"    : address,
            "type"   : dev_type,
            "warning": warning,
            "confidence": classification["confidence"],
            "source": classification["source"],
            "company_ids": classification["company_ids"],
            "services": classification["services"],
            "seen_at": time.monotonic(),
            "randomized_mac": is_randomized_mac(address),
        }

    if is_new:
        warn_tag = f"  [{warning['level']} {warning['label']}]" if warning else ""
        log_event(
            f"NEW  {dev_type:<18} {adv_name:<18} {address}  "
            f"{rssi} dBm  C={classification['confidence']:02d} "
            f"SRC={classification['source']}{warn_tag}",
            mode="BLE",
        )
        
        # Play alarm sound for high-confidence alerts
        if warning and warning.get("confidence", 0) >= 80 and warning["level"] == "ALERT":
            play_alarm_sound()
            if cmd_ready:
                print(f"  🚨 ALARM TRIGGERED: {adv_name} ({address})")
        
        # 添加到警告隊列以供 GUI 彈窗顯示 (只有高置信度警告才會彈窗)
        # ALERT: 需要 >= 80% 置信度; DEV: 需要 >= 75% 置信度
        if warning:
            warn_conf = warning.get("confidence", 0)
            min_confidence = 80 if warning["level"] == "ALERT" else 75
            
            if warn_conf >= min_confidence:
                with warning_queue_lock:
                    warning_queue.append({
                        "name": adv_name,
                        "type": dev_type,
                        "warning": warning,
                        "mac": address,
                        "rssi": rssi,
                        "confidence": classification["confidence"],
                    })
                if cmd_ready and _active_mode() == "BLE":
                    alert_emoji = "🚨" if warning["level"] == "ALERT" else "⚠️"
                    conf_indicator = "✓✓✓" if warn_conf >= 90 else "✓✓" if warn_conf >= 80 else "✓"
                    print(f"{alert_emoji} [{warning['level']}] {warning['label']}: {adv_name} ({address}) [{warn_conf}% {conf_indicator}]")
            elif cmd_ready and _active_mode() == "BLE" and warn_conf >= 50:
                alert_emoji = "ℹ️"
                print(f"{alert_emoji} [POTENTIAL] {warning['label']}: {adv_name} ({address}) [{warn_conf}% - low confidence]")


async def scan_forever():
    if BleakScanner is None:
        raise RuntimeError("The 'bleak' package is missing. Please run: python -m pip install bleak")
    scanner = BleakScanner(detection_callback=remember_device)
    await scanner.start()
    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await scanner.stop()

def ble_scan_worker():
    global scanner_error
    if BleakScanner is None:
        scanner_error = "The 'bleak' package is missing. Please run: python -m pip install bleak"
        return
    retry_delay = 3
    while True:
        try:
            scanner_error = None
            asyncio.run(scan_forever())
        except Exception as exc:
            scanner_error = (
                f"BLE scan error: {exc}. Retrying in {retry_delay}s. "
                "Check Bluetooth is ON, no other scanner is using the adapter, "
                "and Windows Bluetooth permissions are enabled."
            )
            log_event(scanner_error, mode="BLE")
            time.sleep(retry_delay)
            retry_delay = min(30, retry_delay + 3)

def lerp_color(t, dark="#050805", bright="#7cff8b"):
    def parse(h):
        h = h.lstrip("#")
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r0, g0, b0 = parse(dark)
    r1, g1, b1 = parse(bright)
    r = int(r0 + (r1 - r0) * t)
    g = int(g0 + (g1 - g0) * t)
    b = int(b0 + (b1 - b0) * t)
    return f"#{r:02x}{g:02x}{b:02x}"

# =================== Wi-Fi Scanning Functions ===================

def _run_command(cmd):
    """Run a shell command and return its stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=10,
        )
        return result.stdout or ""
    except Exception as e:
        log_event(f"Command failed ({cmd}): {e}", mode="WIFI")
        return ""

def scan_wifi_networks():
    """Scan available Wi-Fi networks (Windows/Linux/macOS)"""
    try:
        with wifi_lock:
            before = set(wifi_networks.keys())

        if os.name == 'nt':  # Windows
            result = _run_command(
                'netsh wlan show networks mode=bssid'
            )
            if result:
                parse_wifi_windows(result)
        else:  # Linux/macOS
            result = _run_command(
                'nmcli -t -f BSSID,SSID,CHAN,SIGNAL dev wifi list'
            )
            if result:
                parse_wifi_linux(result)
            else:
                result = _run_command(
                    '/System/Library/PrivateFrameworks/Apple80211.framework'
                    '/Versions/Current/Resources/airport -s'
                )
                if result:
                    parse_wifi_macos(result)

        with wifi_lock:
            after = set(wifi_networks.keys())
        new_nets = after - before
        lost_nets = before - after
        for ssid in new_nets:
            with wifi_lock:
                sig = wifi_networks.get(ssid, {}).get("signal", "?")
            log_event(f"NEW  Wi-Fi network: {ssid}  ({sig} dBm)", mode="WIFI")
        for ssid in lost_nets:
            log_event(f"LOST Wi-Fi network: {ssid}", mode="WIFI")

    except Exception as e:
        log_event(f"Wi-Fi scan error: {e}", mode="WIFI")

def parse_wifi_windows(output):
    """Parse Windows netsh wlan output"""
    global wifi_networks, wifi_lock
    lines = output.split('\n')
    current_ssid = None
    
    for line in lines:
        if 'SSID' in line and ':' in line:
            ssid = line.split(':', 1)[1].strip()
            if ssid:
                current_ssid = ssid
                with wifi_lock:
                    if current_ssid not in wifi_networks:
                        wifi_networks[current_ssid] = {
                            "bssid": None,
                            "channel": None,
                            "signal": -100,
                            "last_seen": time.monotonic(),
                        }
        
        if 'BSSID' in line and ':' in line and current_ssid:
            bssid = line.split(':', 1)[1].strip()
            with wifi_lock:
                if current_ssid in wifi_networks:
                    wifi_networks[current_ssid]["bssid"] = bssid
        
        if 'Signal' in line and '%' in line:
            signal = line.split(':')[1].strip()
            signal_val = int(signal.rstrip('%')) if signal.rstrip('%').isdigit() else -100
            with wifi_lock:
                if current_ssid in wifi_networks:
                    wifi_networks[current_ssid]["signal"] = signal_val

def parse_wifi_linux(output):
    """Parse Linux nmcli terse output (colon-separated: BSSID:SSID:CHAN:SIGNAL)"""
    for line in output.splitlines():
        if not line.strip():
            continue
        # nmcli -t uses ':' as delimiter; BSSID contains '\:' (escaped colons)
        # Replace escaped colons in BSSID temporarily
        parts = line.replace(r'\:', '##').split(':')
        if len(parts) >= 4:
            bssid = parts[0].replace('##', ':')
            ssid = parts[1]
            chan = parts[2]
            signal = parts[3]
            if not ssid:
                continue
            with wifi_lock:
                if ssid not in wifi_networks:
                    wifi_networks[ssid] = {}
                wifi_networks[ssid].update({
                    "bssid": bssid,
                    "channel": chan,
                    "signal": int(signal) if signal.lstrip('-').isdigit() else -100,
                    "last_seen": time.monotonic(),
                })

def parse_wifi_macos(output):
    """Parse macOS airport output"""
    global wifi_networks, wifi_lock
    lines = output.split('\n')
    for line in lines[1:]:  # Skip header
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 7:
            ssid, bssid, rssi, chan, ht, cc, sec = parts[:7]
            with wifi_lock:
                if ssid not in wifi_networks:
                    wifi_networks[ssid] = {}
                wifi_networks[ssid].update({
                    "bssid": bssid,
                    "channel": chan,
                    "signal": int(rssi) if rssi.lstrip('-').isdigit() else -100,
                    "last_seen": time.monotonic(),
                })

def wifi_scan_worker():
    """Background worker for Wi-Fi scanning"""
    while True:
        try:
            scan_wifi_networks()
            time.sleep(5)  # Scan every 5 seconds
        except Exception as e:
            log_event(f"Wi-Fi scan worker error: {e}", mode="WIFI")
            time.sleep(10)

# =================== End Wi-Fi Functions ===================

def scan_radio_channels():
    """
    Simulated radio channel scanner (UHF/VHF/FM).
    NOTE: This uses randomly generated data for demonstration purposes.
    For real RF scanning, integrate with SDR hardware (e.g. RTL-SDR via pyrtlsdr).
    """
    bands = {
        "FM": list(range(88, 108)),
        "UHF": list(range(400, 480, 5)),
        "VHF": list(range(150, 175, 5)),
    }

    try:
        with radio_lock:
            for band_name, channels in bands.items():
                for channel in channels:
                    freq_key = f"{band_name}_{channel}"
                    if freq_key not in radio_channels:
                        radio_channels[freq_key] = {
                            "band": band_name,
                            "frequency": channel,
                            "signal": -100,
                            "activity": 0,
                            "last_detected": None,
                            "simulated": True,
                        }
                    else:
                        old_activity = radio_channels[freq_key].get("activity", 0)
                        if old_activity > 0:
                            radio_channels[freq_key]["activity"] = max(0, old_activity - 0.1)

                        if random.random() < 0.2:
                            radio_channels[freq_key]["signal"] = -80 + random.randint(-20, 5)
                            radio_channels[freq_key]["activity"] = 1.0
                            radio_channels[freq_key]["last_detected"] = time.monotonic()
    except Exception as e:
        log_event(f"Radio scan error: {e}", mode="RADIO")

def radio_scan_worker():
    """Background worker for radio channel scanning"""
    while True:
        try:
            scan_radio_channels()
            time.sleep(2)  # Scan every 2 seconds for faster updates
        except Exception as e:
            log_event(f"Radio scan worker error: {e}", mode="RADIO")
            time.sleep(5)

# =================== Radar UI Class ===================
class Radar:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Super Radar")
        self.root.configure(bg=COL_BG)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.minsize(480, 480)

        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(self.root, bg=COL_BG, highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.status = tk.StringVar(value="[SYSTEM] Awaiting boot sequence...")
        tk.Label(
            self.root,
            textvariable=self.status,
            bg=COL_BG,
            fg=COL_LABEL,
            font=("Consolas", 10),
            padx=10,
            pady=6,
        ).grid(row=1, column=0, sticky="ew")

        self._fullscreen = False
        self.root.bind("<F11>", self.toggle_fullscreen)
        self.root.bind("<Escape>", self.exit_fullscreen)
        self.canvas.bind("<Button-1>", self.on_canvas_click)
        self.canvas.bind("<Button-3>", self.on_right_click)  # Right-click
        self.canvas.bind("<Motion>", self.on_mouse_move)

        # Keyboard shortcuts
        self.root.bind("<Control-e>", lambda e: self.export_devices("csv"))
        self.root.bind("<Control-E>", lambda e: self.export_devices("json"))

        self._power_hover = False
        self._mode_menu_hover = False

        self.angle = 0
        self.last_sweep_hit = {}
        self.current_device_positions = []
        self.timeline_data = []
        self.heatmap_grid = {}
        
        self.is_booting = True
        self.boot_frame = 0
        
        # Mode switching and cooldown system
        self.mode_var = tk.StringVar(value="BLE")
        self.mode_cooldown_seconds = 5.0
        self.display_reboot_until = 0.0
        self.last_mode_switch_time = time.monotonic() - self.mode_cooldown_seconds
        self.mode_options = [
            ("BLE", "BLE Radar"),
            ("WIFI", "Wi-Fi Networks"),
            ("HEAT", "Heatmap"),
            ("TIME", "Timeline"),
            ("RADIO", "Radio Scanner")
        ]
        self.mode_menu_open = False

        # Double-click detection for BLE connection
        self._last_click_time = 0.0
        self._last_click_device = None
        self._dbl_click_threshold = 0.35  # seconds

        # BLE connection state
        self._ble_connecting = False
        self._ble_client = None
        self._connected_device = None

        # Blacklist and RSSI tracking
        self._blacklist = set()
        self._rssi_history = {}

        # 將啟動的控制權交由 CMD 端，這裡直接啟動 40ms 循環，但不推進動畫
        self.root.after(40, self.update)

    def toggle_fullscreen(self, event=None):
        self._fullscreen = not self._fullscreen
        self.root.attributes("-fullscreen", self._fullscreen)

    def exit_fullscreen(self, event=None):
        self._fullscreen = False
        self.root.attributes("-fullscreen", False)

    def on_canvas_click(self, event):
        self.on_canvas_click_override(event)

    def on_right_click(self, event):
        """Handle right-click on device for blacklist and RSSI graph."""
        if self.is_booting or time.monotonic() < self.display_reboot_until:
            return
        for x, y, data in self.current_device_positions:
            if math.hypot(event.x - x, event.y - y) < 15:
                # Create context menu
                menu = tk.Menu(self.root, tearoff=0)
                mac = data.get("mac", "")
                name = data.get("name", mac[:8])

                # Toggle blacklist
                if blacklist_is_blocked(mac):
                    menu.add_command(
                        label=f"Remove from Blacklist: {name}",
                        command=lambda: self.toggle_blacklist_device(data)
                    )
                else:
                    menu.add_command(
                        label=f"Add to Blacklist: {name}",
                        command=lambda: self.toggle_blacklist_device(data)
                    )

                menu.add_separator()

                # Show RSSI graph
                menu.add_command(
                    label="Show RSSI History",
                    command=lambda: self.show_rssi_graph(mac)
                )

                menu.add_separator()

                # Export single device info
                menu.add_command(
                    label="Copy Device Info",
                    command=lambda: self._copy_device_info(data)
                )

                try:
                    menu.tk_popup(event.x_root, event.y_root)
                finally:
                    menu.grab_release()
                break

    def _copy_device_info(self, data):
        """Copy device info to clipboard with full details."""
        warning = data.get("warning")
        warning_line = (
            f"\nWarning: {warning['level']} - {warning['message']}"
            if warning else ""
        )

        # Get GPS location
        lat, lon, city = get_gps_location()
        gps_line = f"Location: {lat:.6f}, {lon:.6f} ({city})" if lat else "Location: Unknown"

        # Get scan time
        seen_ago = time.monotonic() - data.get("seen_at", time.monotonic())
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Extract manufacturer from company_ids
        company_ids = data.get('company_ids', '')
        manufacturer = company_ids.split(':')[1].strip() if ':' in company_ids else 'Unknown'

        info = (
            f"========== DEVICE INFO ==========\n"
            f"Device Name: {data.get('device_name', data['name'])}\n"
            f"Display Name: {data['name']}\n"
            f"Type: {data['type']}\n"
            f"Manufacturer: {manufacturer}\n"
            f"\n---------- CONNECTION ----------\n"
            f"MAC Address: {data['mac']}\n"
            f"Randomized MAC: {'Yes' if data.get('randomized_mac') else 'No'}\n"
            f"Signal Strength: {data['rssi']} dBm\n"
            f"RSSI Distance: ~{self._estimate_distance(data['rssi'])}m\n"
            f"\n---------- CLASSIFICATION ----------\n"
            f"Confidence: {data.get('confidence', 0)}%\n"
            f"Class Source: {data.get('source', 'n/a')}\n"
            f"Company IDs: {company_ids or 'n/a'}\n"
            f"Services: {data.get('services') or 'n/a'}\n"
            f"\n---------- SCANNER INFO ----------\n"
            f"Scan Time: {scan_time}\n"
            f"{gps_line}\n"
            f"{warning_line}\n"
            f"=================================="
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(info)
        self.status.set(f"COPIED: {data['name']} (Full Details)")

    def _estimate_distance(self, rssi):
        """Estimate distance from RSSI (rough approximation)."""
        if rssi >= -50:
            return "< 1"
        elif rssi >= -60:
            return "1-2"
        elif rssi >= -70:
            return "2-5"
        elif rssi >= -80:
            return "5-10"
        elif rssi >= -90:
            return "10-20"
        else:
            return "> 20"

    def _power_btn_pos(self, w):
        return w - 30, 30, 14

    def on_mouse_move(self, event):
        w = self.canvas.winfo_width()
        
        # Check dropdown hover
        dx, dy, dw, dh = self._mode_dropdown_rect(w)
        dropdown_hover = dx <= event.x <= dx + dw and dy <= event.y <= dy + dh
        
        # Check power button hover
        bx, by, br = self._power_btn_pos(w)
        power_hover = math.hypot(event.x - bx, event.y - by) <= br + 4
        
        # Set cursor based on what we're hovering over
        if dropdown_hover or power_hover:
            if dropdown_hover != self._mode_menu_hover or power_hover != self._power_hover:
                self._mode_menu_hover = dropdown_hover
                self._power_hover = power_hover
                self.canvas.config(cursor="hand2")
        else:
            self._mode_menu_hover = False
            self._power_hover = False
            self.canvas.config(cursor="")

    def mode_cooldown_remaining(self):
        elapsed = time.monotonic() - self.last_mode_switch_time
        return max(0.0, self.mode_cooldown_seconds - elapsed)

    def on_mode_change(self, new_mode):
        """Switch modes instantly, then show a Minecraft-style cooldown overlay."""
        if new_mode == self.mode_var.get():
            return
        
        remaining = self.mode_cooldown_remaining()
        if remaining > 0:
            self.status.set(f"MODE COOLDOWN: {remaining:.1f}s remaining")
            return

        mode_descriptions = {
            "BLE":   "BLE (Bluetooth Low Energy) Scan",
            "WIFI":  "Wi-Fi Networks Scan",
            "HEAT":  "Signal Heatmap",
            "TIME":  "Timeline View",
            "RADIO": "Radio Channel Scanner (UHF/VHF/FM)",
        }
        mode_desc = mode_descriptions.get(new_mode, new_mode)
        print(f"\n{'='*55}")
        print(f"  >>> MODE: {mode_desc}")
        print(f"{'='*55}")
        log_headers = {
            "BLE":   "  LIVE BLE SCAN  (NEW = detected / LOST = expired)",
            "WIFI":  "  LIVE WI-FI SCAN  (network discovery events)",
            "HEAT":  "  HEATMAP MODE  (signal strength analysis)",
            "TIME":  "  TIMELINE MODE  (device discovery log)",
            "RADIO": "  RADIO SCANNER  (simulated channel activity)",
        }
        header = log_headers.get(new_mode, "")
        if header:
            print(f"  {'─'*51}")
            print(header)
            print(f"  {'─'*51}")
        print()

        self.mode_var.set(new_mode)
        with mode_lock:
            global current_mode
            current_mode = new_mode

        self.timeline_data = []
        self.heatmap_grid = {}
        self.current_device_positions = []
        self.last_mode_switch_time = time.monotonic()
        self.display_reboot_until = time.monotonic() + 0.42
        self.mode_menu_open = False

        if new_mode == "BLE":
            start_sound()
        else:
            stop_sound()

        self.canvas.delete("all")
        self.status.set(f"MODE SWITCHED: {new_mode}")

    def _mode_dropdown_rect(self, w):
        """Get position of mode dropdown button"""
        dropdown_w = 180
        dropdown_h = 24
        dropdown_x = w - dropdown_w - 50  # To the left of power button
        dropdown_y = 8
        return dropdown_x, dropdown_y, dropdown_w, dropdown_h
    
    def on_canvas_click_override(self, event):
        """Override click handling to include dropdown menu"""
        w = self.canvas.winfo_width()
        
        # Check dropdown menu click
        dx, dy, dw, dh = self._mode_dropdown_rect(w)
        if dx <= event.x <= dx + dw and dy <= event.y <= dy + dh:
            self.mode_menu_open = not self.mode_menu_open
            return
        
        # Check mode menu item click
        if self.mode_menu_open:
            for i, (mode_id, mode_label) in enumerate(self.mode_options):
                item_y = dy + dh + 3 + i * 22
                if dx <= event.x <= dx + dw and item_y <= event.y <= item_y + 20:
                    self.on_mode_change(mode_id)
                    return
        
        # Check power button
        bx, by, br = self._power_btn_pos(w)
        if math.hypot(event.x - bx, event.y - by) <= br + 4:
            self.close()
            return
        
        # Original device click handling
        if self.is_booting or time.monotonic() < self.display_reboot_until:
            return
        
        for x, y, data in self.current_device_positions:
            if math.hypot(event.x - x, event.y - y) < 15:
                now = time.monotonic()
                mac = data.get("mac", "")

                # Double-click detection
                if (now - self._last_click_time < self._dbl_click_threshold
                        and self._last_click_device == mac):
                    self._last_click_time = 0.0
                    self._last_click_device = None
                    self.ble_connect_device(data)
                    return

                self._last_click_time = now
                self._last_click_device = mac

                # Single click – copy info (existing behavior)
                warning = data.get("warning")
                warning_line = (
                    f"\nWarning: {warning['level']} - {warning['message']}"
                    if warning else ""
                )
                info = (
                    f"Type: {data['type']}\n"
                    f"Confidence: {data.get('confidence', 0)}%\n"
                    f"Class Source: {data.get('source', 'n/a')}\n"
                    f"Device Name: {data.get('device_name', data['name'])}\n"
                    f"Display Name: {data['name']}\n"
                    f"MAC: {data['mac']}\n"
                    f"Randomized MAC: {'Yes' if data.get('randomized_mac') else 'No'}\n"
                    f"Company IDs: {data.get('company_ids') or 'n/a'}\n"
                    f"Services: {data.get('services') or 'n/a'}\n"
                    f"RSSI: {data['rssi']} dBm"
                    f"{warning_line}"
                )
                self.root.clipboard_clear()
                self.root.clipboard_append(info)
                old_status = self.status.get()
                prefix = f"{warning['level']} " if warning else ""
                self.status.set(f"{prefix}COPIED: {data['name']} [{data['type']}]")
                self.root.after(2000, lambda: self.status.set(old_status))
                break

    def toggle_blacklist_device(self, data):
        """Toggle blacklist status for a device."""
        mac = data.get("mac", "")
        if not mac:
            return
        if blacklist_is_blocked(mac):
            blacklist_remove(mac)
            self.show_toast(f"Removed from blacklist: {data['name']}", "info")
        else:
            blacklist_add(mac)
            # Remove from active devices if blacklisted
            with devices_lock:
                devices.pop(mac, None)
            self.show_toast(f"Blacklisted: {data['name']}", "warning")

    def show_rssi_graph(self, mac):
        """Display RSSI history graph in a popup window."""
        with rssi_history_lock:
            hist = rssi_history.get(mac, [])
        if not hist:
            self.status.set(f"RSSI: No history for {mac}")
            return

        # Create popup window
        win = tk.Toplevel(self.root)
        win.title(f"RSSI History - {mac}")
        win.configure(bg=COL_BG)
        win.geometry("400x200")
        win.resizable(False, False)

        # Get recent values
        recent = hist[-30:]
        values = [r for _, r in recent]
        min_r = min(values)
        max_r = max(values)
        range_r = max_r - min_r if max_r != min_r else 1

        # Draw graph
        canvas = tk.Canvas(win, bg=COL_BG, highlightthickness=0)
        canvas.pack(fill="both", expand=True, padx=10, pady=10)

        # Title
        canvas.create_text(10, 10, text=f"Signal Strength (last {len(recent)} readings)",
                          fill=COL_LABEL, anchor="nw", font=("Consolas", 9, "bold"))

        # Draw bars
        bar_w = max(4, (360) // len(recent))
        x_start = 10
        y_top = 40
        y_bottom = 150
        y_range = y_bottom - y_top

        for i, r in enumerate(values):
            x = x_start + i * (bar_w + 2)
            h = max(2, int((r - min_r) / range_r * y_range))
            color = COL_HIT if r > -60 else COL_WARN if r > -80 else COL_ALERT
            canvas.create_rectangle(x, y_bottom - h, x + bar_w, y_bottom, fill=color, outline="")

        # Labels
        canvas.create_text(10, y_bottom + 10, text=f"{min_r} dBm",
                          fill=COL_DIM_RING, anchor="nw", font=("Consolas", 8))
        canvas.create_text(350, y_bottom + 10, text=f"{max_r} dBm",
                          fill=COL_DIM_RING, anchor="ne", font=("Consolas", 8))
        canvas.create_text(180, y_bottom + 10, text=f"Avg: {sum(values)//len(values)} dBm",
                          fill=COL_TEXT, anchor="n", font=("Consolas", 8))

    def export_devices(self, fmt="csv"):
        """Export devices to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "csv":
            filepath = APP_DIR / f"radar_export_{timestamp}.csv"
            ok, msg = export_csv(filepath)
        else:
            filepath = APP_DIR / f"radar_export_{timestamp}.json"
            ok, msg = export_json(filepath)
        if ok:
            self.show_toast(f"Exported {filepath.name}", "success")
        else:
            self.show_toast(f"Export failed: {msg}", "error")
        self.status.set(f"EXPORT: {msg}")

    def close(self):
        self._ble_disconnect()
        stop_sound()
        self.root.destroy()

    def _ble_disconnect(self):
        """Disconnect any active BLE connection."""
        if self._ble_client and self._ble_client.is_connected:
            try:
                self._ble_client.disconnect()
            except Exception:
                pass
        self._ble_client = None
        self._connected_device = None

    def show_toast(self, message, msg_type="info", duration=3):
        """Show a toast notification with slide-in and fade-out animation."""
        colors = {
            "info": COL_SWEEP,
            "success": "#00ff00",
            "warning": COL_WARN,
            "error": COL_ALERT,
        }
        bg_colors = {
            "info": "#0a2a0a",
            "success": "#0a2a0a",
            "warning": "#2a2a0a",
            "error": "#2a0a0a",
        }
        color = colors.get(msg_type, COL_SWEEP)
        bg = bg_colors.get(msg_type, "#0a0a0a")

        # Create toast frame (start hidden at bottom)
        toast = tk.Frame(self.root, bg=bg, bd=1, relief="solid")
        
        # Left color bar
        tk.Frame(toast, bg=color, width=4).pack(side="left", fill="y")

        # Message
        tk.Label(toast, text=f"  {message}  ", bg=bg, fg=color,
                font=("Consolas", 9), padx=8, pady=6).pack()

        # Get target position
        self.root.update_idletasks()
        target_y = self.root.winfo_height() - 60
        toast.place(relx=0.5, y=self.root.winfo_height() + 50, anchor="s")

        # Slide-in animation
        current_y = self.root.winfo_height() + 50
        def slide_in():
            nonlocal current_y
            if current_y > target_y:
                current_y -= 8
                toast.place(relx=0.5, y=current_y, anchor="s")
                self.root.after(10, slide_in)
        slide_in()

        # Fade-out and remove
        def fade_out():
            toast.configure(bg="#000000")
            for widget in toast.winfo_children():
                try:
                    widget.configure(bg="#000000")
                except:
                    pass
            self.root.after(100, toast.destroy)

        self.root.after(duration * 1000, fade_out)

    def ble_connect_device(self, data):
        """Initiate BLE connection to a device on double-click."""
        if BleakClient is None:
            self.show_toast("bleak library not available", "error")
            return

        if self._ble_connecting:
            self.show_toast("Connection already in progress...", "warning")
            return

        mac = data.get("mac", "")
        name = data.get("name", mac)
        if not mac:
            return

        # If already connected to this device, disconnect
        if self._connected_device == mac:
            self.show_toast(f"Disconnecting from {name}...", "info")
            threading.Thread(target=self._do_disconnect, daemon=True).start()
            return

        self._ble_connecting = True
        self.show_toast(f"Connecting to {name}...", "info")
        threading.Thread(
            target=self._do_connect, args=(mac, name), daemon=True
        ).start()

    def _do_connect(self, mac, name):
        """Background thread: connect to BLE device and discover services."""
        try:
            self._ble_disconnect()
            client = BleakClient(mac, timeout=10.0)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(client.connect())
            loop.close()

            self._ble_client = client
            self._connected_device = mac
            services = list(client.services.keys()) if client.services else []
            svc_count = len(services)

            self.root.after(0, lambda: self.show_toast(
                f"Connected to {name} ({svc_count} services)", "success"
            ))
            self.root.after(0, lambda: self.status.set(
                f"CONNECTED: {name} | {svc_count} service(s) discovered"
            ))
            log_event(f"BLE CONNECTED to {name} [{mac}] — {svc_count} services")
        except Exception as e:
            self.root.after(0, lambda: self.show_toast(
                f"Connection failed: {e}", "error"
            ))
            self.root.after(0, lambda: self.status.set(
                f"CONNECT FAILED: {name} — {e}"
            ))
            log_event(f"BLE connect failed for {name} [{mac}]: {e}")
        finally:
            self._ble_connecting = False

    def _do_disconnect(self):
        """Background thread: disconnect current BLE device."""
        try:
            if self._ble_client and self._ble_client.is_connected:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._ble_client.disconnect())
                loop.close()
            name = self._connected_device or "device"
            self._ble_client = None
            self._connected_device = None
            self.root.after(0, lambda: self.show_toast(f"Disconnected from {name}", "info"))
            self.root.after(0, lambda: self.status.set(f"DISCONNECTED: {name}"))
            log_event(f"BLE DISCONNECTED from {name}")
        except Exception as e:
            self._ble_client = None
            self._connected_device = None
            self.root.after(0, lambda: self.show_toast(f"Disconnect error: {e}", "error"))
            self.root.after(0, lambda: self.status.set(f"DISCONNECT ERROR: {e}"))

    def dims(self):
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 2 or h < 2: w, h = 640, 640
        size  = min(w, h)
        return w, h, w // 2, h // 2, size // 2 - 20

    def rssi_to_radius(self, rssi, max_r):
        clamped  = max(-95, min(-35, rssi))
        strength = (clamped + 95) / 60
        return 35 + (1 - strength) * (max_r - 35)

    def angle_for_address(self, address):
        return hash(address) % 360

    def sweep_hits(self, target_angle):
        diff = abs((self.angle - target_angle + 180) % 360 - 180)
        return diff < 7

    def cleanup_devices(self):
        now = time.monotonic()
        with devices_lock:
            expired = [addr for addr, data in devices.items() if now - data["seen_at"] > DEVICE_TTL_SECONDS]
            for addr in expired:
                data = devices.pop(addr, None)
                self.last_sweep_hit.pop(addr, None)
                if data:
                    log_event(f"LOST {data['name']:<14} {addr}  {data['type']}", mode="BLE")

    def snapshot_devices(self):
        with devices_lock:
            return dict(devices)

    def draw_boot_sequence(self, w, h, cx, cy):
        self.canvas.delete("all")
        
        # 1. 如果終端機的 5 秒還沒倒數完，不畫任何東西 (保持純黑畫面待機)
        if not start_boot_event.is_set():
            return
            
        # 2. 控制動畫幀推進 (當到達第 55 幀，強制停下來等待終端機打完字)
        if self.boot_frame < 55 or cmd_ready:
            self.boot_frame += 1
        
        # 3. 根據目前的幀數繪製畫面
        term_text = []
        if self.boot_frame > 5: term_text.append("> WAKING UP TACTICAL NEURAL NET...")
        if self.boot_frame > 12: term_text.append("> CHARGING PHOTON RELAY...")
        if self.boot_frame > 18: term_text.append("> INITIATING BLE SENSOR ARRAY...")
        if self.boot_frame > 24: term_text.append("> CALIBRATING QUANTUM SENSORS...")
        if self.boot_frame > 30: term_text.append("> OVERRIDING SECURITY PROTOCOLS... [OK]")
        if self.boot_frame > 36: term_text.append("> DECRYPTING MAC ADDRESSES...")
        if self.boot_frame > 42: term_text.append("> SYNCHRONIZING TEMPORAL MATRIX...")
        if self.boot_frame > 48: term_text.append("> ENGAGING RADAR SWEEP...")

        # 第 55 幀起：呈現閃爍綠色的系統上線畫面，直到終端機放行 cmd_ready=True
        if 55 <= self.boot_frame < 65:
            self.canvas.create_rectangle(0, 0, w, h, fill=COL_DIM_RING, outline="")
            self.canvas.create_text(cx, cy, text="[ SYSTEM ONLINE ]", fill=COL_BG, font=("Consolas", 32, "bold"))
            self.status.set("SYSTEM UPLINK ESTABLISHED.")
        elif self.boot_frame >= 65:
            # 動畫結束，進入正常雷達
            self.is_booting = False
            start_sound() 
        else:
            # 55 幀以前的雷達讀取特效
            ty = cy - 80
            for line in term_text:
                self.canvas.create_text(cx - 180, ty, text=line, fill=COL_TEXT, anchor="w", font=("Consolas", 10, "bold"))
                ty += 20
                
            arc_r = 30
            self.canvas.create_arc(cx-arc_r, cy+40, cx+arc_r, cy+100, start=self.boot_frame*18%360, extent=70, outline=COL_SWEEP, width=2, style=tk.ARC)
            self.canvas.create_arc(cx-arc_r, cy+40, cx+arc_r, cy+100, start=(self.boot_frame*18+180)%360, extent=70, outline=COL_SWEEP, width=2, style=tk.ARC)
            
            hex_noise = f"0x{hash(self.boot_frame) % 0xFFFFFF:06X}"
            self.canvas.create_text(cx, cy + 130, text=f"MEM_ALLOC: {hex_noise}", fill=COL_GRID_DIM, font=("Consolas", 9))
            self.status.set(f"BOOT SEQUENCE PROGRESS: {min(100, int((self.boot_frame/55)*100))}%")

    def draw_grid(self, cx, cy, max_r):
        for frac, label in RINGS:
            r = int(max_r * frac)
            self.canvas.create_oval(cx - r, cy - r, cx + r, cy + r, outline=COL_GRID)
            self.canvas.create_text(cx + 4, cy - r + 10, text=label, fill=COL_DIM_RING, font=("Consolas", 8), anchor="w")

        self.canvas.create_line(cx, cy - max_r - 10, cx, cy + max_r + 10, fill=COL_GRID)
        self.canvas.create_line(cx - max_r - 10, cy, cx + max_r + 10, cy, fill=COL_GRID)

        for deg in range(0, 360, 30):
            rad = math.radians(deg)
            x1, y1 = cx + math.cos(rad) * (max_r * 0.90), cy + math.sin(rad) * (max_r * 0.90)
            x2, y2 = cx + math.cos(rad) * max_r, cy + math.sin(rad) * max_r
            self.canvas.create_line(x1, y1, x2, y2, fill=COL_GRID_DIM)

    def draw_sweep(self, cx, cy, max_r):
        for i in range(TRAIL_STEPS):
            t = i / TRAIL_STEPS
            back_angle = (self.angle - TRAIL_SPREAD * (1 - t)) % 360
            rad = math.radians(back_angle)
            x, y = cx + math.cos(rad) * max_r, cy + math.sin(rad) * max_r
            self.canvas.create_line(cx, cy, x, y, fill=lerp_color(t * 0.55), width=1)
        
        rad = math.radians(self.angle)
        x, y = cx + math.cos(rad) * max_r, cy + math.sin(rad) * max_r
        self.canvas.create_line(cx, cy, x, y, fill=COL_SWEEP, width=2)
        self.angle = (self.angle + 3) % 360

    def draw_devices(self, snapshot, cx, cy, max_r, canvas_h):
        now = time.monotonic()
        shown = 0
        self.current_device_positions = []

        VISIBLE_SECS = 4.0  
        BRIGHT_SECS  = 0.8  

        for address, data in snapshot.items():
            angle = self.angle_for_address(address)
            
            if self.sweep_hits(angle):
                self.last_sweep_hit[address] = now

            shown += 1
            radius = self.rssi_to_radius(data["rssi"], max_r)
            rad = math.radians(angle)
            x, y = cx + math.cos(rad) * radius, cy + math.sin(rad) * radius

            self.current_device_positions.append((x, y, data))

            hit_age = now - self.last_sweep_hit.get(address, now)
            swept = address in self.last_sweep_hit

            # Connected device gets a special highlight
            is_connected = (self._connected_device == address)

            warning = data.get("warning")
            if is_connected:
                dot_color = "#00ff00"  # Bright green for connected
                p_r = 12
                pulse_color = "#00ff00"
                self.canvas.create_oval(x-p_r, y-p_r, x+p_r, y+p_r, outline=pulse_color, width=2)
            elif swept and hit_age < BRIGHT_SECS:
                dot_color = COL_HIT
                p_r = 9 + int((BRIGHT_SECS - hit_age) / BRIGHT_SECS * 8)
                pulse_color = COL_ALERT if warning and warning["level"] == "ALERT" else COL_WARN if warning else COL_SWEEP
                self.canvas.create_oval(x-p_r, y-p_r, x+p_r, y+p_r, outline=pulse_color)
            elif swept and hit_age < VISIBLE_SECS:
                dot_color = COL_FADE
            else:
                dot_color = COL_GRID_DIM
            if warning:
                dot_color = COL_ALERT if warning["level"] == "ALERT" else COL_WARN

            self.canvas.create_oval(x-5, y-5, x+5, y+5, fill=dot_color, outline="white")

            fade = max(0.15, 1.0 - hit_age / VISIBLE_SECS) if swept else 0.15
            if is_connected:
                txt_col = "#00ff00"
            else:
                txt_col = COL_ALERT if warning and warning["level"] == "ALERT" else COL_WARN if warning else lerp_color(fade * 0.6 + 0.1, dark=COL_BG, bright=COL_TEXT)
            
            tx = x + 12 if x >= cx else x - 12
            ty = y + 4  if y >= cy else y - 4
            anchor = "w" if x >= cx else "e"
            
            warn_line = f"\n{warning['level']}: {warning['label']}" if warning else ""
            conn_line = "\n[CONNECTED]" if is_connected else ""
            rand_line = " [R]" if data.get("randomized_mac") else ""
            self.canvas.create_text(
                tx, ty,
                text=f"{data['type']}\n{data.get('device_name', data['name'])}{rand_line}{warn_line}{conn_line}\n{data['mac']} | {data['rssi']} dBm",
                fill=txt_col, anchor=anchor, font=("Consolas", 8),
            )

        total = len(snapshot)
        if total > DEVICE_OVERFLOW:
            self.canvas.create_text(
                16, canvas_h - 16,
                text=f"Monitoring {total} total device(s)",
                fill=COL_DIM_RING, anchor="sw", font=("Consolas", 9, "bold"),
            )

        return shown

    def draw_right_anim(self, w, h, cx, max_r):
        px = cx + max_r + 18
        if px > w - 10:
            return

        panel_w  = w - px - 10
        if panel_w < 30:
            return

        col_w    = 10          
        n_cols   = panel_w // col_w
        line_h   = 14
        n_rows   = h // line_h

        frame = getattr(self, "_anim_frame", 0)
        self._anim_frame = frame + 1

        if not hasattr(self, "_anim_offsets"):
            self._anim_offsets = [
                random.randint(0, n_rows) for _ in range(n_cols)
            ]
            self._anim_speeds = [
                random.choice([1, 1, 1, 2]) for _ in range(n_cols)
            ]

        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&"

        for col_i in range(n_cols):
            cx_col = px + col_i * col_w
            head   = (self._anim_offsets[col_i] + frame * self._anim_speeds[col_i] // 3) % n_rows

            for row_i in range(n_rows):
                dist = (head - row_i) % n_rows
                if dist > 12:          
                    continue

                ch = random.choice(chars)
                cy_char = row_i * line_h

                if dist == 0:          
                    color = "#ffffff"
                elif dist <= 2:        
                    color = COL_SWEEP
                elif dist <= 6:        
                    color = COL_FADE
                else:                  
                    color = COL_GRID

                self.canvas.create_text(
                    cx_col, cy_char,
                    text=ch,
                    fill=color,
                    anchor="nw",
                    font=("Consolas", 8),
                )

    def draw_info_panel(self, total, cx, cy, alerts=0, dev_warnings=0):
        global peak_devices
        with devices_lock:
            peak_devices = max(peak_devices, total)
            current_peak = peak_devices
        elapsed = int(time.monotonic() - scan_start_time)
        m, s = divmod(elapsed, 60); h, m = divmod(m, 60)

        # Get GPS location (real GPS only, no IP fallback)
        lat, lon, city = get_gps_location()
        if lat is not None:
            gps_text = f"GPS      {lat:.6f}, {lon:.6f}"
        else:
            gps_text = "GPS      No GPS signal"

        lines = [
            f"TIME     {datetime.now().strftime('%H:%M:%S')}",
            f"ELAPSED  {h:02d}:{m:02d}:{s:02d}",
            f"PEAK     {current_peak} device(s)",
            f"ALERTS   {alerts} alert / {dev_warnings} dev",
            gps_text,
            "",
            "F11 Fullscreen | ESC Exit",
        ]
        if _active_mode() == "BLE":
            lines.append("CLICK DOT TO COPY INFO")
            lines.append("RIGHT-CLICK = Blacklist | DOUBLE-CLICK = BLE Connect")
        x, y = 16, 16
        for line in lines:
            self.canvas.create_text(x, y, text=line, fill=COL_DIM_RING, anchor="nw", font=("Consolas", 9))
            y += 15

    def draw_mode_dropdown(self, w):
        """Draw the mode dropdown menu at top right"""
        dx, dy, dw, dh = self._mode_dropdown_rect(w)
        current = self.mode_var.get()
        cooldown = self.mode_cooldown_remaining()
        cooldown_frac = cooldown / self.mode_cooldown_seconds if self.mode_cooldown_seconds else 0.0
        
        # Find current mode label
        current_label = next((label for mid, label in self.mode_options if mid == current), "BLE")
        
        # Main dropdown button
        hover = self._mode_menu_hover
        btn_color = COL_SWEEP if hover else COL_GRID
        text_color = COL_BG if hover else COL_TEXT
        
        self.canvas.create_rectangle(dx, dy, dx + dw, dy + dh, fill=btn_color, outline=COL_TEXT, width=1)
        self.canvas.create_text(dx + dw // 2, dy + dh // 2, text=current_label + " ▼", 
                               fill=text_color, font=("Consolas", 8, "bold"), anchor="center")
        self.draw_mode_cooldown_overlay(dx, dy, dw, dh, cooldown_frac)
        
        # Dropdown menu
        if self.mode_menu_open:
            for i, (mode_id, mode_label) in enumerate(self.mode_options):
                item_y = dy + dh + 3 + i * 22
                is_current = mode_id == current
                item_bg = COL_SWEEP if is_current else COL_GRID_DIM
                self.canvas.create_rectangle(dx, item_y, dx + dw, item_y + 20,
                                            fill=item_bg, outline=COL_GRID, width=1)
                self.canvas.create_text(dx + dw // 2, item_y + 10, text=mode_label,
                                       fill=COL_BG if is_current else COL_TEXT, 
                                       font=("Consolas", 8), anchor="center")
                if cooldown > 0 and not is_current:
                    self.draw_mode_cooldown_overlay(dx, item_y, dw, 20, cooldown_frac)

    def draw_mode_cooldown_overlay(self, x, y, w, h, fraction):
        """Draw a Minecraft-inventory style cooldown shade over a mode button."""
        if fraction <= 0:
            return

        shade_h = max(1, int(h * min(1.0, fraction)))
        shade_y = y + h - shade_h
        self.canvas.create_rectangle(
            x, shade_y, x + w, shade_y + shade_h,
            fill=COL_BG, outline="", stipple="gray50",
        )
        sweep_y = shade_y
        self.canvas.create_line(x, sweep_y, x + w, sweep_y, fill=COL_WARN, width=2)

    def draw_display_reboot(self, w, h, cx, cy):
        """Momentarily blank the display so mode changes feel like a clean reboot."""
        remaining = self.display_reboot_until - time.monotonic()
        if remaining <= 0:
            return False

        self.canvas.delete("all")
        phase = max(0.0, min(1.0, remaining / 0.42))
        bar_w = int(w * (1.0 - phase))
        self.canvas.create_rectangle(0, 0, w, h, fill=COL_BG, outline="")
        self.canvas.create_text(
            cx, cy - 16,
            text="DISPLAY BUS RESET",
            fill=COL_SWEEP,
            font=("Consolas", 14, "bold"),
        )
        self.canvas.create_rectangle(cx - 120, cy + 12, cx + 120, cy + 22, outline=COL_GRID)
        self.canvas.create_rectangle(cx - 120, cy + 12, cx - 120 + min(240, bar_w // 3), cy + 22, fill=COL_SWEEP, outline="")
        return True

    def draw_shutdown_button(self, w):
        bx, by, br = self._power_btn_pos(w)
        hover = self._power_hover

        ring_color    = "#ff4444" if hover else "#1a0a0a"
        outline_color = "#ff4444" if hover else "#7a2a2a"
        self.canvas.create_oval(
            bx - br, by - br, bx + br, by + br,
            fill=ring_color, outline=outline_color, width=1,
        )

        arc_col = "#ffffff" if hover else "#cc4444"
        arc_r   = br - 4

        self.canvas.create_arc(
            bx - arc_r, by - arc_r, bx + arc_r, by + arc_r,
            start=120, extent=300,
            outline=arc_col, width=2, style=tk.ARC,
        )

        self.canvas.create_line(
            bx, by + 2,
            bx, by - arc_r,
            fill=arc_col, width=2,
        )

        # Tooltip for POWER OFF
        if hover:
            tt_text = "POWER OFF"
            tt_w = 66
            tt_h = 18
            tt_x = bx
            tt_y = by + br + 8
            
            self.canvas.create_rectangle(
                tt_x - tt_w//2, tt_y, 
                tt_x + tt_w//2, tt_y + tt_h,
                fill="#0a0a0a", outline="#ff4444", width=1
            )
            self.canvas.create_text(
                tt_x, tt_y + tt_h//2, 
                text=tt_text, fill="#ffffff", font=("Consolas", 8, "bold")
            )

    def draw_wifi_networks(self, w, h):
        """Draw Wi-Fi networks in a clean table layout below the info panel."""
        with wifi_lock:
            networks = dict(wifi_networks)

        top = 160
        self.canvas.create_text(16, top, text="Wi-Fi Networks Available:",
                               fill=COL_LABEL, anchor="nw", font=("Consolas", 11, "bold"))
        self.canvas.create_line(16, top + 18, w - 50, top + 18, fill=COL_GRID_DIM)

        if not networks:
            self.canvas.create_text(16, top + 28,
                                   text="Scanning... no networks found yet.",
                                   fill=COL_DIM_RING, anchor="nw", font=("Consolas", 9))
            return

        # Column positions - signal bar on left, SSID centered, BSSID/CH on right
        col_signal = 16
        bar_max = 50
        col_ssid   = w // 2  # Center of screen
        col_bssid  = max(col_ssid + 120, w - 200)
        col_chan   = max(col_bssid + 130, w - 60)

        y = top + 26
        # Header row
        self.canvas.create_text(col_signal, y, text="SIGNAL", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_ssid, y, text="SSID", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_bssid, y, text="BSSID", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_chan, y, text="CH", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        y += 16
        self.canvas.create_line(16, y - 2, w - 50, y - 2, fill=COL_GRID_DIM)

        sorted_nets = sorted(networks.items(),
                             key=lambda x: x[1].get("signal", -100),
                             reverse=True)

        for idx, (ssid, data) in enumerate(sorted_nets):
            if y > h - 60:
                remaining = len(sorted_nets) - idx
                self.canvas.create_text(16, y, text=f"... and {remaining} more",
                                       fill=COL_DIM_RING, anchor="nw", font=("Consolas", 8))
                break

            signal = data.get("signal", -100)
            bssid  = data.get("bssid") or "N/A"
            channel = data.get("channel", "?")

            # Alternating row background for readability
            if idx % 2 == 0:
                self.canvas.create_rectangle(12, y - 2, w - 50, y + 14,
                                           fill="#0a1a0a", outline="")

            # Signal strength bar + dBm value
            bar_fill = max(1, int((signal + 100) / 100 * bar_max))
            bar_color = COL_HIT if signal > -60 else COL_WARN if signal > -80 else COL_ALERT
            self.canvas.create_rectangle(col_signal, y + 1, col_signal + bar_max, y + 11,
                                        outline=COL_GRID_DIM)
            self.canvas.create_rectangle(col_signal, y + 1, col_signal + bar_fill, y + 11,
                                        fill=bar_color, outline="")
            self.canvas.create_text(col_signal + bar_max + 4, y,
                                   text=f"{signal} dBm", fill=COL_TEXT,
                                   anchor="nw", font=("Consolas", 8))

            # SSID (centered)
            display_ssid = (ssid[:30] + "..") if len(ssid) > 30 else ssid
            self.canvas.create_text(col_ssid, y, text=display_ssid, fill=COL_TEXT,
                                   anchor="nw", font=("Consolas", 9))

            # BSSID
            self.canvas.create_text(col_bssid, y, text=bssid, fill=COL_DIM_RING,
                                   anchor="nw", font=("Consolas", 8))

            # Channel
            self.canvas.create_text(col_chan, y, text=str(channel), fill=COL_DIM_RING,
                                   anchor="nw", font=("Consolas", 8))

            y += 22

    def draw_heatmap(self, snapshot, w, h):
        """Draw signal strength heatmap below the info panel."""
        top = 160
        self.canvas.create_text(16, top, text="Signal Strength Heatmap (dBm):",
                               fill=COL_LABEL, anchor="nw", font=("Consolas", 11, "bold"))
        self.canvas.create_line(16, top + 18, w - 50, top + 18, fill=COL_GRID_DIM)

        rssi_values = [d.get("rssi", -100) for d in snapshot.values()]
        if not rssi_values:
            self.canvas.create_text(16, top + 28,
                                   text="No BLE devices to display.",
                                   fill=COL_DIM_RING, anchor="nw", font=("Consolas", 9))
            return

        min_rssi = min(rssi_values)
        max_rssi = max(rssi_values)
        rssi_range = max_rssi - min_rssi if max_rssi != min_rssi else 1

        col_name = 16
        col_bar  = 180
        bar_max  = min(250, w - col_bar - 100)

        y = top + 28
        # Header
        self.canvas.create_text(col_name, y, text="DEVICE", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_bar, y, text="SIGNAL STRENGTH", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        y += 16
        self.canvas.create_line(16, y - 2, w - 50, y - 2, fill=COL_GRID_DIM)

        sorted_devs = sorted(snapshot.items(),
                             key=lambda x: x[1].get("rssi", -100),
                             reverse=True)

        for idx, (address, data) in enumerate(sorted_devs):
            if y > h - 60:
                remaining = len(sorted_devs) - idx
                self.canvas.create_text(16, y, text=f"... and {remaining} more",
                                       fill=COL_DIM_RING, anchor="nw", font=("Consolas", 8))
                break

            rssi = data.get("rssi", -100)
            strength = (rssi - min_rssi) / rssi_range
            bar_length = max(1, int(strength * bar_max))
            signal_color = lerp_color(strength, dark="#331111", bright="#ff4444")

            display_name = data['name'][:22] if len(data['name']) > 22 else data['name']
            self.canvas.create_text(col_name, y, text=display_name, fill=COL_TEXT,
                                   anchor="nw", font=("Consolas", 8))
            self.canvas.create_rectangle(col_bar, y + 1, col_bar + bar_max, y + 11,
                                        outline=COL_GRID_DIM)
            self.canvas.create_rectangle(col_bar, y + 1, col_bar + bar_length, y + 11,
                                        fill=signal_color, outline="")
            self.canvas.create_text(col_bar + bar_max + 6, y,
                                   text=f"{rssi} dBm", fill=COL_TEXT,
                                   anchor="nw", font=("Consolas", 8))
            y += 20

    def draw_timeline(self, snapshot, w, h):
        """Draw device discovery timeline below the info panel."""
        top = 160
        self.canvas.create_text(16, top, text="Device Discovery Timeline:",
                               fill=COL_LABEL, anchor="nw", font=("Consolas", 11, "bold"))
        self.canvas.create_line(16, top + 18, w - 50, top + 18, fill=COL_GRID_DIM)

        if not snapshot:
            self.canvas.create_text(16, top + 28,
                                   text="No BLE devices detected yet.",
                                   fill=COL_DIM_RING, anchor="nw", font=("Consolas", 9))
            return

        col_age  = 16
        col_name = 100
        col_type = max(col_name + 180, w - 200)

        y = top + 26
        # Header
        self.canvas.create_text(col_age, y, text="LAST SEEN", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_name, y, text="DEVICE", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_type, y, text="TYPE", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        y += 16
        self.canvas.create_line(16, y - 2, w - 50, y - 2, fill=COL_GRID_DIM)

        now = time.monotonic()
        devices_by_age = sorted(snapshot.items(),
                               key=lambda x: x[1].get("seen_at", now),
                               reverse=True)

        for idx, (address, data) in enumerate(devices_by_age):
            if y > h - 60:
                remaining = len(devices_by_age) - idx
                self.canvas.create_text(16, y, text=f"... and {remaining} more",
                                       fill=COL_DIM_RING, anchor="nw", font=("Consolas", 8))
                break

            age = now - data.get("seen_at", now)
            age_str = f"{age:.1f}s ago" if age < 60 else f"{int(age/60)}m ago"
            warning = data.get("warning")
            color = COL_ALERT if warning and warning["level"] == "ALERT" else COL_WARN if warning else COL_TEXT

            self.canvas.create_text(col_age, y, text=age_str, fill=COL_DIM_RING,
                                   anchor="nw", font=("Consolas", 8))
            display_name = data['name'][:22] if len(data['name']) > 22 else data['name']
            self.canvas.create_text(col_name, y, text=display_name, fill=color,
                                   anchor="nw", font=("Consolas", 9))
            display_type = data['type'][:18] if len(data['type']) > 18 else data['type']
            self.canvas.create_text(col_type, y, text=display_type, fill=COL_DIM_RING,
                                   anchor="nw", font=("Consolas", 8))
            y += 20

    def draw_radio(self, w, h):
        """Draw radio channel scanner with activity detection below the info panel."""
        top = 160
        self.canvas.create_text(16, top, text="Radio Channel Scanner (UHF/VHF/FM) [SIMULATED]:",
                               fill=COL_LABEL, anchor="nw", font=("Consolas", 11, "bold"))
        self.canvas.create_text(16, top + 16, text="Demo data - connect SDR hardware for real RF scanning",
                               fill=COL_DIM_RING, anchor="nw", font=("Consolas", 8))
        self.canvas.create_line(16, top + 30, w - 50, top + 30, fill=COL_GRID_DIM)

        active_channels = []
        with radio_lock:
            for freq_key, data in radio_channels.items():
                if data.get("activity", 0) > 0 or data.get("signal", -100) > -95:
                    active_channels.append((freq_key, data))

        active_channels.sort(key=lambda x: x[1].get("signal", -100), reverse=True)

        col_band   = 16
        col_freq   = 70
        col_bar    = 170
        bar_max    = min(200, w - col_bar - 120)
        col_status = col_bar + bar_max + 60

        y = top + 38
        # Header
        self.canvas.create_text(col_band, y, text="BAND", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_freq, y, text="FREQUENCY", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_bar, y, text="SIGNAL", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        self.canvas.create_text(col_status, y, text="STATUS", fill=COL_DIM_RING,
                               anchor="nw", font=("Consolas", 8, "bold"))
        y += 16
        self.canvas.create_line(16, y - 2, w - 50, y - 2, fill=COL_GRID_DIM)

        if not active_channels:
            self.canvas.create_text(16, y + 6,
                                   text="Scanning for radio channels... (awaiting signal detection)",
                                   fill=COL_DIM_RING, anchor="nw", font=("Consolas", 9))
            return

        for idx, (freq_key, data) in enumerate(active_channels):
            if y > h - 60:
                remaining = len(active_channels) - idx
                self.canvas.create_text(16, y, text=f"... and {remaining} more",
                                       fill=COL_DIM_RING, anchor="nw", font=("Consolas", 8))
                break

            band      = data.get("band", "")
            frequency = data.get("frequency", 0)
            signal    = data.get("signal", -100)
            activity  = data.get("activity", 0)

            bar_fill  = max(1, int((signal + 100) / 100 * bar_max))
            bar_color = COL_ALERT if activity > 0.7 else COL_WARN if activity > 0.3 else COL_SWEEP

            self.canvas.create_text(col_band, y, text=band, fill=COL_TEXT,
                                   anchor="nw", font=("Consolas", 9))
            self.canvas.create_text(col_freq, y, text=f"{frequency:.1f} MHz", fill=COL_TEXT,
                                   anchor="nw", font=("Consolas", 8))

            self.canvas.create_rectangle(col_bar, y + 1, col_bar + bar_max, y + 11,
                                        outline=COL_GRID_DIM)
            self.canvas.create_rectangle(col_bar, y + 1, col_bar + bar_fill, y + 11,
                                        fill=bar_color, outline="")
            self.canvas.create_text(col_bar + bar_max + 4, y,
                                   text=f"{signal} dBm", fill=COL_TEXT,
                                   anchor="nw", font=("Consolas", 8))

            if activity > 0:
                status_text = "ACTIVE" if activity > 0.7 else "DETECTED"
                self.canvas.create_text(col_status, y, text=status_text, fill=COL_ALERT,
                                       anchor="nw", font=("Consolas", 8, "bold"))

            y += 20

    def show_warning_popup(self, warn_info):
        """顯示警告彈窗（包含驗證詳情）"""
        warning = warn_info['warning']
        level = warning['level']
        label = warning['label']
        message = warning['message']
        confidence = warn_info.get('confidence', 0)
        warn_confidence = warning.get('confidence', 0)
        num_sources = warning.get('sources', 0)
        
        # 置信度等級
        if warn_confidence >= 90:
            confidence_level = "VERY HIGH 🔴"
        elif warn_confidence >= 80:
            confidence_level = "HIGH 🟠"
        elif warn_confidence >= 75:
            confidence_level = "MEDIUM 🟡"
        else:
            confidence_level = "LOW 🟢"
        
        sources_text = f"({num_sources} independent source{'s' if num_sources != 1 else ''})" if num_sources > 0 else "(single indicator)"
        
        title = f"🚨 [{level}] {label}" if level == "ALERT" else f"⚠️  [{level}] {label}"
        
        popup_message = (
            f"Threat Detected!\n\n"
            f"Alert Type: {label}\n"
            f"Severity: {level}\n"
            f"Message: {message}\n\n"
            f"Verification Details:\n"
            f"Confidence: {warn_confidence}% [{confidence_level}]\n"
            f"Verification: {sources_text}\n\n"
            f"Device Information:\n"
            f"Name: {warn_info['name']}\n"
            f"Type: {warn_info['type']}\n"
            f"MAC Address: {warn_info['mac']}\n"
            f"Signal Strength: {warn_info['rssi']} dBm\n"
            f"Overall Confidence: {confidence}%\n\n"
            f"[This alert was triggered by multi-layer verification]"
        )
        
        if level == "ALERT":
            messagebox.showerror(title, popup_message)
        else:
            messagebox.showwarning(title, popup_message)

    def check_warnings(self):
        """檢查警告隊列並顯示彈窗"""
        with warning_queue_lock:
            while warning_queue:
                warn_info = warning_queue.pop(0)
                self.show_warning_popup(warn_info)

    def update(self):
        w, h, cx, cy, max_r = self.dims()

        if self.is_booting:
            self.draw_boot_sequence(w, h, cx, cy)
            self.draw_shutdown_button(w)
            self.root.after(40, self.update)
            return

        self.check_warnings()

        self.cleanup_devices()
        snapshot = self.snapshot_devices()
        alerts = sum(
            1 for data in snapshot.values()
            if data.get("warning") and data["warning"]["level"] == "ALERT"
        )
        dev_warnings = sum(
            1 for data in snapshot.values()
            if data.get("warning") and data["warning"]["level"] == "DEV"
        )
        
        self.canvas.delete("all")

        if self.draw_display_reboot(w, h, cx, cy):
            self.draw_shutdown_button(w)
            self.draw_mode_dropdown(w)
            self.root.after(40, self.update)
            return
        
        # Render based on current mode
        current_mode_val = self.mode_var.get()
        
        if current_mode_val == "BLE":
            self.draw_grid(cx, cy, max_r)
            visible = self.draw_devices(snapshot, cx, cy, max_r, h)
            self.draw_sweep(cx, cy, max_r)
            self.draw_info_panel(len(snapshot), cx, cy, alerts, dev_warnings)
            status_msg = f"Tracking {len(snapshot)} BLE device(s), {visible} visible. [BLE Radar Mode]"
        elif current_mode_val == "WIFI":
            self.draw_info_panel(len(snapshot), cx, cy, alerts, dev_warnings)
            self.draw_wifi_networks(w, h)
            visible = len(snapshot)
            status_msg = f"Wi-Fi Networks Detected. [WiFi Mode]"
        elif current_mode_val == "HEAT":
            self.draw_info_panel(len(snapshot), cx, cy, alerts, dev_warnings)
            self.draw_heatmap(snapshot, w, h)
            visible = len(snapshot)
            status_msg = f"Displaying signal heatmap for {len(snapshot)} device(s). [Heatmap Mode]"
        elif current_mode_val == "TIME":
            self.draw_info_panel(len(snapshot), cx, cy, alerts, dev_warnings)
            self.draw_timeline(snapshot, w, h)
            visible = len(snapshot)
            status_msg = f"Timeline view: {len(snapshot)} device(s). [Timeline Mode]"
        elif current_mode_val == "RADIO":
            self.draw_info_panel(0, cx, cy, 0, 0)
            self.draw_radio(w, h)
            visible = 0
            status_msg = f"Radio channel scanner active (simulated). [Radio Scanner Mode]"
        else:
            visible = 0
            status_msg = "Unknown mode"
        
        self.draw_shutdown_button(w)
        self.draw_mode_dropdown(w)
        
        if not scanner_error:
            self.status.set(status_msg)
        else:
            self.status.set(scanner_error)

        self.root.after(40, self.update)

    def run(self):
        if BleakScanner is None:
            messagebox.showerror("Error", "The 'bleak' library is missing. Please install it using: python -m pip install bleak")
        self.root.mainloop()

def cmd_boot_animation():
    """CMD window boot animation (Turbo Version) with master-slave sync"""
    global cmd_ready, start_boot_event
    
    # 立即清空終端機
    os.system("cls" if os.name == "nt" else "clear")
    
    # 終端機負責精準倒數 5 秒 (此時兩邊都是全黑畫面待機)
    time.sleep(5)
    
    # 【鳴槍起跑】告訴 GUI 視窗：「我倒數完了，開始一起播動畫吧！」
    start_boot_event.set()
    
    BANNER = r"""
█████ █   █ █████ █████ ████       █████ ████  █████ ████  █████
█     █   █ █   █ █     █   █      █   █ █   █ █   █ █   █ █   █
█████ █   █ █████ ████  ████       █████ █████ █   █ █████ ████ 
    █ █   █ █     █     █  █       █  █  █   █ █   █ █   █ █  █ 
█████ █████ █     █████ █   █      █   █ █   █ █████ █   █ █   █

Coded by HACKEREric
"""
    
    STEPS = [
        (0.05, "  > INITIALIZING NEURAL INTERFACE..."),
        (0.05, "  > WAKING UP TACTICAL NEURAL NET..."),
        (0.05, "  > CHARGING PHOTON RELAY..."),
        (0.05, "  > INITIATING BLE SENSOR ARRAY..."),
        (0.05, "  > LOADING DEVICE FINGERPRINT DATABASE..."),
        (0.05, "  > CALIBRATING QUANTUM SENSORS..."),
        (0.10, "  > OVERRIDING SECURITY PROTOCOLS...          [OK]"),
        (0.10, "  > ENGAGING RADAR SWEEP ENGINE...            [OK]"),
        (0.10, "  > DECRYPTING MAC ADDRESS POOL..."),
        (0.05, "  > CALIBRATING RSSI DISTANCE ESTIMATORS...  [OK]"),
        (0.05, "  > SYNCHRONIZING TEMPORAL MATRIX..."),
        (0.20, "  > UPLINK ESTABLISHED. RADAR SYSTEM ARE READY..."),
        (0.10, ""),
        (0.02, "  ─────────────────────────────────────────────────"),
        (0.02, "  LIVE SCAN LOG  (NEW = detected  /  LOST = expired)"),
        (0.02, "  ─────────────────────────────────────────────────"),
        (0.02, ""),
        (0.02, "  SHORTCUTS:"),
        (0.02, "    Right-click device = Blacklist / RSSI History"),
        (0.02, "    Double-click device = BLE Connect"),
        (0.02, "    Ctrl+E = Export CSV | Ctrl+Shift+E = Export JSON"),
        (0.02, ""),
    ]

    print(BANNER)
    time.sleep(0.1)

    for delay, line in STEPS:
        for ch in line:
            print(ch, end="", flush=True)
            time.sleep(0.005)
        print()
        time.sleep(delay)
        
    # 【抵達終點】告訴 GUI 視窗：「我打完字了，你可以亮綠燈進雷達了！」
    cmd_ready = True


def main():
    global scan_start_time
    scan_start_time = time.monotonic()

    threading.Thread(target=cmd_boot_animation, daemon=True).start()
    threading.Thread(target=ble_scan_worker, daemon=True).start()
    threading.Thread(target=wifi_scan_worker, daemon=True).start()
    threading.Thread(target=radio_scan_worker, daemon=True).start()
    Radar().run()


if __name__ == "__main__":
    main()