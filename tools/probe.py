# /// script
# requires-python = ">=3.10"
# dependencies = ["bleak", "pycryptodome"]
# ///
"""Read-only BLE probe for an AstralPool Viron XT pump.

    uv run tools/probe.py scan            # list nearby AstralPool-looking devices
    uv run tools/probe.py scan --all      # list every advertiser
    uv run tools/probe.py gatt <address>  # connect, dump the GATT table, read what is readable
    uv run tools/probe.py watch           # keep scanning; report when the pump advertises an access code

Nothing here writes to the pump. Output is also appended to captures/.
"""

import argparse
import asyncio
import datetime
import pathlib
import struct
import sys

from bleak import BleakClient, BleakScanner

# Shared by the Viron eQ (…3001) and Halo (…3002) chlorinators; the pump is
# reported to advertise the same family under the local name POOL00.
ASTRAL_UUID_PREFIX = "4500"
ASTRAL_UUID_SUFFIX = "-98b7-4e29-a03f-1601746430"
ASTRAL_NAMES = ("POOL", "HCHLOR", "VIRON", "ASTRAL")

FABTRONICS_COMPANY_ID = 0x0447
DEVICE_TYPES = {0: "Pump", 1: "Chlorinator", 2: "Doser", 3: "Light", 4: "Probe", 129: "ChlorinatorEmulator"}
# Same layout as pychlorinator's halo_parsers.ScanResponse.
ADV_FMT = "<BBBBBBI4sBBBBBBB"


def decode_adv(data: bytes) -> dict | None:
    if len(data) < struct.calcsize(ADV_FMT):
        return None
    (dev_type, dev_ver, proto, proto_rev, status, _reserved, unique_id, access_code,
     fw_major, fw_minor, bl_major, bl_minor, hw_lo, hw_hi, time_alive) = struct.unpack_from(ADV_FMT, data)
    if dev_type == 0 and len(data) >= 23:
        # Pump adverts differ from pychlorinator's chlorinator layout: byte 18 counts
        # seconds since power-on (saturating at 100) and bytes 19..22 carry the access
        # code while that pairing window is open.
        time_alive, access_code = data[18], data[19:23]
        hw_lo = hw_hi = 0
    return {
        "type": DEVICE_TYPES.get(dev_type, f"?{dev_type}"),
        "version": dev_ver,
        "protocol": f"{proto}.{proto_rev}",
        "status": status,
        "unique_id": f"{unique_id:08x}",
        "access_code": access_code,
        "pairable": access_code != bytes(4),
        "firmware": f"{fw_major}.{fw_minor}",
        "bootloader": f"{bl_major}.{bl_minor}",
        "hw_platform": hw_lo | hw_hi << 8,
        "time_alive": time_alive,
    }


CAPTURES = pathlib.Path(__file__).resolve().parent.parent / "captures"


def is_astral_uuid(uuid: str) -> bool:
    return uuid.startswith(ASTRAL_UUID_PREFIX) and ASTRAL_UUID_SUFFIX in uuid


class Log:
    def __init__(self, name: str):
        CAPTURES.mkdir(exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = CAPTURES / f"{stamp}-{name}.txt"
        self.file = self.path.open("w")

    def __call__(self, line: str = ""):
        print(line)
        self.file.write(line + "\n")
        self.file.flush()


async def scan(show_all: bool, seconds: float):
    log = Log("scan")
    log(f"Scanning for {seconds:.0f}s...")
    found = await BleakScanner.discover(timeout=seconds, return_adv=True)
    hits = 0
    for address, (device, adv) in sorted(found.items(), key=lambda kv: -kv[1][1].rssi):
        name = adv.local_name or device.name or ""
        astral = any(is_astral_uuid(u) for u in adv.service_uuids) or name.upper().startswith(ASTRAL_NAMES)
        if not (astral or show_all):
            continue
        hits += 1
        log(f"{'*' if astral else ' '} {address}  rssi={adv.rssi:4d}  name={name!r}")
        for u in adv.service_uuids:
            log(f"      service      {u}")
        for company, data in adv.manufacturer_data.items():
            log(f"      manufacturer 0x{company:04x}  {data.hex()}  {data!r}")
            if company == FABTRONICS_COMPANY_ID and (decoded := decode_adv(data)):
                log(f"      decoded      {decoded}")
        for u, data in adv.service_data.items():
            log(f"      service_data {u}  {data.hex()}")
    log(f"\n{hits} device(s) shown, {len(found)} seen. Saved to {log.path}")
    if not hits:
        log("No AstralPool-looking device. Power-cycle the pump (it advertises for pairing "
            "after power-on), stand next to it, and retry — or use --all.")


async def watch(seconds: float):
    """Log every change in an AstralPool pump advert; flag when an access code appears."""
    log = Log("watch")
    last: dict[str, bytes] = {}
    got_code = asyncio.Event()

    def on_adv(device, adv):
        data = adv.manufacturer_data.get(FABTRONICS_COMPANY_ID)
        if data is None or last.get(device.address) == data:
            return
        last[device.address] = data
        decoded = decode_adv(data)
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        log(f"{stamp} {device.address} {adv.local_name!r} rssi={adv.rssi} {data.hex()}")
        if decoded:
            log(f"         {decoded}")
            if decoded["type"] == "Pump" and decoded["pairable"]:
                log(f"\n*** PUMP ACCESS CODE: hex={decoded['access_code'].hex()} raw={decoded['access_code']!r} ***\n")
                got_code.set()

    log(f"Watching for {seconds:.0f}s. Power the pump off, wait 10s, power it back on.")
    async with BleakScanner(on_adv):
        try:
            await asyncio.wait_for(got_code.wait(), timeout=seconds)
            await asyncio.sleep(5)  # keep logging a little to see how the advert evolves
        except asyncio.TimeoutError:
            log("No access code seen.")
    log(f"Saved to {log.path}")


async def gatt(address: str, reads: int):
    log = Log("gatt")
    log(f"Connecting to {address}...")
    async with BleakClient(address, timeout=20) as client:
        log(f"Connected. MTU={client.mtu_size}")
        for service in client.services:
            log(f"\nSERVICE {service.uuid}  ({service.description})")
            for char in service.characteristics:
                log(f"  CHAR {char.uuid}  handle={char.handle}  [{','.join(char.properties)}]")
                if "read" in char.properties:
                    # Read several times: a value that changes per read/connection
                    # is a nonce (session key), a stable one is state.
                    for i in range(reads):
                        try:
                            value = bytes(await client.read_gatt_char(char))
                            log(f"       read[{i}] len={len(value):2d}  {value.hex()}  {value!r}")
                        except Exception as err:  # noqa: BLE001 - report and keep going
                            log(f"       read[{i}] FAILED: {err}")
                            break
                for desc in char.descriptors:
                    log(f"       DESC {desc.uuid} handle={desc.handle}")
    log(f"\nSaved to {log.path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--all", action="store_true")
    p_scan.add_argument("--seconds", type=float, default=15)
    p_gatt = sub.add_parser("gatt")
    p_gatt.add_argument("address", help="address/UUID as printed by scan")
    p_gatt.add_argument("--reads", type=int, default=2)
    p_watch = sub.add_parser("watch")
    p_watch.add_argument("--seconds", type=float, default=300)
    args = parser.parse_args()

    if args.cmd == "scan":
        asyncio.run(scan(args.all, args.seconds))
    elif args.cmd == "watch":
        asyncio.run(watch(args.seconds))
    else:
        asyncio.run(gatt(args.address, args.reads))


if __name__ == "__main__":
    sys.exit(main())
