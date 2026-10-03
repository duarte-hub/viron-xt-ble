# /// script
# requires-python = ">=3.10"
# dependencies = ["bleak", "pycryptodome"]
# ///
"""Send a read request for every command id in a range and log what answers.

    uv run tools/sweep.py <address> --code XXXX --start 0 --end 1535

Only read requests ([2, cmd u16le]) are sent; nothing sets pump state.
"""

import argparse
import asyncio
import datetime

from bleak import BleakClient

from auth import (CAPTURES, UUID_AUTH, UUID_RX, UUID_SESSION_KEY, UUID_TX,
                  decrypt_characteristic, encrypt_characteristic, encrypt_mac_key)


async def run(args):
    CAPTURES.mkdir(exist_ok=True)
    path = CAPTURES / f"{datetime.datetime.now():%Y%m%d-%H%M%S}-sweep.txt"
    out = path.open("w")

    def log(line: str, show: bool = True):
        line = f"{datetime.datetime.now():%H:%M:%S.%f}"[:-3] + " " + line
        if show:
            print(line, flush=True)
        out.write(line + "\n")
        out.flush()

    disconnected = asyncio.Event()
    current = args.start
    async with BleakClient(args.address, timeout=20, disconnected_callback=lambda _: disconnected.set()) as client:
        session_key = bytes(await client.read_gatt_char(UUID_SESSION_KEY))

        def on_notify(_, data: bytearray):
            plain = decrypt_characteristic(bytes(data), session_key)
            cmd = int.from_bytes(plain[1:3], "little")
            log(f"RX after_tx={current:5d} type={plain[0]:3d} cmd={cmd:5d} (0x{cmd:04x}) body={plain[3:].hex()}")

        await client.start_notify(UUID_TX, on_notify)
        await client.write_gatt_char(UUID_AUTH, encrypt_mac_key(session_key, args.code.encode()), response=True)
        log(f"authenticated, sweeping {args.start}..{args.end}")

        for current in range(args.start, args.end + 1):
            if disconnected.is_set():
                log(f"pump disconnected before cmd={current}")
                break
            frame = (bytes([2]) + current.to_bytes(2, "little")).ljust(20, b"\0")
            log(f"TX read cmd={current}", show=False)
            try:
                await client.write_gatt_char(UUID_RX, encrypt_characteristic(frame, session_key), response=True)
            except Exception as err:  # noqa: BLE001 - a dropped link ends the sweep
                log(f"write failed at cmd={current}: {err}")
                break
            await asyncio.sleep(args.gap)
        else:
            await asyncio.sleep(2)
            log("sweep complete")
    log(f"Saved to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("address")
    parser.add_argument("--code", required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, default=1535)
    parser.add_argument("--gap", type=float, default=0.05, help="seconds between requests")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
