# /// script
# requires-python = ">=3.10"
# dependencies = ["bleak", "pycryptodome"]
# ///
"""Poll the pump's readable commands and print a line whenever a value changes.

    uv run tools/monitor.py <address> --code XXXX --seconds 300

Only read requests are sent. Use it while pressing buttons on the pump keypad.
"""

import argparse
import asyncio
import datetime

from bleak import BleakClient

from auth import (CAPTURES, UUID_AUTH, UUID_RX, UUID_SESSION_KEY, UUID_TX,
                  decrypt_characteristic, encrypt_characteristic, encrypt_mac_key)

# Meaningful payload length per command; bytes beyond it are stale buffer contents.
PAYLOAD_LEN = {100: 8, 101: 10, 102: 13, 104: 12, 105: 10}


def words(body: bytes) -> str:
    return " ".join(str(int.from_bytes(body[i:i + 2], "little")) for i in range(0, len(body) - 1, 2))


async def run(args):
    CAPTURES.mkdir(exist_ok=True)
    path = CAPTURES / f"{datetime.datetime.now():%Y%m%d-%H%M%S}-monitor.txt"
    out = path.open("w")

    def log(line: str):
        line = f"{datetime.datetime.now():%H:%M:%S} " + line
        print(line, flush=True)
        out.write(line + "\n")
        out.flush()

    last: dict[int, bytes] = {}
    disconnected = asyncio.Event()
    async with BleakClient(args.address, timeout=20, disconnected_callback=lambda _: disconnected.set()) as client:
        session_key = bytes(await client.read_gatt_char(UUID_SESSION_KEY))

        def on_notify(_, data: bytearray):
            plain = decrypt_characteristic(bytes(data), session_key)
            cmd = int.from_bytes(plain[1:3], "little")
            body = plain[3:3 + PAYLOAD_LEN.get(cmd, 16)]
            if last.get(cmd) != body:
                last[cmd] = body
                log(f"cmd={cmd:3d} type={plain[0]} {body.hex(' ')}   u16: {words(body)}")

        await client.start_notify(UUID_TX, on_notify)
        await client.write_gatt_char(UUID_AUTH, encrypt_mac_key(session_key, args.code.encode()), response=True)
        log(f"authenticated, polling {args.cmds} for {args.seconds:.0f}s")

        end = asyncio.get_event_loop().time() + args.seconds
        while asyncio.get_event_loop().time() < end and not disconnected.is_set():
            for cmd in args.cmds:
                frame = (bytes([2]) + cmd.to_bytes(2, "little")).ljust(20, b"\0")
                await client.write_gatt_char(UUID_RX, encrypt_characteristic(frame, session_key), response=True)
                await asyncio.sleep(0.1)
            await asyncio.sleep(args.interval)
        log("pump disconnected" if disconnected.is_set() else "done")
    log(f"Saved to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("address")
    parser.add_argument("--code", required=True)
    parser.add_argument("--seconds", type=float, default=300)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--cmds", type=int, nargs="+", default=[100, 101, 102, 104, 105])
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
