# /// script
# requires-python = ">=3.10"
# dependencies = ["bleak", "pycryptodome"]
# ///
"""Send one write frame to the pump and watch how its state responds.

    uv run tools/write.py <address> --code XXXX --cmd 100 --body "02 00 00 00 00 08 aa 05"

THIS CHANGES PUMP STATE. The frame is [type][cmd u16le][body], zero padded to 20 bytes.
Command 100 is polled before and after so the effect is visible.
"""

import argparse
import asyncio
import datetime

from bleak import BleakClient

from auth import (CAPTURES, UUID_AUTH, UUID_RX, UUID_SESSION_KEY, UUID_TX,
                  decrypt_characteristic, encrypt_characteristic, encrypt_mac_key)
from monitor import PAYLOAD_LEN, words


async def run(args):
    CAPTURES.mkdir(exist_ok=True)
    path = CAPTURES / f"{datetime.datetime.now():%Y%m%d-%H%M%S}-write.txt"
    out = path.open("w")

    def log(line: str):
        line = f"{datetime.datetime.now():%H:%M:%S.%f}"[:-3] + " " + line
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
            # Telemetry (105) is noisy; log it only on a real change in power.
            if cmd == 105 and cmd in last and abs(int.from_bytes(body[4:6], "little") - int.from_bytes(last[cmd][4:6], "little")) < 30:
                return
            if last.get(cmd) != body or plain[0] != 1:
                last[cmd] = body
                log(f"RX type={plain[0]} cmd={cmd:3d} {body.hex(' ')}   u16: {words(body)}")

        async def send(frame_type: int, cmd: int, body: bytes = b""):
            frame = (bytes([frame_type]) + cmd.to_bytes(2, "little") + body).ljust(20, b"\0")
            await client.write_gatt_char(UUID_RX, encrypt_characteristic(frame, session_key), response=True)
            return frame

        async def poll(seconds: float):
            end = asyncio.get_event_loop().time() + seconds
            while asyncio.get_event_loop().time() < end and not disconnected.is_set():
                await send(2, 100)
                await asyncio.sleep(0.15)
                await send(2, 105)
                await asyncio.sleep(0.6)

        await client.start_notify(UUID_TX, on_notify)
        await client.write_gatt_char(UUID_AUTH, encrypt_mac_key(session_key, args.code.encode()), response=True)
        log("authenticated; state before:")
        await poll(3)

        frame = await send(args.type, args.cmd, bytes.fromhex(args.body))
        log(f"TX {frame.hex(' ')}")
        await poll(args.watch)
        log("pump disconnected" if disconnected.is_set() else "done")
    log(f"Saved to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("address")
    parser.add_argument("--code", required=True)
    parser.add_argument("--type", type=int, default=3, help="frame type (3 = write)")
    parser.add_argument("--cmd", type=int, required=True)
    parser.add_argument("--body", required=True, help="payload as hex")
    parser.add_argument("--watch", type=float, default=20)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
