# /// script
# requires-python = ">=3.10"
# dependencies = ["bleak", "pycryptodome"]
# ///
"""Authenticate to the pump with the Halo handshake and listen.

    uv run tools/auth.py <address> --code XXXX
    uv run tools/auth.py <address> --code XXXX --read 1 --read 107   # also send read requests

By default this writes only the auth MAC, then listens. --read sends Halo-style
"ReadForCatchAll" requests ([2, cmd u16le]); nothing here sets pump state.
"""

import argparse
import asyncio
import datetime
import pathlib

from bleak import BleakClient
from Crypto.Cipher import AES

BASE = "-98b7-4e29-a03f-160174643002"
UUID_SESSION_KEY = "45000001" + BASE
UUID_AUTH = "45000002" + BASE
UUID_TX = "45000003" + BASE  # pump -> us (notify)
UUID_RX = "45000004" + BASE  # us -> pump (write)

SECRET_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
CAPTURES = pathlib.Path(__file__).resolve().parent.parent / "captures"


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays, left aligned, zero padded."""
    short, long = sorted((a, b), key=len)
    return bytes(x ^ y for x, y in zip(short.ljust(len(long), b"\0"), long))


def encrypt_mac_key(session_key: bytes, access_code: bytes) -> bytes:
    return AES.new(SECRET_KEY, AES.MODE_ECB).encrypt(xor_bytes(session_key, access_code))


def encrypt_characteristic(data: bytes, session_key: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    xored = xor_bytes(data, session_key)
    array = cipher.encrypt(xored[:16]) + xored[16:]
    return array[:4] + cipher.encrypt(array[4:])


def decrypt_characteristic(data: bytes, session_key: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    array = data[:4] + cipher.decrypt(data[4:])
    array = cipher.decrypt(array[:16]) + array[16:]
    return xor_bytes(array, session_key)


async def run(args):
    CAPTURES.mkdir(exist_ok=True)
    path = CAPTURES / f"{datetime.datetime.now():%Y%m%d-%H%M%S}-auth.txt"
    out = path.open("w")

    def log(line: str = ""):
        line = f"{datetime.datetime.now():%H:%M:%S.%f}"[:-3] + " " + line
        print(line, flush=True)
        out.write(line + "\n")
        out.flush()

    code = bytes.fromhex(args.code_hex) if args.code_hex else args.code.encode()
    log(f"Connecting to {args.address}, access code {code!r}")
    disconnected = asyncio.Event()
    async with BleakClient(args.address, timeout=20, disconnected_callback=lambda _: disconnected.set()) as client:
        session_key = bytes(await client.read_gatt_char(UUID_SESSION_KEY))
        log(f"session key   {session_key.hex()}")

        def on_notify(_, data: bytearray):
            raw = bytes(data)
            if len(raw) != 20:
                log(f"RX raw len={len(raw)} {raw.hex()}")
                return
            plain = decrypt_characteristic(raw, session_key)
            cmd = int.from_bytes(plain[1:3], "little")
            log(f"RX type={plain[0]:3d} cmd={cmd:5d} (0x{cmd:04x}) body={plain[3:].hex()}   raw={raw.hex()}")

        await client.start_notify(UUID_TX, on_notify)
        mac = encrypt_mac_key(session_key, code)
        log(f"auth write    {mac.hex()}")
        await client.write_gatt_char(UUID_AUTH, mac, response=True)
        log("auth written")

        for cmd in args.read:
            await asyncio.sleep(0.5)
            frame = (bytes([2]) + cmd.to_bytes(2, "little")).ljust(20, b"\0")
            log(f"TX read request cmd={cmd}  plain={frame.hex()}")
            await client.write_gatt_char(UUID_RX, encrypt_characteristic(frame, session_key), response=True)

        try:
            await asyncio.wait_for(disconnected.wait(), timeout=args.listen)
            log("pump disconnected us")
        except asyncio.TimeoutError:
            log(f"still connected after {args.listen:.0f}s, disconnecting")
    log(f"Saved to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("address")
    parser.add_argument("--code", default="", help="access code as ASCII, e.g. XXXX")
    parser.add_argument("--code-hex", help="access code as hex, overrides --code")
    parser.add_argument("--read", type=int, action="append", default=[], help="send a read request for this command id")
    parser.add_argument("--listen", type=float, default=20)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
