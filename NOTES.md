# Viron P320C XT — BLE reverse engineering notes

Goal: set pump speed from an ESP32, with no Halo chlorinator in the loop.

## Roles

- The pump is a BLE **peripheral**. A Halo Chlor is the **central** that pairs to it
  ("AstralPool Variable Speed (Wireless)" in the Halo install menu).
- The pump enters pairing mode when it is **powered on**; Halo then pairs automatically.
- So the ESP32 must act as a BLE central impersonating the Halo.
- The phone app (Halo Chlor Go) never talks to the pump. The pump-side protocol lives in
  the Halo's firmware, not in the app.

## What is known (from the chlorinator side, same vendor: Fabtronics)

Reported, unverified on this pump: an XT320 advertises local name `POOL00` with the
"same service UUID" as a Viron eQ chlorinator (HA forum, ianmcginley, Nov 2023).

| | Viron eQ chlorinator | Halo chlorinator |
|---|---|---|
| Adv name | `POOL01` | `HCHLOR` |
| Service | `45000001-98b7-4e29-a03f-160174643001` | `45000001-…643002` |
| Session key (read) | `45000002-…3001` | `45000001-…3002` |
| Auth (write) | `45000003-…3001` | `45000002-…3002` |
| Data | one characteristic per struct (`450002xx`) | TX notify `45000003`, RX write `45000004`, 20-byte frames `[type][cmd u16le][17 body]` |

Chlorinator auth/crypto (see pychlorinator, `pychlorinator/chlorinator.py`):

1. Read 16-byte session key (random per connection).
2. Write `AES128-ECB(SECRET, session_key XOR access_code)` to the auth characteristic.
3. Payloads: XOR with session key, AES-ECB bytes 0..15, then AES-ECB bytes 4..19.

- `SECRET` = `2b7e151628aed2a6abf7158809cf4f3c` (the NIST AES test key).
- A second key `7313584761b264bc69863c8ab6484907` was seen in the Halo app decompile.
- Access code: 4 chars shown on the eQ's screen. Halo fw ≥ 2.4 moved this server-side —
  irrelevant to us unless the pump uses the same access-code idea.

## Unknown — what we need to find out

1. Does this pump really expose the `4500xxxx-…` service? Which variant, which characteristics?
2. Is there a readable per-connection session key (same handshake family)?
3. What stands in for the access code when a Halo pairs with a pump?
4. Speed command format (Halo sets RPM 600–3600 per speed slot, so likely an RPM u16).
5. Does the pump need a keep-alive, and what does it do when the link drops?

## Plan

1. `uv run tools/probe.py scan` next to the powered pump → address, adv data.
2. `uv run tools/probe.py gatt <address>` → GATT table + readable values (read-only).
3. Depending on 2: try the known handshake with candidate access codes, or
4. get a ground-truth capture: sniff a real Halo↔pump session (nRF52840 dongle +
   Wireshark), or extract Halo firmware.
5. Port the working sequence to ESP32 (NimBLE central / ESPHome `ble_client`).

## Wired fallback

XT pumps also take an RJ12 comms cable from a Halo/eQ chlorinator ("automatic" setup).
If BLE auth turns out to be a wall, that port is a second way in.

## Sources

- https://community.home-assistant.io/t/viron-astral-pool-chlorinatorgo-integration/375495?page=9
- https://github.com/pbutterworth/pychlorinator
- https://github.com/robmarkoski/pychlorinator-cloud/issues/1
- Halo Chlor manual: https://s3-ap-southeast-2.amazonaws.com/astralpools-au-2/Products/Halo_Chlor/Halo_Chlor_manual_H0725000_REVA.PDF

## Findings — 2026-10-03 (verified on this pump)

- Advertises as **`HPUMP`** (not `POOL00`), service `45000001-…643002` → **Halo protocol variant**.
  macOS address `<pump address>` (CoreBluetooth UUID, not the MAC).
- GATT is identical to a Halo chlorinator: `…0001` session key (read, 16 bytes, new value on
  every read), `…0002` auth (write), `…0003` TX (notify), `…0004` RX (write). MTU 23.
- Manufacturer data (company 0x0447) parses with pychlorinator's `ScanResponse`:
  type=Pump(0), version 9, protocol 0.1, unique id `00xxxxxx`, firmware 5.1, hw platform 100,
  **access code = 00000000 → not in pairing mode**.
- On Halo chlorinators the 4-byte access code is broadcast in this field while pairing mode is
  active. Hypothesis: the pump does the same for ~a minute after power-on.
  `uv run tools/probe.py watch` waits for it.
- A `POOL01` (Viron eQ chlorinator) is also in range at about -100 dBm — whose is it?
- **Pairing window confirmed.** After a mains power-cycle the advert tail (bytes 18..22) changes
  from `64 00000000` to `<n> 58585858`: byte 18 counts up once a second from power-on and
  bytes 19..22 are ASCII **`XXXX`**. At 100 (0x64) the code is zeroed again, so the window is
  ~100 s. The pump layout is not the chlorinator `ScanResponse` layout (code is at 19, not 10).
- Access code candidate for this pump: `XXXX`. Unknown yet: whether auth is only accepted
  inside the window, and whether the code is fixed or regenerated per power-up.
- `tools/auth.py` does the Halo handshake with a given code and logs decrypted notifications.

## Auth + command map — 2026-10-03

- **Auth works with `XXXX` using the unmodified Halo handshake**, and works outside the
  100 s pairing window. Wrong code → pump drops the link in ~100 ms. Right code → link stays
  up; idle timeout is 10 s without traffic.
- Frames: 20 bytes, `[type][cmd u16le][17 body]`. type 2 = read request, type 1 = response.
  Last body byte is a rolling packet counter. Short payloads leave stale bytes from the
  previous frame in the tail — don't over-read.
- Read sweep of cmd 0..1535 (`tools/sweep.py`): only these answer —

| cmd | body (hex) | reading |
|---|---|---|
| 1 | `00 09 00 01 05 01 xxxxxx00 …` | device profile: type Pump, v9, proto 0.1, fw 5.1, unique id |
| 2 | `36 10 16 02 18 04 18 …` | ? (clock?) |
| 3 | `01 10 16 02 18 04 18 …` | ? |
| 4 | `50554d50` | name `PUMP` |
| 100 | `02 01 00 00 00 08 6009` | state? u16@6 = 2400 (rpm?) |
| 101 | `7a0d 220b 5802 01 0e 46 01` | 3450, 2850, 600 → limits? |
| 102 | `aa05 6009 8c0a 0807 78000000 1e` | 1450, 2400, 2700, 1800, 120, 30 → speed presets / timers? |
| 104 | `a800 0c00 7000 1400 0800 0c00` | 168, 12, 112, 20, 8, 12 → ? |
| 105 | `2e01 c405 1a02 db01 db01` | 302, 1476, 538, 475, 475 → live telemetry? |

  cmd 103 did not answer; a second cmd 100 frame arrived around then (unsolicited status?).
- Next: poll 100/104/105 while changing speed on the keypad to label fields, then find the
  write frame (Halo uses type 3 for writes).

## Field labels — 2026-10-03 (keypad test: Low, High, Med, Stop, Start)

cmd 100 — live state (8 bytes):

| offset | meaning | seen |
|---|---|---|
| 0 | run state | `02` running, `00` stopped |
| 1 | selected speed | 0 low, 1 medium, 2 high |
| 2-3 | ? | `0000` |
| 4-5 | flags | `0008` running, `0009` priming, `0000` stopped |
| 6-7 | target rpm u16le | 1450 / 2400 / 2700 / 1800 (priming) |

cmd 102 — setup: low rpm, medium rpm, high rpm, priming rpm (1800), priming seconds (120), `00 00`, 30 (?).
User confirmed low=1450, high=2700, running=2400, priming=1800 for a couple of minutes.

cmd 101 — probably limits: 3450 max, 2850 ?, 600 min, then `01 0e 46 01`.

cmd 105 — telemetry (u16le ×5): [0] ~296–309, rises when stopped (bus voltage?);
[1] tracks load: 488 @1450, 743 @1800, 1500 @2400, 2190 @2700 (current mA?);
[2] 224 @1450, 307 @1800, 536 @2400, 745 @2700, 0 stopped (**power in W**, likely);
[3]=[4] ~428–483 (temperature ×10?).

cmd 104 — static during the test (168 12 112 20 8 12), unknown.

Write frames in the Halo protocol are type 3: `[03][cmd u16le][payload]`. Untested on the pump.
First candidate: type 3 to cmd 100 with a state body, e.g. `03 6400 02 00 0000 0008 aa05` (Low).

## First write — 2026-10-03 13:52

- `03 6400 02 00 0000 0008 aa05` (type 3 → cmd 100, "Low" state body): **no effect, no
  response, link stayed up.** cmd 100 is read-only state.
- The pump's numbering mirrors the Viron eQ characteristic block (`450002xx`): x00 state,
  x01 capabilities, x02 setup, **x03 app action**, x04 timers, x05 statistics. So:
  100 state, 101 capabilities, 102 setup, **103 action (write-only — it was the one id in
  100..105 with no read reply of its own)**, 104 timers, 105 statistics.
- In the sweep, read(103) returned cmd 104's data and read(104) returned cmd 100's.
- Next candidate: type 3 → cmd 103, body `[action u8][i32 param]` like the chlorinator action.
  Pump action enum unknown; chlorinator's is 0 NoAction, 1 Off, 2 Auto, 3 On, 4 Low, 5 Med, 6 High.

## Control command found — 2026-10-03 13:53–13:55

**Write frame: `03 67 00 <action>` (type 3 → cmd 103, 1-byte action), zero padded to 20.**
No explicit ack; the pump pushes fresh cmd 100 (and cmd 102 if setup changed) within ~100 ms.

| action | effect observed |
|---|---|
| 0 | nothing |
| 1 | **stop** (state `00`, flags `0000`) |
| 2 | nothing while stopped (Auto? untested while running) |
| 3 | **start** (goes into priming: flags `0009`, 1800 rpm, then selected speed) |
| 4 | **+25 rpm** on the selected preset (2400 → 2425; cmd 102 medium changed too) |
| 5 | **−25 rpm** on the selected preset (2425 → 2400) |
| 6+ | untested |

- 4/5 edit the stored preset (cmd 102), i.e. same as the keypad arrows. Probably persisted to
  flash — do not use them as a continuous control loop without checking wear.
- Open: how to select low/medium/high (actions 6..8?), whether cmd 102 accepts a type-3 write
  with arbitrary rpm, what action 2 does while running.
- Medium preset was restored to 2400 after the test.

## Full control — 2026-10-03 13:57–13:59

Actions (type 3 → cmd 103), complete table as tested:

| action | effect |
|---|---|
| 1 | stop |
| 3 | start (primes first) |
| 4 / 5 | +25 / −25 rpm on the selected preset |
| 6 / 7 / 8 | **select low / medium / high** |
| 0, 2 | no visible effect (2 only tried while stopped) |

**Arbitrary RPM: type 3 → cmd 102 with the setup body in the same layout it is read in.**
`03 6600 aa05 d007 8c0a 0807 7800 0000 1e` set medium to 2000; the pump echoed cmd 102, then
cmd 100 showed 2000 rpm and the motor followed immediately (no re-prime). Read-back confirmed.
Layout: low u16, medium u16, high u16, priming rpm u16, priming seconds u16, `0000`, `1e`.

Presets restored to 1450 / 2400 / 2700 after the test, pump left running on medium.

Recipe for the ESP32: connect → read `…0001` → write AES(key, session XOR "XXXX") to `…0002`
→ subscribe `…0003` → writes to `…0004`. Poll cmd 100/105 at least every few seconds
(10 s idle timeout). Speed = action 6/7/8, or rewrite a preset via cmd 102.

Open: does `XXXX` survive a power-cycle; limits accepted by cmd 102 (cmd 101 suggests
600..3450); whether setup writes hit flash (wear) — prefer switching between three presets
over rewriting them continuously; behaviour of the pump when the link drops (it should just
keep its last state, as with the keypad — unverified).

## ESPHome firmware — 2026-10-03

`esphome/pool-pump.yaml` + external component `components/viron_pump/` (hub with the
handshake, crypto, polling and control methods; entities are template platforms in the YAML).
Compiles on ESPHome 2026.9.1 (esp-idf, esp32dev). **Not yet run on hardware.**
Needs the pump's real MAC (macOS only shows a CoreBluetooth UUID): the config logs a
`pump_finder` line with it on first boot.
