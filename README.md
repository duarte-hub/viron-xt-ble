# viron-xt-ble

Control an AstralPool **Viron XT** variable-speed pool pump over Bluetooth LE from an ESP32
(ESPHome), without a Halo chlorinator.

The pump advertises as `HPUMP` and speaks the same protocol as the AstralPool Halo
chlorinators, which [pychlorinator](https://github.com/pbutterworth/pychlorinator) had already
reverse engineered. This repo adds the pump side: the command map, the control commands, and
an ESPHome component. Everything known is written up in [NOTES.md](NOTES.md).

Tested on one pump: a Viron P320C XT, firmware 5.1. The ESPHome component compiles but has
had little time on real hardware — treat it as experimental.

## What works

- Start / stop
- Select low / medium / high
- Set the RPM of each preset (600–3450)
- Read state (running, priming, selected speed, target RPM) and power draw

## Getting the access code

The pump only talks to a client that knows its 4-character access code. It broadcasts the
code in its advertisement for about 100 seconds after a mains power-cycle:

```
uv run tools/probe.py watch     # then switch the pump off at the wall, wait 30 s, back on
```

## ESPHome

Copy [`esphome/pool-pump.yaml`](esphome/pool-pump.yaml) and fill in `secrets.yaml` from
[`secrets.yaml.example`](esphome/secrets.yaml.example). The component is pulled from this
repo:

```yaml
external_components:
  - source: github://duarte-hub/viron-xt-ble
    components: [viron_pump]

ble_client:
  - mac_address: !secret pump_mac
    id: pump_ble

viron_pump:
  id: pump
  ble_client_id: pump_ble
  access_code: !secret pump_access_code
```

Entities are template platforms calling the component, e.g. `id(pump).start()`,
`id(pump).select_speed(1)`, `id(pump).set_preset_rpm(1, 2000)`.

The pump accepts one BLE connection at a time and drops a link that is idle for 10 s.

## Tools

Python scripts used for the reverse engineering, run with [uv](https://docs.astral.sh/uv/):

| script | does |
|---|---|
| `tools/probe.py` | scan, dump GATT, watch for the access code (read-only) |
| `tools/auth.py` | handshake and listen |
| `tools/sweep.py` | read request for every command id |
| `tools/monitor.py` | poll and print value changes |
| `tools/write.py` | send one write frame — **changes pump state** |

## Disclaimer

Unofficial and not affiliated with AstralPool or Fluidra. This drives a mains-powered motor;
use it at your own risk.
