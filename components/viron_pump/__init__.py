import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import ble_client
from esphome.const import CONF_ID

DEPENDENCIES = ["ble_client", "esp32"]

CONF_ACCESS_CODE = "access_code"

viron_pump_ns = cg.esphome_ns.namespace("viron_pump")
VironPump = viron_pump_ns.class_(
    "VironPump", cg.PollingComponent, ble_client.BLEClientNode
)


def access_code(value):
    value = cv.string_strict(value)
    if len(value) != 4:
        raise cv.Invalid("access_code must be exactly 4 characters")
    return value


CONFIG_SCHEMA = (
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(VironPump),
            cv.Required(CONF_ACCESS_CODE): access_code,
        }
    )
    .extend(cv.polling_component_schema("2s"))
    .extend(ble_client.BLE_CLIENT_SCHEMA)
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)
    cg.add(var.set_access_code(config[CONF_ACCESS_CODE]))
