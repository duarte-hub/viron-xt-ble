#include "viron_pump.h"

#ifdef USE_ESP32

#include <algorithm>
#include <cstring>

#include "esphome/core/hal.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "mbedtls/aes.h"

namespace esphome {
namespace viron_pump {

static const char *const TAG = "viron_pump";

static const char *const SERVICE_UUID = "45000001-98b7-4e29-a03f-160174643002";
static const char *const SESSION_KEY_UUID = "45000001-98b7-4e29-a03f-160174643002";
static const char *const AUTH_UUID = "45000002-98b7-4e29-a03f-160174643002";
static const char *const TX_UUID = "45000003-98b7-4e29-a03f-160174643002";
static const char *const RX_UUID = "45000004-98b7-4e29-a03f-160174643002";

// Shared by every AstralPool/Fabtronics BLE device (it is the NIST AES test key).
static const uint8_t SECRET_KEY[KEY_LEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

// The pump drops a link that is silent for 10 s, and one frame per connection
// interval is as fast as it answers.
static const uint32_t TX_GAP_MS = 150;
static const uint8_t SETUP_REFRESH_POLLS = 30;

static uint16_t u16le(const uint8_t *p) { return p[0] | (p[1] << 8); }

void VironPump::dump_config() {
  ESP_LOGCONFIG(TAG, "Viron XT pump:");
  ESP_LOGCONFIG(TAG, "  Access code: %s", this->access_code_.c_str());
  LOG_UPDATE_INTERVAL(this);
}

void VironPump::reset_() {
  this->authenticated_ = false;
  this->has_state_ = this->has_setup_ = this->has_telemetry_ = false;
  this->session_handle_ = this->auth_handle_ = this->tx_handle_ = this->rx_handle_ = 0;
  this->queue_.clear();
  this->polls_ = 0;
}

void VironPump::aes_block_(const uint8_t *in, uint8_t *out, bool encrypt) const {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (encrypt) {
    mbedtls_aes_setkey_enc(&ctx, SECRET_KEY, 128);
  } else {
    mbedtls_aes_setkey_dec(&ctx, SECRET_KEY, 128);
  }
  mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, in, out);
  mbedtls_aes_free(&ctx);
}

// A frame is XORed with the session key (first 16 bytes), then bytes 0..15 and
// bytes 4..19 are each run through AES-ECB. Decryption undoes that in reverse.
void VironPump::crypt_frame_(uint8_t *frame, bool encrypt) const {
  uint8_t block[KEY_LEN];
  if (encrypt) {
    for (uint8_t i = 0; i < KEY_LEN; i++)
      frame[i] ^= this->session_key_[i];
    this->aes_block_(frame, block, true);
    memcpy(frame, block, KEY_LEN);
    this->aes_block_(frame + 4, block, true);
    memcpy(frame + 4, block, KEY_LEN);
  } else {
    this->aes_block_(frame + 4, block, false);
    memcpy(frame + 4, block, KEY_LEN);
    this->aes_block_(frame, block, false);
    memcpy(frame, block, KEY_LEN);
    for (uint8_t i = 0; i < KEY_LEN; i++)
      frame[i] ^= this->session_key_[i];
  }
}

void VironPump::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                    esp_ble_gattc_cb_param_t *param) {
  switch (event) {
    case ESP_GATTC_OPEN_EVT:
      if (param->open.status == ESP_GATT_OK)
        this->reset_();
      break;

    case ESP_GATTC_DISCONNECT_EVT:
      ESP_LOGW(TAG, "Disconnected from pump");
      this->reset_();
      break;

    case ESP_GATTC_SEARCH_CMPL_EVT: {
      auto service = esp32_ble_tracker::ESPBTUUID::from_raw(SERVICE_UUID);
      auto find = [&](const char *uuid) -> uint16_t {
        auto *chr = this->parent()->get_characteristic(service, esp32_ble_tracker::ESPBTUUID::from_raw(uuid));
        return chr == nullptr ? 0 : chr->handle;
      };
      this->session_handle_ = find(SESSION_KEY_UUID);
      this->auth_handle_ = find(AUTH_UUID);
      this->tx_handle_ = find(TX_UUID);
      this->rx_handle_ = find(RX_UUID);
      if (!this->session_handle_ || !this->auth_handle_ || !this->tx_handle_ || !this->rx_handle_) {
        ESP_LOGE(TAG, "Pump service/characteristics not found - is this the right device?");
        break;
      }
      auto status = esp_ble_gattc_read_char(gattc_if, this->parent()->get_conn_id(), this->session_handle_,
                                            ESP_GATT_AUTH_REQ_NONE);
      if (status != ESP_OK)
        ESP_LOGW(TAG, "Session key read failed, status=%d", status);
      break;
    }

    case ESP_GATTC_READ_CHAR_EVT: {
      if (param->read.handle != this->session_handle_)
        break;
      if (param->read.status != ESP_GATT_OK || param->read.value_len != KEY_LEN) {
        ESP_LOGW(TAG, "Bad session key read, status=%d len=%d", param->read.status, param->read.value_len);
        break;
      }
      memcpy(this->session_key_, param->read.value, KEY_LEN);

      uint8_t mac[KEY_LEN];
      memcpy(mac, this->session_key_, KEY_LEN);
      for (size_t i = 0; i < this->access_code_.size() && i < KEY_LEN; i++)
        mac[i] ^= static_cast<uint8_t>(this->access_code_[i]);
      uint8_t encrypted[KEY_LEN];
      this->aes_block_(mac, encrypted, true);

      // Subscribe before authenticating so nothing the pump pushes is missed.
      esp_ble_gattc_register_for_notify(gattc_if, this->parent()->get_remote_bda(), this->tx_handle_);
      auto status = esp_ble_gattc_write_char(gattc_if, this->parent()->get_conn_id(), this->auth_handle_, KEY_LEN,
                                             encrypted, ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
      if (status != ESP_OK)
        ESP_LOGW(TAG, "Auth write failed, status=%d", status);
      break;
    }

    case ESP_GATTC_WRITE_CHAR_EVT: {
      if (param->write.handle != this->auth_handle_ || this->authenticated_)
        break;
      if (param->write.status != ESP_GATT_OK) {
        ESP_LOGW(TAG, "Auth write rejected, status=%d", param->write.status);
        break;
      }
      // A wrong access code makes the pump drop the link ~100 ms after this point.
      ESP_LOGI(TAG, "Authentication sent");
      this->authenticated_ = true;
      this->node_state = esp32_ble_tracker::ClientState::ESTABLISHED;
      this->queue_frame_(FRAME_READ, CMD_CAPABILITIES);
      this->queue_frame_(FRAME_READ, CMD_SETUP);
      this->queue_frame_(FRAME_READ, CMD_STATE);
      this->queue_frame_(FRAME_READ, CMD_TELEMETRY);
      break;
    }

    case ESP_GATTC_NOTIFY_EVT: {
      if (param->notify.handle != this->tx_handle_ || param->notify.value_len != FRAME_LEN)
        break;
      uint8_t plain[FRAME_LEN];
      memcpy(plain, param->notify.value, FRAME_LEN);
      this->crypt_frame_(plain, false);
      this->handle_frame_(plain);
      break;
    }

    default:
      break;
  }
}

void VironPump::handle_frame_(const uint8_t *plain) {
  uint16_t cmd = u16le(plain + 1);
  const uint8_t *body = plain + 3;
  ESP_LOGV(TAG, "RX type=%u cmd=%u body=%s", plain[0], cmd, format_hex_pretty(body, FRAME_LEN - 3).c_str());
  if (plain[0] != FRAME_RESPONSE)
    return;

  switch (cmd) {
    case CMD_STATE:
      this->run_state_ = body[0];
      this->speed_ = body[1];
      this->flags_ = u16le(body + 4);
      this->target_rpm_ = u16le(body + 6);
      this->has_state_ = true;
      break;
    case CMD_CAPABILITIES: {
      uint16_t max_rpm = u16le(body), min_rpm = u16le(body + 4);
      if (min_rpm >= 300 && max_rpm <= 4000 && min_rpm < max_rpm) {
        this->max_rpm_ = max_rpm;
        this->min_rpm_ = min_rpm;
      }
      break;
    }
    case CMD_SETUP:
      memcpy(this->setup_, body, SETUP_LEN);
      for (uint8_t i = 0; i < 3; i++)
        this->preset_rpm_[i] = u16le(body + 2 * i);
      this->has_setup_ = true;
      break;
    case CMD_TELEMETRY:
      this->power_w_ = u16le(body + 4);
      this->has_telemetry_ = true;
      break;
    default:
      break;
  }
}

void VironPump::queue_frame_(uint8_t type, uint16_t cmd, const uint8_t *body, size_t len) {
  Frame frame{};
  frame[0] = type;
  frame[1] = cmd & 0xff;
  frame[2] = cmd >> 8;
  if (body != nullptr)
    memcpy(frame.data() + 3, body, std::min(len, static_cast<size_t>(FRAME_LEN - 3)));
  this->queue_.push_back(frame);
}

void VironPump::send_action_(uint8_t action) {
  if (!this->authenticated_) {
    ESP_LOGW(TAG, "Not connected to the pump, action %u dropped", action);
    return;
  }
  this->queue_frame_(FRAME_WRITE, CMD_ACTION, &action, 1);
  this->queue_frame_(FRAME_READ, CMD_STATE);
}

void VironPump::select_speed(uint8_t speed) {
  if (speed > SPEED_HIGH)
    return;
  this->send_action_(ACTION_SELECT_LOW + speed);
}

void VironPump::set_preset_rpm(uint8_t speed, uint16_t rpm) {
  if (speed > SPEED_HIGH)
    return;
  // The write replaces the whole setup block, so it needs the current one first.
  if (!this->has_setup()) {
    ESP_LOGW(TAG, "Pump setup not read yet, preset change dropped");
    return;
  }
  rpm = clamp<uint16_t>(rpm, this->min_rpm_, this->max_rpm_);
  if (rpm == this->preset_rpm_[speed])
    return;
  uint8_t setup[SETUP_LEN];
  memcpy(setup, this->setup_, SETUP_LEN);
  setup[2 * speed] = rpm & 0xff;
  setup[2 * speed + 1] = rpm >> 8;
  ESP_LOGI(TAG, "Setting preset %u to %u rpm", speed, rpm);
  this->queue_frame_(FRAME_WRITE, CMD_SETUP, setup, SETUP_LEN);
  this->queue_frame_(FRAME_READ, CMD_SETUP);
  this->queue_frame_(FRAME_READ, CMD_STATE);
}

void VironPump::update() {
  if (!this->authenticated_)
    return;
  // Polling doubles as the keep-alive. Skip a round if the queue is backed up.
  if (this->queue_.size() > 4)
    return;
  this->queue_frame_(FRAME_READ, CMD_STATE);
  this->queue_frame_(FRAME_READ, CMD_TELEMETRY);
  if (++this->polls_ % SETUP_REFRESH_POLLS == 0)
    this->queue_frame_(FRAME_READ, CMD_SETUP);
}

void VironPump::loop() {
  if (!this->authenticated_ || this->queue_.empty())
    return;
  uint32_t now = millis();
  if (now - this->last_tx_ < TX_GAP_MS)
    return;
  this->last_tx_ = now;

  Frame frame = this->queue_.front();
  this->queue_.pop_front();
  ESP_LOGV(TAG, "TX %s", format_hex_pretty(frame.data(), FRAME_LEN).c_str());
  this->crypt_frame_(frame.data(), true);
  auto status = esp_ble_gattc_write_char(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                         this->rx_handle_, FRAME_LEN, frame.data(), ESP_GATT_WRITE_TYPE_RSP,
                                         ESP_GATT_AUTH_REQ_NONE);
  if (status != ESP_OK)
    ESP_LOGW(TAG, "Frame write failed, status=%d", status);
}

}  // namespace viron_pump
}  // namespace esphome

#endif  // USE_ESP32
