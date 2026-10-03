#pragma once

#ifdef USE_ESP32

#include <array>
#include <deque>
#include <string>

#include "esphome/components/ble_client/ble_client.h"
#include "esphome/core/component.h"

namespace esphome {
namespace viron_pump {

static const uint8_t FRAME_LEN = 20;
static const uint8_t KEY_LEN = 16;

enum Speed : uint8_t { SPEED_LOW = 0, SPEED_MEDIUM = 1, SPEED_HIGH = 2 };

// Client for an AstralPool Viron XT pump ("HPUMP"), which speaks the Halo protocol:
// read a session key, answer with AES(session ^ access code), then exchange
// AES-wrapped 20-byte frames [type][cmd u16le][body]. See NOTES.md.
class VironPump : public PollingComponent, public ble_client::BLEClientNode {
 public:
  void set_access_code(const std::string &code) { this->access_code_ = code; }

  void loop() override;
  void update() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::DATA; }
  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;

  // State, valid once has_state() / has_setup() / has_telemetry() are true.
  bool is_authenticated() const { return this->authenticated_; }
  bool has_state() const { return this->authenticated_ && this->has_state_; }
  bool has_setup() const { return this->authenticated_ && this->has_setup_; }
  bool has_telemetry() const { return this->authenticated_ && this->has_telemetry_; }
  bool running() const { return this->run_state_ != 0; }
  bool priming() const { return (this->flags_ & 0x0100) != 0; }
  uint8_t speed() const { return this->speed_; }
  uint16_t target_rpm() const { return this->running() ? this->target_rpm_ : 0; }
  uint16_t power_w() const { return this->power_w_; }
  uint16_t preset_rpm(uint8_t speed) const { return speed < 3 ? this->preset_rpm_[speed] : 0; }
  uint16_t min_rpm() const { return this->min_rpm_; }
  uint16_t max_rpm() const { return this->max_rpm_; }

  // Control.
  void start() { this->send_action_(ACTION_START); }
  void stop() { this->send_action_(ACTION_STOP); }
  void select_speed(uint8_t speed);
  // Rewrites a stored preset on the pump; the motor follows at once if that preset
  // is the selected one. Not meant to be called in a tight loop.
  void set_preset_rpm(uint8_t speed, uint16_t rpm);

 protected:
  enum : uint8_t { FRAME_RESPONSE = 1, FRAME_READ = 2, FRAME_WRITE = 3 };
  enum : uint16_t { CMD_STATE = 100, CMD_CAPABILITIES = 101, CMD_SETUP = 102, CMD_ACTION = 103, CMD_TELEMETRY = 105 };
  enum : uint8_t { ACTION_STOP = 1, ACTION_START = 3, ACTION_SELECT_LOW = 6 };
  static const uint8_t SETUP_LEN = 13;

  using Frame = std::array<uint8_t, FRAME_LEN>;

  void reset_();
  void queue_frame_(uint8_t type, uint16_t cmd, const uint8_t *body = nullptr, size_t len = 0);
  void send_action_(uint8_t action);
  void handle_frame_(const uint8_t *plain);
  void crypt_frame_(uint8_t *frame, bool encrypt) const;
  void aes_block_(const uint8_t *in, uint8_t *out, bool encrypt) const;

  std::string access_code_;
  uint8_t session_key_[KEY_LEN]{};
  uint16_t session_handle_{0};
  uint16_t auth_handle_{0};
  uint16_t tx_handle_{0};  // pump -> us (notify)
  uint16_t rx_handle_{0};  // us -> pump (write)
  bool authenticated_{false};

  std::deque<Frame> queue_;
  uint32_t last_tx_{0};
  uint32_t polls_{0};

  bool has_state_{false};
  bool has_setup_{false};
  bool has_telemetry_{false};
  uint8_t run_state_{0};
  uint8_t speed_{0};
  uint16_t flags_{0};
  uint16_t target_rpm_{0};
  uint16_t power_w_{0};
  uint16_t preset_rpm_[3]{};
  uint8_t setup_[SETUP_LEN]{};
  uint16_t min_rpm_{600};
  uint16_t max_rpm_{3450};
};

}  // namespace viron_pump
}  // namespace esphome

#endif  // USE_ESP32
