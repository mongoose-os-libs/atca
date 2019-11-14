/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"

#include "common/cs_dbg.h"

#include "mongoose.h"

#include "mgos_hal.h"
#include "mgos_i2c.h"
#include "mgos_sys_config.h"

#include "cryptoauthlib.h"
#include "hal/atca_hal.h"
#include "host/atca_host.h"

/*
 * This is a HAL implementation for the Atmel/Microchip CryptoAuthLib.
 * It translates ATCA interface calls into MGOS API calls.
 * Currently only I2C is implemented.
 */
static ATCA_STATUS mgos_atca_hal_i2c_init(void *hal, ATCAIfaceCfg *cfg) {
  (void) hal;
  (void) cfg;
  return ATCA_SUCCESS;
}

static ATCA_STATUS mgos_atca_hal_i2c_post_init(ATCAIface iface) {
  (void) iface;
  return ATCA_SUCCESS;
}

static ATCA_STATUS mgos_atca_hal_i2c_send(ATCAIface iface, uint8_t *txdata,
                                          int txlength) {
  const ATCAIfaceCfg *cfg = atgetifacecfg(iface);
  struct mgos_i2c *i2c = (struct mgos_i2c *) atgetifacehaldat(iface);

  ATCA_STATUS status = ATCA_TX_TIMEOUT;

  if (txlength > 0) {
    txdata[0] = 0x03; /* Word Address Value = Command */
  } else {
    /* This is our (MGOS) extension. In this mode WAV is set by wake or idle. */
  }
  txlength++; /* Include Word Address value in txlength */

  if (mgos_i2c_write(i2c, (cfg->atcai2c.slave_address >> 1), txdata, txlength,
                     true /* stop */)) {
    status = ATCA_SUCCESS;
  } else {
    status = ATCA_TX_FAIL;
  }
  return status;
}

static ATCA_STATUS mgos_atca_hal_i2c_receive(ATCAIface iface, uint8_t *rxdata,
                                             uint16_t *rxlength) {
  const ATCAIfaceCfg *cfg = atgetifacecfg(iface);
  struct mgos_i2c *i2c = (struct mgos_i2c *) atgetifacehaldat(iface);

  ATCA_STATUS status = ATCA_RX_TIMEOUT;

  int retries = cfg->rx_retries;

  while (retries-- > 0) {
    uint8_t count;
    if (!mgos_i2c_read(i2c, (cfg->atcai2c.slave_address >> 1), rxdata, 1,
                       false /* stop */)) {
      continue;
    }
    count = rxdata[0];
    if ((count < ATCA_RSP_SIZE_MIN) || (count > *rxlength)) {
      mgos_i2c_stop(i2c);
      status = ATCA_INVALID_SIZE;
      break;
    }
    if (!mgos_i2c_read(i2c, MGOS_I2C_ADDR_CONTINUE, rxdata + 1, count - 1,
                       true /* stop */)) {
      continue;
    }
    status = ATCA_SUCCESS;
    break;
  }
  /*
   * rxlength is a pointer, which suggests that the actual number of bytes
   * received should be returned in the value pointed to, but none of the
   * existing HAL implementations do it.
   */
  return status;
}

static ATCA_STATUS mgos_atca_hal_i2c_wake(ATCAIface iface) {
  const ATCAIfaceCfg *cfg = atgetifacecfg(iface);
  struct mgos_i2c *i2c = (struct mgos_i2c *) atgetifacehaldat(iface);

  ATCA_STATUS status = ATCA_WAKE_FAILED;

  uint8_t response[4] = {0x00, 0x00, 0x00, 0x00};
  uint8_t expected_response[4] = {0x04, 0x11, 0x33, 0x43};

  /*
   * ATCA devices define "wake up" token as START, 80 us of SDA low, STOP.
   * Simulate this by trying to send 0 bytes to address 0 @ 100 kHz. This will
   * fail, but we're not expecting an ACK, so don't check for return value.
   */
  int old_freq = mgos_i2c_get_freq(i2c);
  mgos_i2c_set_freq(i2c, MGOS_I2C_FREQ_100KHZ);
  mgos_i2c_write(i2c, 0, response, 1, true /* stop */);
  mgos_i2c_set_freq(i2c, old_freq);

  /* After wake signal we need to wait some time for device to init. */
  atca_delay_us(cfg->wake_delay);

  /* Receive the wake response. */
  uint16_t len = sizeof(response);
  status = mgos_atca_hal_i2c_receive(iface, response, &len);
  if (status == ATCA_SUCCESS) {
    if (memcmp(response, expected_response, 4) != 0) {
      status = ATCA_WAKE_FAILED;
    }
  }

  return status;
}

ATCA_STATUS mgos_atca_hal_i2c_idle(ATCAIface iface) {
  uint8_t idle_cmd = 0x02;
  return mgos_atca_hal_i2c_send(iface, &idle_cmd, 0);
}

ATCA_STATUS mgos_atca_hal_i2c_sleep(ATCAIface iface) {
  uint8_t sleep_cmd = 0x01;
  return mgos_atca_hal_i2c_send(iface, &sleep_cmd, 0);
}

ATCA_STATUS mgos_atca_hal_i2c_release(void *hal_data) {
  (void) hal_data;
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_iface_init(ATCAIfaceCfg *cfg, ATCAHAL_t *hal) {
  if (cfg->iface_type != ATCA_I2C_IFACE) return ATCA_BAD_PARAM;
  struct mgos_i2c *i2c =
      mgos_i2c_get_bus(mgos_sys_config_get_sys_atca_i2c_bus());
  if (i2c == NULL) return ATCA_GEN_FAIL;
  hal->halinit = &mgos_atca_hal_i2c_init;
  hal->halpostinit = &mgos_atca_hal_i2c_post_init;
  hal->halsend = &mgos_atca_hal_i2c_send;
  hal->halreceive = &mgos_atca_hal_i2c_receive;
  hal->halwake = &mgos_atca_hal_i2c_wake;
  hal->halidle = &mgos_atca_hal_i2c_idle;
  hal->halsleep = &mgos_atca_hal_i2c_sleep;
  hal->halrelease = &mgos_atca_hal_i2c_release;
  hal->hal_data = i2c;
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_iface_release(ATCAIfaceType ifacetype, void *hal_data) {
  if (ifacetype != ATCA_I2C_IFACE) return ATCA_BAD_PARAM;
  /* I2C connection is global, do not free. */
  (void) hal_data;
  return ATCA_SUCCESS;
}
