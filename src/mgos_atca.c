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

#include "mgos_atca.h"

#include "common/cs_dbg.h"

#include "mongoose.h"

#include "mgos_i2c.h"
#include "mgos_sys_config.h"
#include "mgos_system.h"

#include "atca_basic.h"

bool s_atca_is_available = false;
static bool s_is_608 = false;

/* Invoked from mbedTLS during ECDH phase of the handshake. */
int mbedtls_atca_is_available() {
  return s_atca_is_available;
}

int mbedtls_atca_is_608(void) {
  return s_is_608;
}

uint16_t mbedtls_atca_get_ecdh_slots_mask() {
  return mgos_sys_config_get_sys_atca_ecdh_slots_mask();
}

bool mgos_atca_init(void) {
  uint32_t revision;
  uint32_t
      serial[(ATCA_SERIAL_NUM_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
  bool config_is_locked, data_is_locked;
  ATCA_STATUS status;
  ATCAIfaceCfg *atca_cfg;

  if (!mgos_sys_config_get_sys_atca_enable()) {
    return true;
  }

  if (mgos_i2c_get_bus(mgos_sys_config_get_sys_atca_i2c_bus()) == NULL) {
    LOG(LL_ERROR, ("ATCA requires I2C to be enabled (i2c.enable=true)"));
    return false;
  }

  uint8_t addr = mgos_sys_config_get_sys_atca_i2c_addr();
  /*
   * It's a bit unfortunate that Atmel requires address already shifted by 1.
   * If user specifies address > 0x80, it must be already shifted since I2C bus
   * addresses > 0x7f are invalid.
   */
  if (addr < 0x7f) addr <<= 1;
  atca_cfg = &cfg_ateccx08a_i2c_default;
  if (atca_cfg->atcai2c.slave_address != addr) {
    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *) calloc(1, sizeof(*cfg));
    memcpy(cfg, &cfg_ateccx08a_i2c_default, sizeof(*cfg));
    cfg->atcai2c.slave_address = addr;
    atca_cfg = cfg;
  }

  status = atcab_init(atca_cfg);
  if (status != ATCA_SUCCESS) {
    LOG(LL_ERROR, ("ATCA: Library init failed"));
    goto out;
  }

  status = atcab_info((uint8_t *) &revision);
  if (status != ATCA_SUCCESS) {
    LOG(LL_ERROR, ("ATCA: Failed to get chip info (%d/0x%x)",
                   mgos_sys_config_get_sys_atca_i2c_bus(),
                   (atca_cfg->atcai2c.slave_address >> 1)));
    goto out;
  }

  status = atcab_read_serial_number((uint8_t *) serial);
  if (status != ATCA_SUCCESS) {
    LOG(LL_ERROR, ("ATCA: Failed to get chip serial number"));
    goto out;
  }

  status = atcab_is_locked(LOCK_ZONE_CONFIG, &config_is_locked);
  status = atcab_is_locked(LOCK_ZONE_DATA, &data_is_locked);
  if (status != ATCA_SUCCESS) {
    LOG(LL_ERROR, ("ATCA: Failed to get chip zone lock status"));
    goto out;
  }

  s_is_608 = (htonl(revision) >= 0x6000);

  LOG(LL_INFO,
      ("%s @ %d/0x%02x: rev 0x%04x S/N 0x%04x%04x%02x, zone "
       "lock status: %s, %s; ECDH slots: 0x%02x",
       (s_is_608 ? "ATECC608A" : "ATECC508A"),
       mgos_sys_config_get_sys_atca_i2c_bus(), (unsigned int) (addr >> 1),
       (unsigned int) htonl(revision), (unsigned int) htonl(serial[0]),
       (unsigned int) htonl(serial[1]), *((uint8_t *) &serial[2]),
       (config_is_locked ? "yes" : "no"), (data_is_locked ? "yes" : "no"),
       mbedtls_atca_get_ecdh_slots_mask()));

  s_atca_is_available = true;

out:
  /*
   * We do not free atca_cfg in case of an error even if it was allocated
   * because it is referenced by ATCA basic object.
   */
  if (status != ATCA_SUCCESS) {
    LOG(LL_ERROR, ("ATCA: Chip is not available"));
    /* In most cases the device can still work, so we continue anyway. */
  }
  return true;
}
