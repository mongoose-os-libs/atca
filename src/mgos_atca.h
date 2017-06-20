/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_FW_SRC_MGOS_ATCA_H_
#define CS_FW_SRC_MGOS_ATCA_H_

#include "fw/src/mgos_features.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool mgos_atca_init(void);
bool mbedtls_atca_is_available();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CS_FW_SRC_MGOS_ATCA_H_ */
