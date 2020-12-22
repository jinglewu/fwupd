/*
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

#include "fu-synaptics-rmi-device.h"

typedef enum {
	RMI_V5_FLASH_CMD_WRITE_FW_BLOCK			= 0x02,
	RMI_V5_FLASH_CMD_ERASE_ALL			= 0x03,
	RMI_V5_FLASH_CMD_WRITE_LOCKDOWN_BLOCK		= 0x04,
	RMI_V5_FLASH_CMD_WRITE_CONFIG_BLOCK		= 0x06,
	RMI_V5_FLASH_CMD_ENABLE_FLASH_PROG		= 0x0f,
} RmiFlashCommandV5;

gboolean	 fu_synaptics_rmi_v5_device_write_firmware	(FuDevice	*device,
								 FuFirmware	*firmware,
								 FwupdInstallFlags flags,
								 GError		**error);
gboolean	 fu_synaptics_rmi_v5_device_setup		(FuSynapticsRmiDevice	*self,
								 GError			**error);
gboolean	 fu_synaptics_rmi_v5_device_query_status	(FuSynapticsRmiDevice	*self,
								 GError			**error);
gboolean 	 fu_synaptics_rmi_v5_device_secure_check (FuDevice *device,
					   			 FuFirmware *firmware,
					   			 GError **error);
