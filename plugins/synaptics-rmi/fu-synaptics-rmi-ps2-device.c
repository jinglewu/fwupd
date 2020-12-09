/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 * Copyright (c) 2020 Synaptics Incorporated.
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "fu-io-channel.h"

#include "fu-synaptics-rmi-ps2-device.h"

struct _FuSynapticsRmiPs2Device {
	FuSynapticsRmiDevice	 parent_instance;
	FuIOChannel		*io_channel;
	gboolean		 in_backdoor;
};

G_DEFINE_TYPE (FuSynapticsRmiPs2Device, fu_synaptics_rmi_ps2_device, FU_TYPE_SYNAPTICS_RMI_DEVICE)

static gboolean
fu_synaptics_rmi_ps2_device_read_ack (FuSynapticsRmiPs2Device *self,
				      guint8 *pbuf,
				      GError **error)
{
	for(guint i = 0 ; i < 60; i++) {
		g_autoptr(GError) error_local = NULL;
		if (!fu_io_channel_read_raw (self->io_channel, pbuf, 0x1,
					     NULL, 60,
					     FU_IO_CHANNEL_FLAG_NONE,
					     &error_local)) {
			if (g_error_matches (error_local, G_IO_ERROR, G_IO_ERROR_TIMED_OUT)) {
				g_warning ("read timed out: %u", i);
				g_usleep (30);
				continue;
			}
			g_propagate_error (error, g_steal_pointer (&error_local));
			return FALSE;
		}
		return TRUE;
	}
	g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed");
	return FALSE;
}

/* read a single byte from the touchpad */
static gboolean
fu_synaptics_rmi_ps2_device_read_byte (FuSynapticsRmiPs2Device *self,
				       guint8 *pbuf,
				       guint timeout,
				       GError **error)
{
	g_return_val_if_fail (timeout > 0, FALSE);
	return fu_io_channel_read_raw (self->io_channel, pbuf, 0x1,
				       NULL, timeout,
				       FU_IO_CHANNEL_FLAG_NONE,
				       error);
}

/* write a single byte to the touchpad and the read the acknowledge */
static gboolean
fu_synaptics_rmi_ps2_device_write_byte (FuSynapticsRmiPs2Device *self,
					guint8 buf,
					guint timeout,
					GError **error)
{
	gboolean do_write = TRUE;
	g_return_val_if_fail (timeout > 0, FALSE);
	for (guint i = 0; ; i++) {
		guint8 res = 0;
		g_autoptr(GError) error_local = NULL;
		if (do_write) {
			if (!fu_io_channel_write_raw (self->io_channel,
						      &buf, sizeof(buf),
						      timeout,
						      FU_IO_CHANNEL_FLAG_FLUSH_INPUT | 
						      FU_IO_CHANNEL_FLAG_USE_BLOCKING_IO,
						      error))
				return FALSE;
		}
		do_write = FALSE;

		/* attempt to read acknowledge... */
		if (!fu_synaptics_rmi_ps2_device_read_ack (self, &res, &error_local)) {
			if (i > 3) {
				g_propagate_prefixed_error (error,
							    g_steal_pointer (&error_local),
							    "read ack failed: ");
				return FALSE;
			}
			g_warning ("read ack failed: %s, retrying", error_local->message);
			continue;
		}
		if (res == edpsAcknowledge)
			break;
		if (res == edpsResend) {
			do_write = TRUE;
			g_usleep (G_USEC_PER_SEC);
			continue;
		}
		if (res == edpsError) {
			do_write = TRUE;
			g_usleep (1000 * 10);
			continue;
		}
		g_debug ("other response : 0x%x", res);
		g_usleep (1000 * 10);
	}

	/* success */
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_set_resolution_sequence (FuSynapticsRmiPs2Device *self,
						     guint8 arg,
						     gboolean send_e6s,
						     GError **error)
{
	/* send set scaling twice if send_e6s */
	for (gint i = send_e6s ? 2 : 1; i > 0; --i) {
		if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxSetScaling1To1, 50, error))
			return FALSE;
	}
	for (gint i = 3; i >= 0; --i) {
		guint8 ucTwoBitArg = (arg >> (i * 2)) & 0x3;
		if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxSetResolution, 50, error)) {
			return FALSE;
		}
		if (!fu_synaptics_rmi_ps2_device_write_byte (self, ucTwoBitArg, 50, error))
			return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_status_request_sequence (FuSynapticsRmiPs2Device *self,
							guint8 ucArgument, 
							guint32 *buf,
							GError **error)
{
	gboolean success = FALSE;

	// allow 3 retries
	for (gint i = 0; i < 3; ++i) {
		if (!fu_synaptics_rmi_ps2_device_set_resolution_sequence (self, ucArgument, FALSE, error)) {
			success = FALSE;
			continue;
		}
		if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxStatusRequest, 10, error)) {
			success = FALSE;
			continue;
		}
		success = TRUE;
		break;
	}

	if (success == FALSE) {
		return FALSE;
	}

	// Read the response from the Status Request
	guint8 aucBytes[3];
	memset(aucBytes, 0, sizeof(guint8) * 3);
	for (gint i = 0; i < 3; ++i) {
		if (!fu_synaptics_rmi_ps2_device_read_byte (self, &aucBytes[i], 10, error)) {
			g_prefix_error (error, "failed to read byte: ");
			return FALSE;
		}
		*buf = ((*buf) << 8) | aucBytes[i];
	}

	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_sample_rate_sequence (FuSynapticsRmiPs2Device *self,
						  guint8 param,
						  guint8 arg,
						  gboolean send_e6s,
						  GError **error)
{
	/* allow 3 retries */
	for (guint i = 0; ; i++) {
		g_autoptr(GError) error_local = NULL;
		if (i > 0) {
			/* always send two E6s when retrying */
			send_e6s = TRUE;
		}
		if (!fu_synaptics_rmi_ps2_device_set_resolution_sequence (self, arg, send_e6s, &error_local) ||
		    !fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxSetSampleRate, 50, &error_local) ||
		    !fu_synaptics_rmi_ps2_device_write_byte (self, param, 50, &error_local)) {
			if (i > 3) {
				g_propagate_error (error,
						   g_steal_pointer (&error_local));
				return FALSE;
			}
			g_warning ("failed, will retry: %s", error_local->message);
			continue;
		}
		break;
	}
	/* success */
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_detect_synaptics_styk (FuSynapticsRmiPs2Device *self, gboolean *result, GError **error)
{
	guint8 ucData;
	if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxIBMReadSecondaryID, 10, error)){
		g_prefix_error (error, "failed to write IBMReadSecondaryID(0xE1): ");
		return FALSE;
	}
	if (!fu_synaptics_rmi_ps2_device_read_byte (self, &ucData, 10, error)) {
		g_prefix_error (error, "failed to receive IBMReadSecondaryID: ");
		return FALSE;
	}
	if ((ucData == esdtJYTSyna) || (ucData == esdtSynaptics)) {
		g_debug ("Synaptics stick detected");
		*result = TRUE;
		return TRUE;
	} else {
		g_debug ("Non Synaptics stick detected");
		return FALSE;
	}
}

static gboolean 
fu_synaptics_rmi_ps2_device_query_build_id (FuSynapticsRmiDevice *rmi_device, 
						guint32 *build_id, 
						GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (rmi_device);
	*build_id = 0;
	guint32 buf = 0;
	enum EDeviceType deviceType;
	gboolean isSynapticsStyk = FALSE;

	self->in_backdoor = FALSE;

	if (!fu_synaptics_rmi_ps2_device_status_request_sequence (self, esrIdentifySynaptics, &buf, error)) {
		g_prefix_error (error, "failed to status request sequence for IdentifySynaptics: ");
		return FALSE;
	}

	g_debug ("Identify Synaptics response = 0x%x\n", buf);

	enum ESynapticsDeviceResponse esdr = (enum ESynapticsDeviceResponse)((buf & 0xFF00) >> 8);
	deviceType = (esdr == esdrTouchPad) ? edtTouchPad : edtUnknown;
	if (!fu_synaptics_rmi_ps2_device_detect_synaptics_styk(self, &isSynapticsStyk, error)) {
		g_prefix_error (error, "failed to detect Synaptics styk: ");
		return FALSE;
	}
	if ((deviceType == edtTouchPad) || isSynapticsStyk) {
		/// Get the firmware id from the Extra Capabilities 2 Byte
		// The firmware id is located in bits 0 - 23
		g_debug ("Trying to query capability2");
		buf = 0;
		if (!fu_synaptics_rmi_ps2_device_status_request_sequence (self, esrReadExtraCapabilities2, &buf, error)) {
			g_prefix_error (error, "failed to status_request_sequence read extraCapabilities2: ");
			return FALSE;
		} else {
			*build_id = buf;
			g_debug ("FW ID : %d", *build_id);
		}
	} 
	return TRUE;
}

static guint8 
fu_synaptics_rmi_ps2_device_query_product_sub_id (FuSynapticsRmiDevice *rmi_device, 
						GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (rmi_device);
	guint32 buf = 0;
	guint8 sub_id = 0;
	
	buf = 0;
	if (!fu_synaptics_rmi_ps2_device_status_request_sequence (self, esrReadCapabilities, &buf, error)) {
		g_prefix_error (error, "failed to status_request_sequence read esrReadCapabilities: ");
		return NULL;
	} else {
		sub_id = (buf >> 8) & 0xFF;
	}
	return sub_id;
}

static gboolean
fu_synaptics_rmi_ps2_device_enable_rmi_backdoor (FuSynapticsRmiPs2Device *self,
						 GError **error)
{
	if (self->in_backdoor)
		return TRUE;

	/* disable stream */
	if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxDisable, 50, error)) {
		g_prefix_error (error, "failed to disable stream mode: ");
		return FALSE;
	}

	/* enable RMI mode */
	g_debug ("enabling RMI backdoor");
	if (!fu_synaptics_rmi_ps2_device_sample_rate_sequence (self,
							       essrSetModeByte2,
							       edpAuxFullRMIBackDoor,
							       FALSE,
							       error)) {
		g_prefix_error (error, "failed to enter RMI mode: ");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_write_rmi_register (FuSynapticsRmiPs2Device *self,
						guint8 addr,
						const guint8 *buf,
						guint8 buflen,
						guint timeout,
						GError **error)
{
	g_return_val_if_fail (timeout > 0, FALSE);
	if (!fu_synaptics_rmi_ps2_device_enable_rmi_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable RMI backdoor: ");
		return FALSE;
	}
	if (!fu_synaptics_rmi_ps2_device_write_byte (self,
						     edpAuxSetScaling2To1,
						     timeout,
						     error)) {
		g_prefix_error (error, "failed to edpAuxSetScaling2To1: ");
		return FALSE;
	}
	if (!fu_synaptics_rmi_ps2_device_write_byte (self,
						     edpAuxSetSampleRate,
						     timeout,
						     error)) {
		g_prefix_error (error, "failed to edpAuxSetSampleRate: ");
		return FALSE;
	}
	if (!fu_synaptics_rmi_ps2_device_write_byte (self,
						     addr,
						     timeout,
						     error)) {
		g_prefix_error (error, "failed to write address: ");
		return FALSE;
	}
	for (guint8 i = 0; i < buflen; i++) {
		if (!fu_synaptics_rmi_ps2_device_write_byte (self,
							     edpAuxSetSampleRate,
							     timeout,
							     error)) {
			g_prefix_error (error, "failed to set byte %u: ", i);
			return FALSE;
		}
		if (!fu_synaptics_rmi_ps2_device_write_byte (self,
							     buf[i],
							     timeout,
							     error)) {
			g_prefix_error (error, "failed to write byte %u: ", i);
			return FALSE;
		}
	}

	/* success */
	g_usleep (1000 * 20);
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_read_rmi_register (FuSynapticsRmiPs2Device *self,
					       guint8 addr,
					       guint8 *buf,
					       GError **error)
{
	guint32 response = 0;

	g_return_val_if_fail (buf != NULL, FALSE);

	if (!fu_synaptics_rmi_ps2_device_enable_rmi_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable RMI backdoor: ");
		return FALSE;
	}
	if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxSetScaling2To1, 50, error) ||
	    !fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxSetSampleRate, 50, error) ||
	    !fu_synaptics_rmi_ps2_device_write_byte (self, addr, 50, error) ||
	    !fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxStatusRequest, 50, error)) {
		g_prefix_error (error, "failed to write command in Read RMI register: ");
		return FALSE;
	}
	for (guint i = 0; i < 3; i++) {
		guint8 tmp = 0;
		if (!fu_synaptics_rmi_ps2_device_read_byte (self, &tmp, 500, error)) {
			g_prefix_error (error, "failed to read byte %u: ", i);
			return FALSE;
		}
		response = response | (tmp << (8 * i));
	}

	/* we only care about the least significant byte since that
	 * is what contains the value of the register at the address addr */
	*buf = (guint8) response;

	/* success */
	g_usleep (1000 * 20);
	return TRUE;
}

static GByteArray *
fu_synaptics_rmi_ps2_device_read_rmi_packet_register (FuSynapticsRmiPs2Device *self,
						      guint8 addr,
						      guint req_sz,
						      GError **error)
{
	g_autoptr(GByteArray) buf = g_byte_array_new ();

	if (!fu_synaptics_rmi_ps2_device_enable_rmi_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable RMI backdoor: ");
		return NULL;
	}
	if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxSetScaling2To1, 50, error) ||
	    !fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxSetSampleRate, 50, error) ||
	    !fu_synaptics_rmi_ps2_device_write_byte (self, addr, 50, error) ||
	    !fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxStatusRequest, 50, error)) {
		g_prefix_error (error, "failed to write command in Read RMI Packet Register: ");
		return NULL;
	}
	for (guint i = 0; i < req_sz; ++i) {
		guint8 tmp = 0;
		if (!fu_synaptics_rmi_ps2_device_read_byte (self, &tmp, 50, error)) {
			g_prefix_error (error, "failed to read byte %u: ", i);
			return NULL;
		}
		fu_byte_array_append_uint8 (buf, tmp);
	}

	g_usleep (1000 * 20);
	return g_steal_pointer (&buf);
}

static gboolean
fu_synaptics_rmi_ps2_device_query_status (FuSynapticsRmiDevice *rmi_device,
					  GError **error)
{
	/* this doesn't work in PS/2 mode */
	return TRUE;
}

static gboolean 
fu_synaptics_rmi_ps2_device_set_page (FuSynapticsRmiDevice *rmi_device,
				      guint8 page,
				      GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (rmi_device);
	if (!fu_synaptics_rmi_ps2_device_write_rmi_register (self,
							     RMI_DEVICE_PAGE_SELECT_REGISTER,
							     &page,
							     1,
							     20,
							     error)) {
		g_prefix_error (error, "failed to write page %u: ", page);
		return FALSE;
	}
	return TRUE;
}

static GByteArray *
fu_synaptics_rmi_ps2_device_read (FuSynapticsRmiDevice *rmi_device,
				  guint16 addr,
				  gsize req_sz,
				  GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (rmi_device);
	g_autoptr(GByteArray) buf = NULL;
	gboolean isPacketRegister = FALSE; //FIXME?! How do we know?!

	if (!fu_synaptics_rmi_device_set_page (rmi_device,
					       addr >> 8,
					       error)) {
		g_prefix_error (error, "failed to set RMI page:");
		return FALSE;
	}

	if (isPacketRegister){
		buf = fu_synaptics_rmi_ps2_device_read_rmi_packet_register (self,
									    addr,
									    req_sz,
									    error);
		if (buf == NULL) {
			g_prefix_error (error,
					"failed packet register read %x: ",
					addr);
			return FALSE;
		}
	} else {
		buf = g_byte_array_new ();
		for (guint i = 0; i < req_sz; i++) {
			guint8 tmp = 0x0;
			if (!fu_synaptics_rmi_ps2_device_read_rmi_register (self,
									    (guint8) ((addr & 0x00FF) + i),
									    &tmp,
									    error)) {
				g_prefix_error (error,
						"failed register read 0x%x: ",
						addr + i);
				return FALSE;
			}
			fu_byte_array_append_uint8 (buf, tmp);
		}
	}
	if (g_getenv ("FWUPD_SYNAPTICS_RMI_VERBOSE") != NULL) {
		fu_common_dump_full (G_LOG_DOMAIN, "PS2DeviceRead",
				     buf->data, buf->len,
				     80, FU_DUMP_FLAGS_NONE);
	}
	return g_steal_pointer (&buf);
}

static gboolean
fu_synaptics_rmi_ps2_device_write (FuSynapticsRmiDevice *rmi_device,
				   guint16 addr,
				   GByteArray *req,
				   GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (rmi_device);
	guint32 timeout = 999; //FIXME
	if (!fu_synaptics_rmi_device_set_page (rmi_device,
					       addr >> 8,
					       error)) {
		g_prefix_error (error, "failed to set RMI page: ");
		return FALSE;
	}
	if (!fu_synaptics_rmi_ps2_device_write_rmi_register (self,
							     addr & 0x00FF,
							     req->data,
							     req->len,
							     timeout,
							     error)) {
		g_prefix_error (error,
				"failed to write register %x: ",
				addr);
		return FALSE;
	}
	return TRUE;
}

static void
fu_synaptics_rmi_ps2_device_to_string (FuUdevDevice *device, guint idt, GString *str)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (device);
	fu_common_string_append_kb (str, idt, "InRmiBackdoor", self->in_backdoor);
}

static gboolean
fu_synaptics_rmi_ps2_device_probe (FuUdevDevice *device, GError **error)
{
	/* psmouse is the usual mode, but serio is needed for update */
	if (g_strcmp0 (fu_udev_device_get_driver (device), "serio_raw") == 0) {
		fu_device_add_flag (FU_DEVICE (device),
				    FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	} else {
		fu_device_remove_flag (FU_DEVICE (device),
				       FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	}

	/* set the physical ID */
	return fu_udev_device_set_physical_id (device, "platform", error);
}

static gboolean
fu_synaptics_rmi_ps2_device_open (FuUdevDevice *device, GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (device);
	guint8 buf[2] = { 0x0 };

	/* create channel */
	self->io_channel = fu_io_channel_unix_new (fu_udev_device_get_fd (device));

	/* in serio_raw mode */
	if (fu_device_has_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_IS_BOOTLOADER)) {

		/* clear out any data in the serio_raw queue */
		for(guint i = 0; i < 0xffff; i++) {
			guint8 tmp = 0;
			if (!fu_synaptics_rmi_ps2_device_read_byte (self, &tmp, 20, NULL))
				break;
		}

		/* send reset -- may take 300-500ms */
		if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxReset, 600, error)) {
			g_prefix_error (error, "failed to reset: ");
			return FALSE;
		}

		/* read the 0xAA 0x00 announcing the touchpad is ready */
		if (!fu_synaptics_rmi_ps2_device_read_byte(self, &buf[0], 500, error) ||
		    !fu_synaptics_rmi_ps2_device_read_byte(self, &buf[1], 500, error)) {
			g_prefix_error (error, "failed to read 0xAA00: ");
			return FALSE;
		}
		if (buf[0] != 0xAA || buf[1] != 0x00) {
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
				     "failed to read 0xAA00, got 0x%02X%02X: ",
				     buf[0], buf[1]);
			return FALSE;
		}

		/* disable the device so that it stops reporting finger data */
		if (!fu_synaptics_rmi_ps2_device_write_byte (self, edpAuxDisable, 50, error)) {
			g_prefix_error (error, "failed to disable stream mode: ");
			return FALSE;
		}
	}

	/* success */
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_close (FuUdevDevice *device, GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (device);
	fu_udev_device_set_fd (device, -1);
	g_clear_object (&self->io_channel);
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_write_firmware (FuDevice *device,
					    FuFirmware *firmware,
					    FwupdInstallFlags flags,
					    GError **error)
{
//	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (device);
	fu_device_sleep_with_progress (device, 5);
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_detach (FuDevice *device, GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (device);

	/* sanity check */
	if (fu_device_has_flag (device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER)) {
		g_debug ("already in bootloader mode, skipping");
		return TRUE;
	}

	/* put in serio_raw mode so that we can do register writes */
	if (!fu_udev_device_write_sysfs (FU_UDEV_DEVICE (device),
					 "drvctl", "serio_raw", error)) {
		g_prefix_error (error, "failed to write to drvctl: ");
		return FALSE;
	}

	/* rescan device */
	if (!fu_device_close (device, error))
		return FALSE;
	if (!fu_device_rescan (device, error))
		return FALSE;
	if (!fu_device_open (device, error))
		return FALSE;

	if (!fu_synaptics_rmi_ps2_device_enable_rmi_backdoor (self, error)){
		g_prefix_error (error, "failed to enable RMI backdoor: ");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_setup (FuDevice *device, GError **error)
{
	/* we can only scan the PDT in serio_raw mode */
	if (fu_device_has_flag (device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER))
		return fu_synaptics_rmi_device_setup (device, error);
	return TRUE;
}

static gboolean
fu_synaptics_rmi_ps2_device_attach (FuDevice *device, GError **error)
{
	FuSynapticsRmiPs2Device *self = FU_SYNAPTICS_RMI_PS2_DEVICE (device);

	/* sanity check */
	if (!fu_device_has_flag (device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER)) {
		g_debug ("already in runtime mode, skipping");
		return TRUE;
	}

	/* back to psmouse */
	if (!fu_udev_device_write_sysfs (FU_UDEV_DEVICE (device),
					 "drvctl", "psmouse", error)) {
		g_prefix_error (error, "failed to write to drvctl: ");
		return FALSE;
	}

	/* rescan device */
	self->in_backdoor = FALSE;
	return fu_device_rescan (device, error);
}

static void
fu_synaptics_rmi_ps2_device_init (FuSynapticsRmiPs2Device *self)
{
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_INTERNAL);
	fu_device_set_name (FU_DEVICE (self), "TouchStyk");
	fu_device_set_vendor (FU_DEVICE (self), "Synaptics");
	fu_device_set_vendor_id (FU_DEVICE (self), "HIDRAW:0x06CB");
	fu_udev_device_set_flags (FU_UDEV_DEVICE (self),
				  FU_UDEV_DEVICE_FLAG_OPEN_READ |
				  FU_UDEV_DEVICE_FLAG_OPEN_WRITE);
}

static void
fu_synaptics_rmi_ps2_device_finalize (GObject *object)
{
	G_OBJECT_CLASS (fu_synaptics_rmi_ps2_device_parent_class)->finalize (object);
}

static void
fu_synaptics_rmi_ps2_device_class_init (FuSynapticsRmiPs2DeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	FuDeviceClass *klass_device = FU_DEVICE_CLASS (klass);
	FuUdevDeviceClass *klass_udev = FU_UDEV_DEVICE_CLASS (klass);
	FuSynapticsRmiDeviceClass *klass_rmi = FU_SYNAPTICS_RMI_DEVICE_CLASS (klass);
	object_class->finalize = fu_synaptics_rmi_ps2_device_finalize;
	klass_device->attach = fu_synaptics_rmi_ps2_device_attach;
	klass_device->detach = fu_synaptics_rmi_ps2_device_detach;
	klass_device->setup = fu_synaptics_rmi_ps2_device_setup;
	klass_device->write_firmware = fu_synaptics_rmi_ps2_device_write_firmware;
	klass_udev->to_string = fu_synaptics_rmi_ps2_device_to_string;
	klass_udev->probe = fu_synaptics_rmi_ps2_device_probe;
	klass_udev->open = fu_synaptics_rmi_ps2_device_open;
	klass_udev->close = fu_synaptics_rmi_ps2_device_close;
	klass_rmi->read = fu_synaptics_rmi_ps2_device_read;
	klass_rmi->write = fu_synaptics_rmi_ps2_device_write;
	klass_rmi->set_page = fu_synaptics_rmi_ps2_device_set_page;
	klass_rmi->query_status = fu_synaptics_rmi_ps2_device_query_status;
	klass_rmi->query_build_id = fu_synaptics_rmi_ps2_device_query_build_id;
	klass_rmi->query_product_sub_id = fu_synaptics_rmi_ps2_device_query_product_sub_id;
}
