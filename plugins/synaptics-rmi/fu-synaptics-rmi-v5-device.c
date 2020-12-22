/*
 * Copyright (C) 2012-2014 Andrew Duggan
 * Copyright (C) 2012-2019 Synaptics Inc.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "fu-chunk.h"
#include "fu-common.h"
#include "fu-synaptics-rmi-device.h"
#include "fu-synaptics-rmi-v5-device.h"
#include "fu-synaptics-rmi-firmware.h"
#include "fwupd-error.h"

#define RMI_F34_BLOCK_SIZE_OFFSET			1
#define RMI_F34_FW_BLOCKS_OFFSET			3
#define RMI_F34_CONFIG_BLOCKS_OFFSET			5

#define RMI_V5_FLASH_CMD_ERASE_WAIT_MS			(5 * 1000)	/* ms */

static gboolean
fu_synaptics_rmi_v5_device_erase_all (FuSynapticsRmiDevice *self, GError **error)
{
	FuSynapticsRmiFunction *f34;
	FuSynapticsRmiFlash *flash = fu_synaptics_rmi_device_get_flash (self);
	g_autoptr(GByteArray) erase_cmd = g_byte_array_new ();

	/* f34 */
	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	/* all other versions */
	fu_byte_array_append_uint8 (erase_cmd, RMI_V5_FLASH_CMD_ERASE_ALL);
	if (!fu_synaptics_rmi_device_write (self,
					    flash->status_addr,
					    erase_cmd,
					    error)) {
		g_prefix_error (error, "failed to erase core config: ");
		return FALSE;
	}
	g_usleep (1000 * RMI_V5_FLASH_CMD_ERASE_WAIT_MS);
	if (!fu_synaptics_rmi_device_wait_for_idle (self,
						    RMI_V5_FLASH_CMD_ERASE_WAIT_MS,
						    RMI_DEVICE_WAIT_FOR_IDLE_FLAG_REFRESH_F34,
						    error)) {
		g_prefix_error (error, "failed to wait for idle for erase: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_synaptics_rmi_v5_device_write_block (FuSynapticsRmiDevice *self,
					guint8 cmd,
					guint32 address,
					const guint8 *data,
					gsize datasz,
					GError **error)
{
	g_autoptr(GByteArray) req = g_byte_array_new ();

	g_byte_array_append (req, data, datasz);
	fu_byte_array_append_uint8 (req, cmd);
	if (!fu_synaptics_rmi_device_write (self, address, req, error)) {
		g_prefix_error (error, "failed to write block @0x%x: ", address);
		return FALSE;
	}
	if (!fu_synaptics_rmi_device_wait_for_idle (self,
						    RMI_F34_IDLE_WAIT_MS,
						    RMI_DEVICE_WAIT_FOR_IDLE_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to wait for idle @0x%x: ", address);
		return FALSE;
	}
	return TRUE;
}

gboolean 
fu_synaptics_rmi_v5_device_secure_check (FuDevice *device,
					   FuFirmware *firmware,
					   GError **error)
{
//	int rc;
	FuSynapticsRmiFirmware *rmi_firmware = FU_SYNAPTICS_RMI_FIRMWARE (firmware);
	FuSynapticsRmiDevice *self = FU_SYNAPTICS_RMI_DEVICE (device);
//	FuSynapticsRmiFlash *flash = fu_synaptics_rmi_device_get_flash (self);
	FuSynapticsRmiFunction *f34;
	g_autoptr(GBytes) bytes_bin = NULL;
	g_autoptr(GBytes) signature = NULL;
	GByteArray *rsadump = g_byte_array_new ();
	g_autoptr(GByteArray) rsaseg = NULL;
	gsize sz;
	const guint8 *data;
	guint16 RSAPublicKeyLength = fu_synaptics_rmi_device_get_rsa_keylen (self) / 8;
	guint16 RSAKeyBlockCount = RSAPublicKeyLength / 3;
	guint16 RSAKeyBlockRemain = RSAPublicKeyLength % 3;
	guint32 signatureLength = fu_synaptics_rmi_firmware_get_signature_size (rmi_firmware);
	guint32 fimrwareLength = fu_synaptics_rmi_firmware_get_firmware_size (rmi_firmware) - signatureLength;
		
	bytes_bin = fu_firmware_get_image_by_id_bytes (firmware, "ui", error);
	if (bytes_bin == NULL)
		return FALSE;

	signature = g_bytes_new_from_bytes (bytes_bin, fimrwareLength, signatureLength);
	
	data = g_bytes_get_data (signature, &sz);

	if (!fu_synaptics_rmi_device_enter_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable backdoor: ");
		return FALSE;
	}

	fu_common_dump_full (G_LOG_DOMAIN, "Signauture",
				     data, sz,
				     16, FU_DUMP_FLAGS_NONE);

	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	g_debug ("Start to parsing RSA public key");
	if (RSAKeyBlockRemain)
		RSAKeyBlockCount += 1;
	for(guint16 blockNum = 0 ; blockNum < RSAKeyBlockCount ; blockNum++){
		g_autoptr(GByteArray) rsa_publickey_seg;
		rsa_publickey_seg = fu_synaptics_rmi_device_read_packet_register (self,
										f34->query_base + 14, // addr of flash properties + 5
										0x3,
										error);
		if (RSAKeyBlockRemain && ((blockNum + 1) == RSAKeyBlockCount)) {
			rsa_publickey_seg = g_byte_array_remove_range (rsa_publickey_seg, 
										RSAKeyBlockRemain , 
										rsa_publickey_seg->len - RSAKeyBlockRemain);
		}
		for (guint i = 0 ; i < rsa_publickey_seg->len / 2 ; i++) {
			guint8 tmp = rsa_publickey_seg->data[i];
			rsa_publickey_seg->data[i] = rsa_publickey_seg->data[rsa_publickey_seg->len - i - 1];
			rsa_publickey_seg->data[rsa_publickey_seg->len - i - 1] = tmp;
		}
		if (RSAKeyBlockRemain && ((blockNum + 1) == RSAKeyBlockCount)) {
			g_byte_array_prepend (rsadump, rsa_publickey_seg->data, RSAKeyBlockRemain);
		} else {
			g_byte_array_prepend (rsadump, rsa_publickey_seg->data, rsa_publickey_seg->len);
		}
	}

	fu_common_dump_full (G_LOG_DOMAIN, "RSA public key",
				     rsadump->data, rsadump->len,
				     16, FU_DUMP_FLAGS_NONE);
	

/*	
 	BIGNUM * modul = BN_new();
	BIGNUM * expon = BN_new();
	BN_bin2bn(RSAPublicKey, bytesRSAPublicKeyLength, modul);
    BN_hex2bn(&expon, "010001");

	RSA_set0_key(public_key, modul, expon, NULL);

	fprintf(stdout, "Going to RSA_verify\n");
	if(public_key && ucSignature && digest){
		verified = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH,
        	ucSignature, signatureLength, public_key);
    	fprintf(stdout, "Verified result : %d\n", verified);
		if(!verified){
			g_prefix_error (error, "RSA verification failed: ");
			return FALSE;
		}
	} else {
		if(!public_key){
			g_prefix_error (error, "public_key NULL: ");
			return FALSE;
		}
		if(!ucSignature){
			g_prefix_error (error, "ucSignature NULL: ");
			return FALSE;
		}
		if(!digest){
			g_prefix_error (error, "digest NULL: ");
			return FALSE;
		}
	}
	
	if(public_key)
    	RSA_free(public_key);*/
	return TRUE;
}

gboolean
fu_synaptics_rmi_v5_device_write_firmware (FuDevice *device,
					   FuFirmware *firmware,
					   FwupdInstallFlags flags,
					   GError **error)
{
	FuSynapticsRmiDevice *self = FU_SYNAPTICS_RMI_DEVICE (device);
	FuSynapticsRmiFlash *flash = fu_synaptics_rmi_device_get_flash (self);
	FuSynapticsRmiFunction *f34;
	FuSynapticsRmiFirmware *rmi_firmware = FU_SYNAPTICS_RMI_FIRMWARE (firmware);
	guint32 address;
	g_autoptr(GBytes) bytes_bin = NULL;
	g_autoptr(GBytes) bytes_cfg = NULL;
	g_autoptr(GPtrArray) chunks_bin = NULL;
	g_autoptr(GPtrArray) chunks_cfg = NULL;
	g_autoptr(GByteArray) req_addr = g_byte_array_new ();
	gboolean isFirmwareSecure = (fu_synaptics_rmi_firmware_get_signature_size (rmi_firmware) != 0) ?
								TRUE : FALSE;
	gboolean isDeviceSecure = (fu_synaptics_rmi_device_get_rsa_keylen (self) != 0) ?
								TRUE : FALSE;

	g_debug ("v5 write firmware");

	/* we should be in bootloader mode now, but check anyway */
	if (!fu_device_has_flag (device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER)) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "not bootloader, perhaps need detach?!");
		return FALSE;
	}

	if (!fu_synaptics_rmi_device_enter_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable backdoor: ");
		return FALSE;
	}

	/* check is idle */
	if (!fu_synaptics_rmi_device_wait_for_idle (self, 0,
						    RMI_DEVICE_WAIT_FOR_IDLE_FLAG_REFRESH_F34,
						    error)) {
		g_prefix_error (error, "not idle: ");
		return FALSE;
	}

	if (!isFirmwareSecure && isDeviceSecure) {
		g_prefix_error (error, "firmware not secure: ");
		return FALSE;
	}
	if (isFirmwareSecure && !isDeviceSecure) {
		g_prefix_error (error, "device not secure: ");
		return FALSE;
	}
	g_debug ("all secure");



	/* f34 */
	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	/* get both images */
	bytes_bin = fu_firmware_get_image_by_id_bytes (firmware, "ui", error);
	if (bytes_bin == NULL)
		return FALSE;
	bytes_cfg = fu_firmware_get_image_by_id_bytes (firmware, "config", error);
	if (bytes_cfg == NULL)
		return FALSE;

	if (!fu_synaptics_rmi_v5_device_secure_check (device, firmware, error)) {
		g_prefix_error (error, "secure check failed: ");
		return FALSE;
	}

	g_debug ("pass secure check");

	/* Currently for implementation breakpoint*/
	fu_device_sleep_with_progress (device, 5);
	return TRUE;

	/* disable powersaving */
	if (!fu_synaptics_rmi_device_disable_sleep (self, error)) {
		g_prefix_error (error, "failed to disable sleep: ");
		return FALSE;
	}

	/* unlock again */
	if (!fu_synaptics_rmi_device_write_bootloader_id (self, error)) {
		g_prefix_error (error, "failed to unlock again: ");
		return FALSE;
	}

	/* erase all */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_ERASE);
	if (!fu_synaptics_rmi_v5_device_erase_all (self, error)) {
		g_prefix_error (error, "failed to erase all: ");
		return FALSE;
	}

	/* write initial address */
	fu_byte_array_append_uint16 (req_addr, 0x0, G_LITTLE_ENDIAN);
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_WRITE);
	if (!fu_synaptics_rmi_device_write (self, f34->data_base, req_addr, error)) {
		g_prefix_error (error, "failed to write 1st address zero: ");
		return FALSE;
	}

	/* write each block */
	if (f34->function_version == 0x01)
		address = f34->data_base + RMI_F34_BLOCK_DATA_V1_OFFSET;
	else
		address = f34->data_base + RMI_F34_BLOCK_DATA_OFFSET;
	chunks_bin = fu_chunk_array_new_from_bytes (bytes_bin,
						    0x00,	/* start addr */
						    0x00,	/* page_sz */
						    flash->block_size);
	chunks_cfg = fu_chunk_array_new_from_bytes (bytes_cfg,
						    0x00,	/* start addr */
						    0x00,	/* page_sz */
						    flash->block_size);
	for (guint i = 0; i < chunks_bin->len; i++) {
		FuChunk *chk = g_ptr_array_index (chunks_bin, i);
		if (!fu_synaptics_rmi_v5_device_write_block (self,
							     RMI_V5_FLASH_CMD_WRITE_FW_BLOCK,
							     address,
							     chk->data,
							     chk->data_sz,
							     error)) {
			g_prefix_error (error, "failed to write bin block %u: ", chk->idx);
			return FALSE;
		}
		fu_device_set_progress_full (device, (gsize) i,
					     (gsize) chunks_bin->len + chunks_cfg->len);
	}

	/* program the configuration image */
	if (!fu_synaptics_rmi_device_write (self, f34->data_base, req_addr, error)) {
		g_prefix_error (error, "failed to 2nd write address zero: ");
		return FALSE;
	}
	for (guint i = 0; i < chunks_cfg->len; i++) {
		FuChunk *chk = g_ptr_array_index (chunks_cfg, i);
		if (!fu_synaptics_rmi_v5_device_write_block (self,
							     RMI_V5_FLASH_CMD_WRITE_CONFIG_BLOCK,
							     address,
							     chk->data,
							     chk->data_sz,
							     error)) {
			g_prefix_error (error, "failed to write cfg block %u: ", chk->idx);
			return FALSE;
		}
		fu_device_set_progress_full (device,
					     (gsize) chunks_bin->len + i,
					     (gsize) chunks_bin->len + chunks_cfg->len);
	}

	/* success */
	return TRUE;
}

gboolean
fu_synaptics_rmi_v5_device_setup (FuSynapticsRmiDevice *self, GError **error)
{
	FuSynapticsRmiFunction *f34;
	FuSynapticsRmiFlash *flash = fu_synaptics_rmi_device_get_flash (self);
	guint8 flash_properties2 = 0;
	g_autoptr(GByteArray) f34_data0 = NULL;
	g_autoptr(GByteArray) f34_data2 = NULL;
	g_autoptr(GByteArray) buf_flash_properties2 = NULL;

	/* f34 */
	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	/* get bootloader ID */
	f34_data0 = fu_synaptics_rmi_device_read (self, f34->query_base, 0x2, error);
	if (f34_data0 == NULL) {
		g_prefix_error (error, "failed to read bootloader ID: ");
		return FALSE;
	}
	flash->bootloader_id[0] = f34_data0->data[0];
	flash->bootloader_id[1] = f34_data0->data[1];

	buf_flash_properties2 = fu_synaptics_rmi_device_read (self, f34->query_base + 0x9, 1, error);
	if (buf_flash_properties2 == NULL) {
		g_prefix_error (error, "failed to read Flash Properties 2: ");
		return FALSE;
	}
	if (!fu_common_read_uint8_safe (buf_flash_properties2->data,
					 buf_flash_properties2->len,
					 0x0, /* offset */
					 &flash_properties2,
					 error)) {
		g_prefix_error (error, "failed to parse Flash Properties 2: ");
		return FALSE;
	}
	if (flash_properties2 & 0x01) {
		guint16 rsa_keylen = 0;
		g_autoptr(GByteArray) buf_rsa_key = NULL;
		buf_rsa_key = fu_synaptics_rmi_device_read (self,
							    f34->query_base + 0x9 + 0x1,
							    2,
							    error);
		if (buf_rsa_key == NULL) {
			g_prefix_error (error, "failed to read RSA key length: ");
			return FALSE;
		}
		if (!fu_common_read_uint16_safe (buf_rsa_key->data,
						 buf_rsa_key->len,
						 0x0, /* offset */
						 &rsa_keylen,
						 G_LITTLE_ENDIAN,
						 error)) {
			g_prefix_error (error, "failed to parse RSA key length: ");
			return FALSE;
		}
		g_debug ("RSA key length: %d", rsa_keylen);
		fu_synaptics_rmi_device_set_rsa_keylen (self, rsa_keylen);
	} else {
		fu_synaptics_rmi_device_set_rsa_keylen (self, 0);
	}


	/* get flash properties */
	f34_data2 = fu_synaptics_rmi_device_read (self, f34->query_base + 0x2, 0x7, error);
	if (f34_data2 == NULL)
		return FALSE;
	flash->block_size = fu_common_read_uint16 (f34_data2->data + RMI_F34_BLOCK_SIZE_OFFSET, G_LITTLE_ENDIAN);
	flash->block_count_fw = fu_common_read_uint16 (f34_data2->data + RMI_F34_FW_BLOCKS_OFFSET, G_LITTLE_ENDIAN);
	flash->block_count_cfg = fu_common_read_uint16 (f34_data2->data + RMI_F34_CONFIG_BLOCKS_OFFSET, G_LITTLE_ENDIAN);
	flash->status_addr = f34->data_base + RMI_F34_BLOCK_DATA_OFFSET + flash->block_size;
	return TRUE;
}

gboolean
fu_synaptics_rmi_v5_device_query_status (FuSynapticsRmiDevice *self, GError **error)
{
	FuSynapticsRmiFunction *f01;
	g_autoptr(GByteArray) f01_db = NULL;
	/* f01 */
	f01 = fu_synaptics_rmi_device_get_function (self, 0x01, error);
	if (f01 == NULL)
		return FALSE;
	f01_db = fu_synaptics_rmi_device_read (self, f01->data_base, 0x1, error);
	if (f01_db == NULL) {
		g_prefix_error (error, "failed to read the f01 data base: ");
		return FALSE;
	}
	if (f01_db->data[0] & 0x40) {
		g_debug ("in bootloader mode add FWUPD_DEVICE_FLAG_IS_BOOTLOADER");
		fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	} else {
		g_debug ("not in bootloader mode remove FWUPD_DEVICE_FLAG_IS_BOOTLOADER");
		fu_device_remove_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	}
	return TRUE;
}
