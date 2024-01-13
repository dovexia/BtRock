/**
 * @copyright Copyright (c) 2023, ThunderSoft, Ltd.
 * @file msc.c
 * @author  xiachen0629@thundersoft.com
 * @brief
 * @date 2023-11-25
 *
 * @par History:
 * <table>
 * <tr><th>Date         <th>version <th>Author       <th>Description
 * <tr><td>2023-11-25   <td>1.0     <td>xiachen0629  <td>init version
 * </table>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <wordexp.h>
#include <glib.h>
#include <stdint.h>
#include <pthread.h>

#include "bluetooth.h"
#include "hci.h"
#include "lib/hci_lib.h"
#include "main.h"
#include "msc.h"

static int devfd;
static int hci_dev = 0;;

static bdaddr_t local_addr;
static bdaddr_t local_random_addr;
void msc_hex_dump(char *prestr, int width, unsigned char *buf, int len)
{
	register int i,n;

	for (i = 0, n = 1; i < len; i++, n++) {
		if (n == 1)
			bt_shell_printf("%s %d: ", prestr, i);
		bt_shell_printf("%2.2X ", buf[i]);
		if (n == width) {
			bt_shell_printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		bt_shell_printf("\n");
}

void msc_init_env(int argc, char **argvcmd_req)
{
    int opt;
	uint8_t events[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00 };
	struct hci_dev_info di;
	struct hci_version ver;

    devfd = hci_open_dev(hci_dev);
	if (devfd < 0) {
		bt_shell_printf("Can't open device hci%d: %s (%d)\n",
                        hci_dev, strerror(errno), errno);
		exit(1);
	}
    bt_shell_printf("Open dev success\n");

	if (hci_devinfo(hci_dev, &di) < 0) {
		bt_shell_printf("Can't get device info for hci%d: %s (%d)\n",
                        hci_dev, strerror(errno), errno);
		hci_close_dev(devfd);
		exit(1);
	}
    bt_shell_printf("get dev success: id is %d, name is %s\n", di.dev_id, di.name);

	if (hci_read_local_version(devfd, &ver, 1000) < 0) {
        bt_shell_printf("Can't read version info for hci%d: %s (%d)\n",
                        hci_dev, strerror(errno), errno);
        hci_close_dev(devfd);
		exit(1);
	}
    bt_shell_printf("get ver success: ver.hci_ver is 0x%x, hci_rev is 0x%x\n", ver.hci_ver, ver.hci_rev);

    bt_shell_printf("%s\n", __func__);
}

void msc_clear_env(int argc, char **argvcmd_req)
{
    hci_reset_dev(devfd);
    hci_close_dev(devfd);
    bt_shell_printf("%s\n", __func__);
}
/* in 2.1 Initial setup*/
void msc_initial_setup(int argc, char **argvcmd_req)
{
    int32_t ret;
    int32_t default_timeout = 1000;
    bt_shell_printf("%s\n", __func__);
    // Reset
    ret = hci_reset_dev(devfd);
    bt_shell_printf("ret is %d\n", ret);

    // Read Local Supported Commands.
    uint8_t cmds[64];
	if (hci_read_local_commands(devfd, cmds, 1000) < 0) {
		bt_shell_printf("Can't read support commands on hci%d: %s (%d)\n",
						hci_dev, strerror(errno), errno);
		return;
	}
    msc_hex_dump("support commands: ", 16, cmds, 64);

    // Read local support Freatures
    uint8_t features[8];
	if (hci_read_local_features(devfd, features, 1000) < 0) {
		bt_shell_printf("Can't read support features on hci%d: %s (%d)\n",
						hci_dev, strerror(errno), errno);
		return;
	}
    msc_hex_dump("support features: ", 16, features, 8);
    // Set Event Mask
    uint8_t evt_mask[8];
    memset(evt_mask, 0xFF, sizeof(evt_mask));
	uint32_t status = -1;
	if (hci_write_common_cmd(devfd, OGF_HOST_CTL, OCF_SET_EVENT_MASK, EVT_CMD_COMPLETE,
                                evt_mask, 8,
								(uint8_t*)&status, sizeof(status),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_SET_EVENT_MASK on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_SET_EVENT_MASK status is 0x%x\n", status);


    // LE setEvent Mask
	status = -1;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EVENT_MASK, EVT_CMD_COMPLETE,
                                evt_mask, 8,
								(uint8_t*)&status, sizeof(status),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_LE_SET_EVENT_MASK on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_SET_EVENT_MASK status is 0x%x\n", status);
    // LE Read Buffer Size
	le_read_buffer_size_rp le_read_buffer_size_reply;
	memset(&le_read_buffer_size_reply, 0, sizeof(le_read_buffer_size_reply));
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_BUFFER_SIZE, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_read_buffer_size_reply,
								sizeof(le_read_buffer_size_reply),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_LE_READ_BUFFER_SIZE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_READ_BUFFER_SIZE status is  0x%x\n", le_read_buffer_size_reply.status);
	bt_shell_printf("OCF_LE_READ_BUFFER_SIZE pkt_len is 0x%x\n", le_read_buffer_size_reply.pkt_len);
	bt_shell_printf("OCF_LE_READ_BUFFER_SIZE max_pkt is 0x%x\n", le_read_buffer_size_reply.max_pkt);
    // Read Buffer Size
	read_buffer_size_rp read_buffer_size_reply;
	memset(&read_buffer_size_reply, 0, sizeof(read_buffer_size_reply));
	if (hci_write_common_cmd(devfd, OGF_INFO_PARAM, OCF_READ_BUFFER_SIZE, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&read_buffer_size_reply,
								sizeof(read_buffer_size_reply),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_READ_BUFFER_SIZE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_READ_BUFFER_SIZE status is 0x%x\n", read_buffer_size_reply.status);
	bt_shell_printf("OCF_READ_BUFFER_SIZE acl_mtu is 0x%x\n", read_buffer_size_reply.acl_mtu);
	bt_shell_printf("OCF_READ_BUFFER_SIZE sco_mtu is 0x%x\n", read_buffer_size_reply.sco_mtu);
	bt_shell_printf("OCF_READ_BUFFER_SIZE acl_max_pkt is 0x%x\n", read_buffer_size_reply.acl_max_pkt);
	bt_shell_printf("OCF_READ_BUFFER_SIZE sco_max_pkt is 0x%x\n", read_buffer_size_reply.sco_max_pkt);
    // LE Read Local Support Features
	le_read_local_supported_features_rp le_read_local_supported_features_reply;
	memset(&le_read_local_supported_features_reply, 0, sizeof(le_read_local_supported_features_reply));
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_read_local_supported_features_reply, sizeof(le_read_local_supported_features_reply),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_LE_READ_LOCAL_SUPPORTED_FEATURES on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_READ_LOCAL_SUPPORTED_FEATURES status is 0x%x\n", le_read_local_supported_features_reply.status);
    msc_hex_dump("le_read_local_supported_features_rp features: ", 16,
        le_read_local_supported_features_reply.features, 8);

    // Read BT_ADDR
	read_bd_addr_rp read_bd_addr_reply;
	memset(&read_bd_addr_reply, 0, sizeof(read_bd_addr_reply));
	if (hci_write_common_cmd(devfd, OGF_INFO_PARAM, OCF_READ_BD_ADDR, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&read_bd_addr_reply, sizeof(read_bd_addr_reply),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_READ_BD_ADDR on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_READ_BD_ADDR status is 0x%x\n", read_bd_addr_reply.status);
    msc_hex_dump("read_bd_addr_reply bdaddr: ", 16,
        (unsigned char *)&read_bd_addr_reply.bdaddr, 6);
    local_addr = read_bd_addr_reply.bdaddr;
    local_random_addr = read_bd_addr_reply.bdaddr;
    local_random_addr.b[0] |= 0xC0;
 }

/* in 2.2 Random Device Address*/
void msc_random_device_address(int argc, char **argvcmd_req)
{
    bt_shell_printf("%s\n", __func__);
    uint8_t status = -1;
    //LE Rand
    le_rand_rp le_rand_reply;
    memset(&le_rand_reply, 0, sizeof(le_rand_reply));
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_RAND, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_rand_reply, sizeof(le_rand_reply),
								1000) <0) {
		bt_shell_printf("Can't OCF_LE_RAND on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_RAND status is 0x%x\n", le_rand_reply.status);
	bt_shell_printf("OCF_LE_RAND status is 0x%lx\n", le_rand_reply.random);
    //LE Encrypt
    le_encrypt_cp le_encrypt_cmd_param;
    le_encrypt_rp le_encrypt_reply;
    memset(&le_encrypt_cmd_param, 0, sizeof(le_encrypt_cmd_param));
    memset(&le_encrypt_reply, 0, sizeof(le_encrypt_reply));
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_ENCRYPT, EVT_CMD_COMPLETE,
                                (uint8_t*)&le_encrypt_cmd_param,
								sizeof(le_encrypt_cmd_param),
								(uint8_t*)&le_encrypt_reply, sizeof(le_encrypt_reply),
								1000) <0) {
		bt_shell_printf("Can't OCF_LE_ENCRYPT on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_ENCRYPT status is 0x%x\n", le_rand_reply.status);
    //LE Set Random Address
    le_set_random_address_cp le_set_random_address_cmd_param;
    //le_set_random_address_cmd_param.btaddr
    le_set_random_address_cmd_param.bdaddr = local_random_addr;
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_RANDOM_ADDRESS, EVT_CMD_COMPLETE,
                                (uint8_t*)&le_set_random_address_cmd_param,
								sizeof(le_set_random_address_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_RANDOM_ADDRESS on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_SET_RANDOM_ADDRESS status is 0x%x\n", status);
}

/* in 2.3 Filter accept List*/
void msc_filter_accept_list(int argc, char **argvcmd_req)
{
    uint8_t status;
    bt_shell_printf("%s\n", __func__);
    //LE Read Filter Accept List Size
    le_read_white_list_size_rp le_read_white_list_size_reply;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_FILTER_ACCEPT_SIZE, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_read_white_list_size_reply, sizeof(le_read_white_list_size_reply),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_READ_FILTER_ACCEPT_SIZE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_READ_FILTER_ACCEPT_SIZE status is 0x%x\n", *(uint8_t*)&le_read_white_list_size_reply);
    //LE Clear Filter Accept List
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_CLEAR_FILTER_ACCEPT_LIST, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_CLEAR_FILTER_ACCEPT_LIST on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_CLEAR_FILTER_ACCEPT_LIST status is 0x%x\n", *(uint8_t*)&status);
    //LE Add Device to Filter Accept List
    le_add_device_to_white_list_cp le_add_device_to_white_list_cmd_param;
    le_add_device_to_white_list_cmd_param.bdaddr_type = 0;
    le_add_device_to_white_list_cmd_param.bdaddr.b[0] = 0xAA;
    le_add_device_to_white_list_cmd_param.bdaddr.b[1] = 0xBB;
    le_add_device_to_white_list_cmd_param.bdaddr.b[2] = 0xCC;
    le_add_device_to_white_list_cmd_param.bdaddr.b[3] = 0xCC;
    le_add_device_to_white_list_cmd_param.bdaddr.b[4] = 0xEE;
    le_add_device_to_white_list_cmd_param.bdaddr.b[5] = 0xFF;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_add_device_to_white_list_cmd_param,	sizeof(le_add_device_to_white_list_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST status is 0x%x\n", status);

}

/* in 2.4Adding IRK to resolving list*/
void msc_adding_irk_to_resolving_list(int argc, char **argvcmd_req)
{
    bt_shell_printf("%s\n", __func__);
    uint8_t status = -1;
    //LE Read Resolving List size
    le_read_resolv_list_size_rp le_read_resolv_list_size_reply;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_RESOLV_LIST_SIZE, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_read_resolv_list_size_reply, sizeof(le_read_resolv_list_size_reply),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_READ_RESOLV_LIST_SIZE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_READ_RESOLV_LIST_SIZE status is 0x%x\n", le_read_resolv_list_size_reply.status);
	bt_shell_printf("OCF_LE_READ_RESOLV_LIST_SIZE size is 0x%x\n", le_read_resolv_list_size_reply.size);
    //LE Clear Resolving List
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_CLEAR_RESOLV_LIST, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_CLEAR_RESOLV_LIST on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_CLEAR_RESOLV_LIST status is 0x%x\n", *(uint8_t*)&status);
    //LE Add device to Resolving List
    status = -1;
    le_add_device_to_resolv_list_cp le_add_device_to_resolv_list_cmd_param;
    le_add_device_to_resolv_list_cmd_param.bdaddr_type = 0x01;
    le_add_device_to_resolv_list_cmd_param.bdaddr.b[0] = 0xAC;
    le_add_device_to_resolv_list_cmd_param.bdaddr.b[1] = 0xBB;
    le_add_device_to_resolv_list_cmd_param.bdaddr.b[2] = 0xCC;
    le_add_device_to_resolv_list_cmd_param.bdaddr.b[3] = 0xDD;
    le_add_device_to_resolv_list_cmd_param.bdaddr.b[4] = 0xEE;
    le_add_device_to_resolv_list_cmd_param.bdaddr.b[5] = 0xFF;
    memset(&le_add_device_to_resolv_list_cmd_param.peer_irk, '1', 16);
    memset(&le_add_device_to_resolv_list_cmd_param.local_irk, 'A', 16);
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_add_device_to_resolv_list_cmd_param, sizeof(le_add_device_to_resolv_list_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST status is 0x%x\n", *(uint8_t*)&status);
    //additional remove device from Resolving list
    status = -1;
    le_remove_device_from_resolv_list_cp le_remove_device_from_resolv_list_cmd_param;
    le_remove_device_from_resolv_list_cmd_param.bdaddr_type = 0x01;
    le_remove_device_from_resolv_list_cmd_param.bdaddr.b[0] = 0xAC;
    le_remove_device_from_resolv_list_cmd_param.bdaddr.b[1] = 0xBB;
    le_remove_device_from_resolv_list_cmd_param.bdaddr.b[2] = 0xCC;
    le_remove_device_from_resolv_list_cmd_param.bdaddr.b[3] = 0xDD;
    le_remove_device_from_resolv_list_cmd_param.bdaddr.b[4] = 0xEE;
    le_remove_device_from_resolv_list_cmd_param.bdaddr.b[5] = 0xFF;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST, EVT_CMD_COMPLETE,
								(uint8_t *)&le_remove_device_from_resolv_list_cmd_param, sizeof(le_remove_device_from_resolv_list_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST status is 0x%x\n", *(uint8_t*)&status);
}

/* in 2.5 Default data length*/
void msc_default_data_length(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    le_write_suggest_default_data_length_cp le_write_suggest_default_data_length_cmd_param;
    le_write_suggest_default_data_length_cmd_param.suggest_max_tx_octets = 0x00FB;
    le_write_suggest_default_data_length_cmd_param.suggest_max_tx_time = 0x4290;

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH,	EVT_CMD_COMPLETE,
								(uint8_t *)&le_write_suggest_default_data_length_cmd_param,	sizeof(le_write_suggest_default_data_length_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH status is 0x%x\n", *(uint8_t*)&status);

    le_read_suggested_default_data_length_rp le_read_suggested_default_data_length_reply;;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_read_suggested_default_data_length_reply,	sizeof(le_read_suggested_default_data_length_reply),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
	bt_shell_printf("OCF_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH status is 0x%x\n", le_read_suggested_default_data_length_reply.status);
	bt_shell_printf("OCF_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH suggest_max_tx_octets is 0x%x\n", le_read_suggested_default_data_length_reply.suggest_max_tx_octets);
	bt_shell_printf("OCF_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH suggest_max_tx_time is 0x%x\n", le_read_suggested_default_data_length_reply.suggest_max_tx_time);

}

/* in 2.6 Periodic Advertiser List*/
void msc_periodic_advertiser_list(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);

    le_set_advertising_parameters_cp le_set_advertising_parameters_cmd_param;
    //config the param
    // ...

    le_read_periodic_advertiser_list_size_rp le_read_periodic_advertiser_list_size_reply;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_read_periodic_advertiser_list_size_reply,	sizeof(le_read_periodic_advertiser_list_size_reply),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE status is 0x%x\n", status);

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_CLEAR_PERIODIC_ADVERTISER_LIST, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_CLEAR_PERIODIC_ADVERTISER_LIST on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_CLEAR_PERIODIC_ADVERTISER_LIST status is 0x%x\n", status);

    le_add_device_to_periodic_advertiser_list_cp le_add_device_to_periodic_advertiser_list_cmd_param;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_add_device_to_periodic_advertiser_list_cmd_param,
                                sizeof(le_add_device_to_periodic_advertiser_list_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST status is 0x%x\n", status);

}

//Advertising state
/* in 3.1 Undirected advertising*/
void * msc_undirected_advertising_stop(void * arg) {
    //after sleep some seconds
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);

    sleep(120);
    status = -1;
    le_set_advertise_enable_cp le_set_advertise_enable_cmd_param;

    le_set_advertise_enable_cmd_param.enable = false;
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertise_enable_cmd_param, sizeof(le_set_advertise_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISE_ENABLE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return NULL;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISE_ENABLE status is 0x%x\n", status);
    return NULL;

}
void msc_undirected_advertising(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    le_set_advertising_parameters_cp le_set_advertising_parameters_cmd_param;
    memset(&le_set_advertising_parameters_cmd_param, 0, sizeof(le_set_advertising_parameters_cmd_param));
    //config the le_set_extended_advertising_parameters_v1_cmd_param
    // ...
    le_set_advertising_parameters_cmd_param.min_interval = 50;
    le_set_advertising_parameters_cmd_param.max_interval = 2000;
    le_set_advertising_parameters_cmd_param.advtype = 0x00; //ADV_IND
    le_set_advertising_parameters_cmd_param.own_bdaddr_type = 0x00; //use default public device address
    /* when Advertising_Type is set to 0x01 (ADV_DIRECT_IND, high duty cycle) or 0x04 (ADV_DIRECT_IND, low duty
        cycle mode), then the Peer_Address_Type and Peer_Address shall be valid. else not.
    */

    status = -1;
    //le_set_advertising_parameters_cmd_param.direct_bdaddr_type = 0x00;
    //le_set_advertising_parameters_cmd_param.direct_bdaddr;
    le_set_advertising_parameters_cmd_param.chan_map = 0x07;
    le_set_advertising_parameters_cmd_param.filter = 0x00;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertising_parameters_cmd_param, sizeof(le_set_advertising_parameters_cmd_param),
								(uint8_t*)&status,	sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISING_PARAMETERS on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);


    status = -1;
    le_read_advertising_channel_tx_power_rp le_read_advertising_channel_tx_power_reply;
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER, EVT_CMD_COMPLETE,
                                NULL, 0,
								(uint8_t*)&le_read_advertising_channel_tx_power_reply, sizeof(le_read_advertising_channel_tx_power_reply),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER status is 0x%x\n", le_read_advertising_channel_tx_power_reply.status);
    bt_shell_printf("OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER min_tx_power is 0x%x\n", le_read_advertising_channel_tx_power_reply.level);

    status = -1;
    le_set_advertising_data_cp le_set_advertising_data_cmd_param;
    memset(&le_set_advertising_data_cmd_param, 0, sizeof(le_set_advertising_data_cmd_param));
    le_set_advertising_data_cmd_param.data[0] = 0x06;   //ad length
    le_set_advertising_data_cmd_param.data[1] = 0x00;   //ad type
    le_set_advertising_data_cmd_param.data[2] = 'H';    //ad data
    le_set_advertising_data_cmd_param.data[3] = 'e';
    le_set_advertising_data_cmd_param.data[4] = 'l';
    le_set_advertising_data_cmd_param.data[5] = 'l';
    le_set_advertising_data_cmd_param.data[6] = 'o';
    //strcpy(le_set_advertising_data_cmd_param.data = {0x1A, 0x00, 'H', 'e', 'l', 'l', 'o', ',', ' ', 'D', 'o', 'v', 'e', ',', ' ', 'w', 'e', 'l', 'c' ,'o', 'm', 'e' ,' ', 't', 'o', ' ', 'L', 'E'};
    le_set_advertising_data_cmd_param.length = 0x07; //the str length of Data
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertising_data_cmd_param, le_set_advertising_data_cmd_param.length + 1,
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISING_DATA on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_DATA status is 0x%x\n", status);

    status = -1;
    le_set_scan_response_data_cp le_set_scan_response_data_cmd_param;
    memset(&le_set_scan_response_data_cmd_param, 0, sizeof(le_set_scan_response_data_cmd_param));
    le_set_advertising_data_cmd_param.data[0] = 0x05;   //ad length
    le_set_advertising_data_cmd_param.data[1] = 0x00;   //ad type
    le_set_advertising_data_cmd_param.data[2] = 'D';    //ad data
    le_set_advertising_data_cmd_param.data[3] = 'o';
    le_set_advertising_data_cmd_param.data[4] = 'v';
    le_set_advertising_data_cmd_param.data[5] = 'e';
    le_set_scan_response_data_cmd_param.length = 0x06; //the str length of Data
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_SCAN_RESPONSE_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_scan_response_data_cmd_param, le_set_advertising_data_cmd_param.length + 1,
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_SCAN_RESPONSE_DATA on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_SCAN_RESPONSE_DATA status is 0x%x\n", status);

    status = -1;
    le_set_advertise_enable_cp le_set_advertise_enable_cmd_param;
    le_set_advertise_enable_cmd_param.enable = true;
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertise_enable_cmd_param, sizeof(le_set_advertise_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISE_ENABLE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISE_ENABLE status is 0x%x\n", status);
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, msc_undirected_advertising_stop, NULL);
}

//In 3.2 Directed advertising
void msc_high_duty_cycle_directed_advertising(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //LE set advertising parameters
    //LE set advertising enable
    //LE advertising disabled when device is connected
    le_set_advertising_parameters_cp le_set_advertising_parameters_cmd_param;
    //config the le_set_extended_advertising_parameters_v1_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertising_parameters_cmd_param, sizeof(le_set_advertising_parameters_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISING_PARAMETERS on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    le_set_advertise_enable_cp le_set_advertise_enable_cmd_param;
    le_set_advertise_enable_cmd_param.enable = true;
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertise_enable_cmd_param, sizeof(le_set_advertise_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISE_ENABLE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISE_ENABLE status is 0x%x\n", status);

    //expect receive connection complete, with status euqalto advertising timeout
}

//In 3.2 Directed advertising
void msc_low_duty_cycle_directed_advertising(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //LE set advertising parameters
    //LE set advertising enable
    //LE set advertising disable
    le_set_advertising_parameters_cp le_set_advertising_parameters_cmd_param;
    //config the le_set_extended_advertising_parameters_v1_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_PARAMETERS, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertising_parameters_cmd_param, sizeof(le_set_advertising_parameters_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISING_PARAMETERS on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    le_set_advertise_enable_cp le_set_advertise_enable_cmd_param;
    le_set_advertise_enable_cmd_param.enable = true;
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertise_enable_cmd_param, sizeof(le_set_advertise_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISE_ENABLE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISE_ENABLE status is 0x%x\n", status);

    sleep(30);
    le_set_advertise_enable_cmd_param.enable = false;
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_advertise_enable_cmd_param, sizeof(le_set_advertise_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_ADVERTISE_ENABLE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISE_ENABLE status is 0x%x\n", status);
}
//3.3
void * msc_advertising_using_adv_ext_ind_stop(void * arg)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);

    uint8_t * padv_handle = (uint8_t *)arg;
    sleep(60);

    status = -1;
    le_set_extended_advertising_enable_cp le_set_extended_advertising_enable_cmd_param;
    //config the le_set_extended_advertising_enable_cmd_param
    // default Num_Sets is 1, so not need malloc for size change

    le_set_extended_advertising_enable_cmd_param.enable = false;
    le_set_extended_advertising_enable_cmd_param.num_sets = 1;
    le_set_extended_advertising_enable_cmd_param.advertising_handle[0] = *padv_handle;  // num_sets *1
    le_set_extended_advertising_enable_cmd_param.duration[0] = 0;    // num_sets *1
    le_set_extended_advertising_enable_cmd_param.max_extended_advertising_events[0] = 0;    //No maximum number of advertising events

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE,	EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_enable_cmd_param, sizeof(le_set_extended_advertising_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return NULL;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE status is 0x%x\n", status);
    return NULL;

}
void msc_advertising_using_adv_ext_ind_start(uint8_t use_random_addr, uint8_t use_scan_rsp_data, uint8_t adv_continuously, uint8_t adv_handle)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //LE set Extended advertising parameters
    //LE set extended advertising data
    //LE set extended scan response data
    //LE set extended advertisging enable
    //LE set extended advertisging disable

    le_set_extended_advertising_parameters_v1_cp le_set_extended_advertising_parameters_v1_cmd_param;
    le_set_extended_advertising_parameters_rp le_set_extended_advertising_parameters_reply;

    memset(&le_set_extended_advertising_parameters_v1_cmd_param, 0, sizeof(le_set_extended_advertising_parameters_v1_cmd_param));
    le_set_extended_advertising_parameters_v1_cmd_param.advertising_handle = adv_handle;
    le_set_extended_advertising_parameters_v1_cmd_param.advertising_event_properties = 0b00010011;
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_interval_min.data[0] = 0x30;
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_interval_min.data[1] = 0x00;
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_interval_min.data[2] = 0x00;
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_interval_max.data[0] = 0x00;
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_interval_max.data[1] = 0x20;
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_interval_max.data[2] = 0x00;
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_channel_map = 0x07; //all 37, 38, 39 channel
    le_set_extended_advertising_parameters_v1_cmd_param.own_address_type = use_random_addr;
    le_set_extended_advertising_parameters_v1_cmd_param.peer_address_type = 0;
    //if the peer address type is 0, not need set the peer address.
    //le_set_extended_advertising_parameters_v1_cmd_param    peer_address;
    le_set_extended_advertising_parameters_v1_cmd_param.advertising_filter_policy = 0;
    le_set_extended_advertising_parameters_v1_cmd_param.advertising_tx_power = 0x7F; //Host has no preference, no specify the tx power.
    le_set_extended_advertising_parameters_v1_cmd_param.primary_advertising_phy = 0x01; //use LE 1M
    le_set_extended_advertising_parameters_v1_cmd_param.secondary_advertising_max_skip = 0x00;
    le_set_extended_advertising_parameters_v1_cmd_param.secondary_advertising_phy = 0x01;   //use LE 1M
    le_set_extended_advertising_parameters_v1_cmd_param.advertising_sid = 0x00; //SID
    le_set_extended_advertising_parameters_v1_cmd_param.scan_request_notification_enable = 0x00; //Host not need to know the peer scan request.

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_parameters_v1_cmd_param, sizeof(le_set_extended_advertising_parameters_v1_cmd_param),
								(uint8_t*)&le_set_extended_advertising_parameters_reply, sizeof(le_set_extended_advertising_parameters_reply),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    status = -1;
    if (use_random_addr) {
        //check if the random address is need.
        le_set_advertising_set_random_address_cp le_set_advertising_set_random_address_cmd_param;
        //config the le_set_extended_advertising_parameters_v1_cmd_param
        // ...
        le_set_advertising_set_random_address_cmd_param.advertising_handle = adv_handle;  //should same as config param
        le_set_advertising_set_random_address_cmd_param.random_address = local_random_addr;  //should same as config param
        if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS, EVT_CMD_COMPLETE,
                                    (uint8_t *)&le_set_advertising_set_random_address_cmd_param, sizeof(le_set_advertising_set_random_address_cmd_param),
                                    (uint8_t*)&status, sizeof(status),
                                    1000) < 0) {
            bt_shell_printf("Can't OCF_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS on hci%d: %s (%d)\n",
                        hci_dev, strerror(errno), errno);
            return;
        }
        bt_shell_printf("OCF_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS status is 0x%x\n", status);
    }

    status = -1;
    le_set_extended_advertising_data_cp * le_set_extended_advertising_data_cmd_param;
    //config the le_set_extended_advertising_data_cmd_param
    // ...
    uint8_t adv_data_len = 0x17;
    le_set_extended_advertising_data_cmd_param = (le_set_extended_advertising_data_cp*)malloc(sizeof(le_set_extended_advertising_data_cp) + adv_data_len);
    uint8_t * padvertising_data = le_set_extended_advertising_data_cmd_param->advertising_data;
    le_set_extended_advertising_data_cmd_param->advertising_handle = adv_handle;  //according to config param
    le_set_extended_advertising_data_cmd_param->operation = 0x03;
    le_set_extended_advertising_data_cmd_param->fragment_preference = 0x00;
    le_set_extended_advertising_data_cmd_param->advertising_data_length = adv_data_len;    //the data array size.
    // le_set_extended_advertising_data_cmd_param->advertising_data[0] = 0x06;   //ad length
    // le_set_extended_advertising_data_cmd_param->advertising_data[1] = 0x00;   //ad type
    // le_set_extended_advertising_data_cmd_param->advertising_data[2] = 'D';    //ad data
    // le_set_extended_advertising_data_cmd_param->advertising_data[3] = 'o';
    // le_set_extended_advertising_data_cmd_param->advertising_data[4] = 'v';
    // le_set_extended_advertising_data_cmd_param->advertising_data[5] = 'e';
    // le_set_extended_advertising_data_cmd_param->advertising_data[6] = '1';
//8
    *padvertising_data++ = 0x07; //manufacture specific
    *padvertising_data++ = 0xFF;
    *padvertising_data++ = 0x26;
    *padvertising_data++ = 0x0A;
    *padvertising_data++ = 't';
    *padvertising_data++ = 'h';
    *padvertising_data++ = 'v';
    *padvertising_data++ = '3' + use_random_addr;
//4
    *padvertising_data++ = 0x03;
    *padvertising_data++ = 0x03;
    *padvertising_data++ = 0x0A;
    *padvertising_data++ = 0x18;
//11
    *padvertising_data++ = 0x0A;
    *padvertising_data++ = 0x09;
    *padvertising_data++ = 'D';
    *padvertising_data++ = 'o';
    *padvertising_data++ = 'v';
    *padvertising_data++ = 'e';
    *padvertising_data++ = 'X';
    *padvertising_data++ = 'i';
    *padvertising_data++ = 'a';
    *padvertising_data++ = '_';
    *padvertising_data++ = '3';

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)le_set_extended_advertising_data_cmd_param, sizeof(le_set_extended_advertising_data_cp) + adv_data_len,
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_EXTENDED_ADVERTISING_DATA on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_ADVERTISING_DATA status is 0x%x\n", status);

    if (use_scan_rsp_data) {
        status = -1;
        uint8_t adv_scan_response_len = 0x1A;

        le_set_extended_scan_response_data_cp *le_set_extended_scan_response_data_cmd_param;
        le_set_extended_scan_response_data_cmd_param = (le_set_extended_scan_response_data_cp*)malloc(sizeof(le_set_extended_scan_response_data_cp) + adv_scan_response_len);
        uint8_t * pscan_response_data = le_set_extended_scan_response_data_cmd_param->scan_response_data;

        le_set_extended_scan_response_data_cmd_param->advertising_handle = adv_handle;
        le_set_extended_scan_response_data_cmd_param->operation = 0x03;
        le_set_extended_scan_response_data_cmd_param->fragment_preference = 0x00;
        le_set_extended_scan_response_data_cmd_param->scan_response_data_length = adv_scan_response_len;

    //+7
        *pscan_response_data++ = 0x06;
        *pscan_response_data++ = 0x08;
        *pscan_response_data++ = 'D';
        *pscan_response_data++ = 'o';
        *pscan_response_data++ = 'v';
        *pscan_response_data++ = 'e';
        *pscan_response_data++ = '5' + use_random_addr;
    //+4
        *pscan_response_data++ = 0x03;
        *pscan_response_data++ = 0x03;
        *pscan_response_data++ = 0x47;
        *pscan_response_data++ = 0x18;
    //+4
        *pscan_response_data++ = 0x03;
        *pscan_response_data++ = 0x0A;
        *pscan_response_data++ = 0x00;
        *pscan_response_data++ = 0x00;
    //+11
        *pscan_response_data++ = 0x0A;
        *pscan_response_data++ = 0x09;
        *pscan_response_data++ = 'D';
        *pscan_response_data++ = 'o';
        *pscan_response_data++ = 'v';
        *pscan_response_data++ = 'e';
        *pscan_response_data++ = 'X';
        *pscan_response_data++ = 'i';
        *pscan_response_data++ = 'a';
        *pscan_response_data++ = '_';
        *pscan_response_data++ = '5' + use_random_addr;


        if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA,	EVT_CMD_COMPLETE,
                                    (uint8_t *)le_set_extended_scan_response_data_cmd_param, sizeof(le_set_extended_scan_response_data_cp) + adv_scan_response_len,
                                    (uint8_t*)&status, sizeof(status),
                                    1000) < 0) {
            bt_shell_printf("Can't OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA on hci%d: %s (%d)\n",
                        hci_dev, strerror(errno), errno);
            return;
        }
        bt_shell_printf("OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA status is 0x%x\n", status);
    }

    status = -1;
    le_set_extended_advertising_enable_cp le_set_extended_advertising_enable_cmd_param;
    //config the le_set_extended_advertising_enable_cmd_param
    // default Num_Sets is 1, so not need malloc for size change

    le_set_extended_advertising_enable_cmd_param.enable = true;
    le_set_extended_advertising_enable_cmd_param.num_sets = 1;
    le_set_extended_advertising_enable_cmd_param.advertising_handle[0] = adv_handle;  // num_sets *1
    le_set_extended_advertising_enable_cmd_param.duration[0] = 0x00;    // num_sets *1
    le_set_extended_advertising_enable_cmd_param.max_extended_advertising_events[0] = 0x00;    //No maximum number of advertising events
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_enable_cmd_param, sizeof(le_set_extended_advertising_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE status is 0x%x\n", status);

    if (adv_continuously) {
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, msc_advertising_using_adv_ext_ind_stop, (void *)&adv_handle);
    }
}

void msc_advertising_using_adv_ext_ind(int argc, char **argvcmd_req)
{
    uint8_t cfg_use_random_addr = 0;    // 0: not use random addr, 1: use random
    uint8_t cfg_use_scan_rsp_data = 1;  // 0: not use scan rsp data, else use
    uint8_t cfg_adv_continuously = 0;   // 0:no timeout, else use timeout
    uint8_t cfg_adv_handle = 0;         // 0:no timeout, else use timeout
    //config adv on handle 0 with static address
    msc_advertising_using_adv_ext_ind_start(cfg_use_random_addr, cfg_use_scan_rsp_data, cfg_adv_continuously, cfg_adv_handle);

    //config adv on handle 1 with random address
    cfg_use_random_addr = 1;
    cfg_adv_handle = 1;
    msc_advertising_using_adv_ext_ind_start(cfg_use_random_addr, cfg_use_scan_rsp_data, cfg_adv_continuously, cfg_adv_handle);
}
void msc_scan_request_notifications(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);

    //LE set extended advertising parameters --scan_request_notification_enable is set
    //LE set extended advertising Data
    //LE set extended scan response data
    le_set_extended_advertising_parameters_v1_cp le_set_extended_advertising_parameters_v1_cmd_param;
    //config the le_set_extended_advertising_parameters_v1_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_parameters_v1_cmd_param, sizeof(le_set_extended_advertising_parameters_v1_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    le_set_extended_advertising_data_cp le_set_extended_advertising_data_cmd_param;
    //config the le_set_extended_advertising_data_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_data_cmd_param, sizeof(le_set_extended_advertising_data_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    le_set_extended_scan_response_data_cp le_set_extended_scan_response_data_cmd_param;
    //config the le_set_extended_scan_response_data_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_scan_response_data_cmd_param, sizeof(le_set_extended_scan_response_data_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);
    //LE set extended advertising enable
    le_set_extended_advertising_enable_cp le_set_extended_advertising_enable_cmd_param;
    //config the le_set_extended_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_enable_cmd_param, sizeof(le_set_extended_advertising_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);
    //verify event LE scan request received.
    //expect received LE scan request event

}

void msc_advertising_duration_ended(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //LE set extended advertising parameters
    //LE set extended advertising Data
    //LE set extended scan response data
    //LE set extended advertising enable

    //verify event LE advertising set terminated received.
    le_set_extended_advertising_parameters_v1_cp le_set_extended_advertising_parameters_v1_cmd_param;
    //config the le_set_extended_advertising_parameters_v1_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_advertising_parameters_v1_cmd_param,
                                sizeof(le_set_extended_advertising_parameters_v1_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    le_set_extended_advertising_data_cp le_set_extended_advertising_data_cmd_param;
    //config the le_set_extended_advertising_data_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_data_cmd_param, sizeof(le_set_extended_advertising_data_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    le_set_extended_scan_response_data_cp le_set_extended_scan_response_data_cmd_param;
    //config the le_set_extended_scan_response_data_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_scan_response_data_cmd_param, sizeof(le_set_extended_scan_response_data_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);
    //LE set extended advertising enable
    le_set_extended_advertising_enable_cp le_set_extended_advertising_enable_cmd_param;
    //config the le_set_extended_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_enable_cmd_param, sizeof(le_set_extended_advertising_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);
    //expect received LE advertising terminated timeout
}

void msc_periodic_advertising(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //LE set extended advertising parameters
    le_set_extended_advertising_parameters_v1_cp le_set_extended_advertising_parameters_v1_cmd_param;
    //config the le_set_extended_advertising_parameters_v1_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_parameters_v1_cmd_param, sizeof(le_set_extended_advertising_parameters_v1_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    //LE set periotic advertising parameters
    le_set_periodic_advertising_parameters_v1_cp le_set_periodic_advertising_parameters_v1_cmd_param;
    //config the le_set_periodic_advertising_parameters_v1_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_PERIODIC_ADVERTISING_PARAMETERS, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_periodic_advertising_parameters_v1_cmd_param, sizeof(le_set_periodic_advertising_parameters_v1_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);
    //LE set periodic advertising enable
    le_set_periodic_advertising_enable_cp le_set_periodic_advertising_enable_cp;
    //config the le_set_periodic_advertising_enable_cp
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_PERIODIC_ADVERTISING_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_periodic_advertising_enable_cp, sizeof(le_set_periodic_advertising_enable_cp),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);
    //LE set extended advertising enable
    le_set_extended_advertising_enable_cp le_set_extended_advertising_enable_cmd_param;
    //config the le_set_extended_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_extended_advertising_enable_cmd_param, sizeof(le_set_extended_advertising_enable_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);
    //LE set periodic advertising data
    le_set_periodic_advertising_data_cp le_set_periodic_advertising_data_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_PERIODIC_ADVERTISING_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_periodic_advertising_data_cmd_param, sizeof(le_set_periodic_advertising_data_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_PERIODIC_ADVERTISING_DATA status is 0x%x\n", status);

    sleep(10);
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_PERIODIC_ADVERTISING_DATA, EVT_CMD_COMPLETE,
                                (uint8_t *)&le_set_periodic_advertising_data_cmd_param, sizeof(le_set_periodic_advertising_data_cmd_param),
								(uint8_t*)&status, sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_ADVERTISING_PARAMETERS status is 0x%x\n", status);

    //LE set periodic advertising data

    //LE set periodic advertising disable
    //LE set extended advertisiong disable
}

void msc_connectionless_constant_tone_extension_transmission(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //LE set extended advertising parameters
    //LE set periotic advertising parameters
    //LE set connectionless CTE transmit parameters
    //LE set connectionless CTE transmig enable
    //LE set periodic advertising enable
    //LE set extended advertising enable
    //LE set periodic adversting data

    //verify
    //LE set periodic advertising data
    //verify 2
    //LE set periodic advertising data
    //verify 3

}

//Isochronous_Broadcasting_State
void msc_create_a_broadcast_isochronous_group(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //Device set periodic advertisements
    //verify adv_EXT_IND, aux_adv_ind, aux_sync_ind
    //LE create BIG
    //verify aux_sync_ind+ACAD
    //LE create BIG complete
    //LE setup ISO data patch
    //verify BIS data packet
    //verify AUX_SYNC_IND + ACAD
}

void msc_terminate_a_broadcast_isochronous_group(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    //step: device is synchornized to a BIG
    //LE terminate BIG
    //verify comand status
    //verify LE terminate BIG complete
}

void msc_periodic_advertising_with_responses_pawr(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /*  LE Set Extended Advertising Parameters
     *  LE set Periodic advertising parameters
     *  LE set periodic advertising enable
     *  LE set exadvertising enable
     */
}

//3.10
void msc_transmitting_pawr_subevents(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_using_a_response_slot_in_pawr(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_connecting_from_pawr(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_failed_connection_attempts_from_pawr(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

//4.1
void msc_passive_scanning(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE Set Scan Parameters, passive scanning
     * LE Set Scan Enable(enable)
     * LE Advertising Report
     * LE set scan enable(disable)
     */
    le_set_scan_parameters_cp le_set_scan_parameters_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_scan_parameters_cmd_param,
                                sizeof(le_set_scan_parameters_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_SCAN_PARAMETERS status is 0x%x\n", status);

    le_set_scan_enable_cp le_set_scan_enable_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_scan_enable_cmd_param,
                                sizeof(le_set_scan_enable_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_SCAN_ENABLE status is 0x%x\n", status);

    // expect receive LE advertising report
    sleep(10);
    //disable scan
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_scan_enable_cmd_param,
                                sizeof(le_set_scan_enable_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_SCAN_ENABLE status is 0x%x\n", status);

}

void msc_active_scanning(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE Set Scan Parameters, active scanning
     * LE Set Scan Enable(enable)
     * LE Advertising Report
     * LE set scan enable(disable)
     */
    le_set_scan_parameters_cp le_set_scan_parameters_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_scan_parameters_cmd_param,
                                sizeof(le_set_scan_parameters_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_SCAN_PARAMETERS status is 0x%x\n", status);

    le_set_scan_enable_cp le_set_scan_enable_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_scan_enable_cmd_param,
                                sizeof(le_set_scan_enable_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_SCAN_ENABLE status is 0x%x\n", status);

    // expect receive LE advertising report
    sleep(10);
    //disable scan
	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_scan_enable_cmd_param,
                                sizeof(le_set_scan_enable_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_SCAN_ENABLE status is 0x%x\n", status);
}

void msc_passive_scanning_for_directed_advertisements_with_privacy(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE set scan parameters(passive scanning)
     * LE set scan enable
     * expect received LE directed advertising report
     */
}

void msc_active_scanning_with_privacy(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE add device to resolving list
     * le set address resolution enable
     * LE set scan parameters
     * LE set scan enable
     * expect received LE advertising report
     */
}

void msc_active_scanning_with_privacy_and_controller_based_resolvable_private_address_generation(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE add device to resolving list
       LE set address resolution enable
       LE set scan parameters
       LE set scan enable

       expect le advertising report

       LE read local resolvable address
       LE read peer resolvable address
     */
}

void msc_active_scanning_on_the_secondary_advertising_physical_channel(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE set extended scan parameters
       LE set extended scan enable
       expect receive LE extended advertising report...

     */
}

void msc_scan_timeout(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE set extended scan parameters
       LE set extended scan enable

       expect receive LE extended advertising report
       expect receive LE scan timeout

     */
    le_set_extended_scan_parameters_cp le_set_extended_scan_parameters_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_PARAMETERS,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_scan_parameters_cmd_param,
                                sizeof(le_set_extended_scan_parameters_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_SCAN_PARAMETERS status is 0x%x\n", status);

    le_set_extended_scan_enable_cp le_set_extended_scan_enable_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_ENABLE,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_scan_enable_cmd_param,
                                sizeof(le_set_extended_scan_enable_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_SCAN_ENABLE status is 0x%x\n", status);

    // verify received LE extended advertising report

    //verify received LE scan timeout
}

void msc_scanning_for_periodic_advertisements(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE set extended scan parameters
     * LE set extended scan enable
     * expect received LE extended advertising report
     * LE periodic advertising create sync
     * expect  LE periodic advertising sync established
     * expect receive LE periodic advertising report ...
     */
    le_set_extended_scan_parameters_cp le_set_extended_scan_parameters_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_PARAMETERS,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_scan_parameters_cmd_param,
                                sizeof(le_set_extended_scan_parameters_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_SCAN_PARAMETERS status is 0x%x\n", status);

    le_set_extended_scan_enable_cp le_set_extended_scan_enable_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_ENABLE,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_scan_enable_cmd_param,
                                sizeof(le_set_extended_scan_enable_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_SCAN_ENABLE status is 0x%x\n", status);

    // verify received LE extended advertising report

    le_periodic_advertising_create_sync_cp le_periodic_advertising_create_sync_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC,
								EVT_CMD_COMPLETE, (uint8_t *)&le_periodic_advertising_create_sync_cmd_param,
                                sizeof(le_periodic_advertising_create_sync_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC status is 0x%x\n", status);

    //expect receive LE periodic advertising report.
    sleep(30);
}

void msc_cancel_scanning_for_periodic_advertisements(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* LE set extended scan prarmeters
     * LE set extended scan enable
     * expect receive LE extended advertising report
     * LE periodic advertising create sync
     * LE periodic advertising create sync cancel
     * expect LE periodic advertising ysnc estaglished
     */
        le_set_extended_scan_parameters_cp le_set_extended_scan_parameters_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_PARAMETERS,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_scan_parameters_cmd_param,
                                sizeof(le_set_extended_scan_parameters_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_SCAN_PARAMETERS status is 0x%x\n", status);

    le_set_extended_scan_enable_cp le_set_extended_scan_enable_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EXTENDED_SCAN_ENABLE,
								EVT_CMD_COMPLETE, (uint8_t *)&le_set_extended_scan_enable_cmd_param,
                                sizeof(le_set_extended_scan_enable_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_SET_EXTENDED_SCAN_ENABLE status is 0x%x\n", status);

    // verify received LE extended advertising report

    le_periodic_advertising_create_sync_cp le_periodic_advertising_create_sync_cmd_param;
    //config the le_set_periodic_advertising_enable_cmd_param
    // ...

	if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC,
								EVT_CMD_COMPLETE, (uint8_t *)&le_periodic_advertising_create_sync_cmd_param,
                                sizeof(le_periodic_advertising_create_sync_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC status is 0x%x\n", status);


    //expect receive LE periodic advertising report.
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL,
								EVT_CMD_COMPLETE, (uint8_t *)&le_periodic_advertising_create_sync_cmd_param,
                                sizeof(le_periodic_advertising_create_sync_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL status is 0x%x\n", status);

    //expect receive LE periodic advertising sync established.

}

void msc_periodic_advertising_synchronization_timeout(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* step1: device receiving periodic adverts from remote device
     * expect received LE periodic advertising report ...
     * expect receive LE periodic advertising sync lost
     */
}

void msc_terminate_reception_of_periodic_advertising(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* step1: local device receiving periodic adverts from remote device
     * expect receive LE periodic advertising report...
     * step2: Local host wants to stop receiving periodic adverts from device B
     * LE periodic advertising teminate sync
     */
    le_periodic_advertising_terminate_sync_cp le_periodic_advertising_terminate_sync_cmd_param;
    if (hci_write_common_cmd(devfd, OGF_LE_CTL, OCF_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC,
								EVT_CMD_COMPLETE, (uint8_t *)&le_periodic_advertising_terminate_sync_cmd_param,
                                sizeof(le_periodic_advertising_terminate_sync_cmd_param),
								(uint8_t*)&status,
								sizeof(status),
								1000) < 0) {
		bt_shell_printf("Can't hci_write_common_cmd on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;
	}
    bt_shell_printf("OCF_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC status is 0x%x\n", status);

    //expect no new LE periodic advertising report received.
}

void msc_connectionless_constant_tone_extension_reception(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* step1: setup local device A to receive periodic adverts with CTE
     * LE set extended scan parameters
     * LE set extended scan enable
     * expect receive LE extended advertising report
     * LE periodic advertising sync enabled
     * expect LE periodic advertising report
     * LE set connectionless IQ sampling enable
     *expect receive LE periodic advertising report
     * expert receive LE connectionless IQ report
     */

}

void msc_synchronization_with_separate_enable_of_reports(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
    /* setp1: remote device sending periodic advertisements
     * setup scanning as in 4.8
     * HCI_LE_periodic_advertising_create_sync(disable report)
     * expect HCI LE periodic advertising sync enabled
     * HCI_LE_Periodic_Advertising_Sync_Established
     * HCI_LE_Set_Periodic_Advertising_Receive_Enable(enable)
     * expect HCI_LE_Periodic_advertising report
     * HCI_LE_Set_Periodic_Advertising_Receive_Enable(disable)
     * HCI_LE_Set_Periodic_Advertising_Receive_Enable(enable)
     * expect HCI_LE_Periodic_Advertising_Report
     * HCI_LE_Set_[eriodic_Advertising_Teminate_sync
     */
}

void msc_initiating_state(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_initiating_a_connection(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_canceling_an_initiation(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_initiating_a_connection_using_undirected_advertising_with_privacy(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_initiating_a_connection_using_directed_advertising_with_privacy(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_initiating_a_connection_that_fails_to_establish(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_initiating_a_connection_on_the_secondary_advertising_physical_channel(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_initiating_a_channel_selection_algorithm_2_connection(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_sending_data(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_connection_update(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_channel_map_update(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_features_exchange(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_version_exchange(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_start_encryption(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_start_encryption_without_long_term_key(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_start_encryption_with_event_masked(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_start_encryption_without_peripheral_supporting_encryption(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_restart_encryption(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_disconnect(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_connection_parameters_request(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_le_ping(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_data_length_update(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_phy_update(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_minimum_number_of_used_channels_request(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_ll_procedure_collision(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_constant_tone_extension_request(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_connected_isochronous_group_setup(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_host_rejects_connected_isochronous_stream(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_link_layer_rejects_connected_isochronous_stream_1(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_link_layer_rejects_connected_isochronous_stream_2(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_host_a_terminates_connected_isochronous_stream(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_acl_disconnected(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_host_a_removes_connected_isochronous_group(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_request_sleep_clock_accuracy(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_power_control(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_data_path_setup_for_a_music_stream_over_a_cis(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_data_path_setup_for_bidirectional_voice_over_a_cis(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_modifying_the_subrate_of_a_connection(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_channel_classification_enable(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_channel_classification_reporting(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_periodic_advertising_sync_transfer(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_transfer_by_scanner_reports_initially_disabled(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_transfer_by_scanner_reports_initially_enabled(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_transfer_by_the_advertiser(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_synchronization_state(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_synchronizing_with_a_broadcast_isochronous_group(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_terminate_synchronization_with_a_big(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_new_channel_map_for_broadcast_isochronous_group(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_lost_synchronization_with_a_broadcast_isochronous_group(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

void msc_data_path_setup_for_a_bis(int argc, char **argvcmd_req)
{
    uint8_t status = -1;
    bt_shell_printf("%s\n", __func__);
}

/* msc menu is test all the le features define bluetooth core spec
 * most apis is to verify the hci msc
 * some api will use the bluetooth api, and some api will directly write hci command
 */
const struct bt_shell_menu msc_menu = {
	.name = "msc",
	.desc = "msc submenu",
	.entries = {
	{ "msc_init_env", "", msc_init_env, "init le hci command test environment" },
	{ "msc_clear_env", "", msc_clear_env, "clear le hci command test environment" },
	{ "msc_initial_setup", "", msc_initial_setup, "" },
	{ "msc_random_device_address", "cmd_req", msc_random_device_address, "" },
	{ "msc_filter_accept_list", "cmd_req", msc_filter_accept_list, "" },
	{ "msc_adding_irk_to_resolving_list", "cmd_req", msc_adding_irk_to_resolving_list, "" },
	{ "msc_default_data_length", "cmd_req", msc_default_data_length, "" },
	{ "msc_periodic_advertiser_list", "cmd_req", msc_periodic_advertiser_list, "" },
	{ "msc_undirected_advertising", "cmd_req", msc_undirected_advertising, "" },
	{ "msc_high_duty_cycle_directed_advertising", "cmd_req", msc_high_duty_cycle_directed_advertising, "" },
	{ "msc_low_duty_cycle_directed_advertising", "cmd_req", msc_low_duty_cycle_directed_advertising, "" },
	{ "msc_advertising_using_adv_ext_ind", "cmd_req", msc_advertising_using_adv_ext_ind, "" },
	{ "msc_scan_request_notifications", "cmd_req", msc_scan_request_notifications, "" },
	{ "msc_advertising_duration_ended", "cmd_req", msc_advertising_duration_ended, "" },
#if 0
	{ "msc_periodic_advertising", "cmd_req", msc_periodic_advertising, "" },
	{ "msc_connectionless_constant_tone_extension_transmission", "cmd_req", msc_connectionless_constant_tone_extension_transmission, "" },
	{ "msc_isochronous_broadcasting_state", "cmd_req", msc_isochronous_broadcasting_state, "" },
	{ "msc_create_a_broadcast_isochronous_group", "cmd_req", msc_create_a_broadcast_isochronous_group, "" },
	{ "msc_terminate_a_broadcast_isochronous_group", "cmd_req", msc_terminate_a_broadcast_isochronous_group, "" },
	{ "msc_periodic_advertising_with_responses_pawr", "cmd_req", msc_periodic_advertising_with_responses_pawr, "" },
	{ "msc_transmitting_pawr_subevents", "cmd_req", msc_transmitting_pawr_subevents, "" },
	{ "msc_using_a_response_slot_in_pawr", "cmd_req", msc_using_a_response_slot_in_pawr, "" },
	{ "msc_connecting_from_pawr", "cmd_req", msc_connecting_from_pawr, "" },
	{ "msc_failed_connection_attempts_from_pawr", "cmd_req", msc_failed_connection_attempts_from_pawr, "" },
	{ "msc_scanning_state", "cmd_req", msc_scanning_state, "" },
	{ "msc_passive_scanning", "cmd_req", msc_passive_scanning, "" },
	{ "msc_active_scanning", "cmd_req", msc_active_scanning, "" },
	{ "msc_passive_scanning_for_directed_advertisements_with_privacy", "cmd_req", msc_passive_scanning_for_directed_advertisements_with_privacy, "" },
	{ "msc_active_scanning_with_privacy", "cmd_req", msc_active_scanning_with_privacy, "" },
	{ "msc_active_scanning_with_privacy_and_controller_based_resolvable_private_address_generation", "cmd_req", msc_active_scanning_with_privacy_and_controller_based_resolvable_private_address_generation, "" },
	{ "msc_active_scanning_on_the_secondary_advertising_physical_channel", "cmd_req", msc_active_scanning_on_the_secondary_advertising_physical_channel, "" },
	{ "msc_scan_timeout", "cmd_req", msc_scan_timeout, "" },
	{ "msc_scanning_for_periodic_advertisements", "cmd_req", msc_scanning_for_periodic_advertisements, "" },
	{ "msc_cancel_scanning_for_periodic_advertisements", "cmd_req", msc_cancel_scanning_for_periodic_advertisements, "" },
	{ "msc_periodic_advertising_synchronization_timeout", "cmd_req", msc_periodic_advertising_synchronization_timeout, "" },
	{ "msc_terminate_reception_of_periodic_advertising", "cmd_req", msc_terminate_reception_of_periodic_advertising, "" },
	{ "msc_connectionless_constant_tone_extension_reception", "cmd_req", msc_connectionless_constant_tone_extension_reception, "" },
	{ "msc_synchronization_with_separate_enable_of_reports", "cmd_req", msc_synchronization_with_separate_enable_of_reports, "" },
	{ "msc_initiating_state", "cmd_req", msc_initiating_state, "" },
	{ "msc_initiating_a_connection", "cmd_req", msc_initiating_a_connection, "" },
	{ "msc_canceling_an_initiation", "cmd_req", msc_canceling_an_initiation, "" },
	{ "msc_initiating_a_connection_using_undirected_advertising_with_privacy", "cmd_req", msc_initiating_a_connection_using_undirected_advertising_with_privacy, "" },
	{ "msc_initiating_a_connection_using_directed_advertising_with_privacy", "cmd_req", msc_initiating_a_connection_using_directed_advertising_with_privacy, "" },
	{ "msc_initiating_a_connection_that_fails_to_establish", "cmd_req", msc_initiating_a_connection_that_fails_to_establish, "" },
	{ "msc_initiating_a_connection_on_the_secondary_advertising_physical_channel", "cmd_req", msc_initiating_a_connection_on_the_secondary_advertising_physical_channel, "" },
	{ "msc_initiating_a_channel_selection_algorithm_2_connection", "cmd_req", msc_initiating_a_channel_selection_algorithm_2_connection, "" },
	{ "msc_sending_data", "cmd_req", msc_sending_data, "" },
	{ "msc_connection_update", "cmd_req", msc_connection_update, "" },
	{ "msc_channel_map_update", "cmd_req", msc_channel_map_update, "" },
	{ "msc_features_exchange", "cmd_req", msc_features_exchange, "" },
	{ "msc_version_exchange", "cmd_req", msc_version_exchange, "" },
	{ "msc_start_encryption", "cmd_req", msc_start_encryption, "" },
	{ "msc_start_encryption_without_long_term_key", "cmd_req", msc_start_encryption_without_long_term_key, "" },
	{ "msc_start_encryption_with_event_masked", "cmd_req", msc_start_encryption_with_event_masked, "" },
	{ "msc_start_encryption_without_peripheral_supporting_encryption", "cmd_req", msc_start_encryption_without_peripheral_supporting_encryption, "" },
	{ "msc_restart_encryption", "cmd_req", msc_restart_encryption, "" },
	{ "msc_disconnect", "cmd_req", msc_disconnect, "" },
	{ "msc_connection_parameters_request", "cmd_req", msc_connection_parameters_request, "" },
	{ "msc_le_ping", "cmd_req", msc_le_ping, "" },
	{ "msc_data_length_update", "cmd_req", msc_data_length_update, "" },
	{ "msc_phy_update", "cmd_req", msc_phy_update, "" },
	{ "msc_minimum_number_of_used_channels_request", "cmd_req", msc_minimum_number_of_used_channels_request, "" },
	{ "msc_ll_procedure_collision", "cmd_req", msc_ll_procedure_collision, "" },
	{ "msc_constant_tone_extension_request", "cmd_req", msc_constant_tone_extension_request, "" },
	{ "msc_connected_isochronous_group_setup", "cmd_req", msc_connected_isochronous_group_setup, "" },
	{ "msc_host_rejects_connected_isochronous_stream", "cmd_req", msc_host_rejects_connected_isochronous_stream, "" },
	{ "msc_link_layer_rejects_connected_isochronous_stream_1", "cmd_req", msc_link_layer_rejects_connected_isochronous_stream_1, "" },
	{ "msc_link_layer_rejects_connected_isochronous_stream_2", "cmd_req", msc_link_layer_rejects_connected_isochronous_stream_2, "" },
	{ "msc_host_a_terminates_connected_isochronous_stream", "cmd_req", msc_host_a_terminates_connected_isochronous_stream, "" },
	{ "msc_acl_disconnected", "cmd_req", msc_acl_disconnected, "" },
	{ "msc_host_a_removes_connected_isochronous_group", "cmd_req", msc_host_a_removes_connected_isochronous_group, "" },
	{ "msc_request_sleep_clock_accuracy", "cmd_req", msc_request_sleep_clock_accuracy, "" },
	{ "msc_power_control", "cmd_req", msc_power_control, "" },
	{ "msc_data_path_setup_for_a_music_stream_over_a_cis", "cmd_req", msc_data_path_setup_for_a_music_stream_over_a_cis, "" },
	{ "msc_data_path_setup_for_bidirectional_voice_over_a_cis", "cmd_req", msc_data_path_setup_for_bidirectional_voice_over_a_cis, "" },
	{ "msc_modifying_the_subrate_of_a_connection", "cmd_req", msc_modifying_the_subrate_of_a_connection, "" },
	{ "msc_channel_classification_enable", "cmd_req", msc_channel_classification_enable, "" },
	{ "msc_channel_classification_reporting", "cmd_req", msc_channel_classification_reporting, "" },
	{ "msc_periodic_advertising_sync_transfer", "cmd_req", msc_periodic_advertising_sync_transfer, "" },
	{ "msc_transfer_by_scanner_reports_initially_disabled", "cmd_req", msc_transfer_by_scanner_reports_initially_disabled, "" },
	{ "msc_transfer_by_scanner_reports_initially_enabled", "cmd_req", msc_transfer_by_scanner_reports_initially_enabled, "" },
	{ "msc_transfer_by_the_advertiser", "cmd_req", msc_transfer_by_the_advertiser, "" },
	{ "msc_synchronization_state", "cmd_req", msc_synchronization_state, "" },
	{ "msc_synchronizing_with_a_broadcast_isochronous_group", "cmd_req", msc_synchronizing_with_a_broadcast_isochronous_group, "" },
	{ "msc_terminate_synchronization_with_a_big", "cmd_req", msc_terminate_synchronization_with_a_big, "" },
	{ "msc_new_channel_map_for_broadcast_isochronous_group", "cmd_req", msc_new_channel_map_for_broadcast_isochronous_group, "" },
	{ "msc_lost_synchronization_with_a_broadcast_isochronous_group", "cmd_req", msc_lost_synchronization_with_a_broadcast_isochronous_group, "" },
	{ "msc_data_path_setup_for_a_bis", "cmd_req", msc_data_path_setup_for_a_bis, "" },
#endif //if 0
	{ } },
};
