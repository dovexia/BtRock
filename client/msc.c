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

#include "bluetooth.h"
#include "hci.h"
#include "lib/hci_lib.h"
#include "main.h"
#include "msc.h"

static int devfd;
static int hci_dev = 0;;


void msc_hex_dump(char *pref, int width, unsigned char *buf, int len)
{
	register int i,n;

	for (i = 0, n = 1; i < len; i++, n++) {
		if (n == 1)
			bt_shell_printf("%s %d: ", pref, i);
		bt_shell_printf("%2.2X ", buf[i]);
		if (n == width) {
			bt_shell_printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		bt_shell_printf("\n");
}

void msc_init_env(int argc, char *argv[])
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

void msc_clear_env(int argc, char *argv[])
{
	hci_close_dev(devfd);
    bt_shell_printf("%s\n", __func__);
}

void msc_Initial_setup(int argc, char *argv[])
{
    int32_t ret;
    int32_t default_timeout = 1000;
    // Reference core spec page 2491
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
    memset(evt_mask, 0, sizeof(evt_mask));
	uint32_t status = 0;
	if (hci_write_comon_cmd(devfd, OGF_HOST_CTL, OCF_SET_EVENT_MASK, 
								EVT_CMD_COMPLETE, evt_mask, 8, 
								(uint8_t*)&status, sizeof(status),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_SET_EVENT_MASK set event mask on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;		
	}
	bt_shell_printf("OCF_SET_EVENT_MASK status is %x\n", status);


    // LE setEvent Mask
	status = 0;
 	if (hci_write_comon_cmd(devfd, OGF_LE_CTL, OCF_LE_SET_EVENT_MASK, 
								EVT_CMD_COMPLETE, evt_mask, 8, 
								(uint8_t*)&status, sizeof(status),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_LE_SET_EVENT_MASK set event mask on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;		
	}
	bt_shell_printf("OCF_LE_SET_EVENT_MASK status is %x\n", status);
    // LE Read Buffer Size
	le_read_buffer_size_rp le_read_buffer_size_reply;
	memset(&le_read_buffer_size_reply, 0, sizeof(le_read_buffer_size_reply));
 	if (hci_write_comon_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_BUFFER_SIZE, 
								EVT_CMD_COMPLETE, NULL, 0, 
								(uint8_t*)&le_read_buffer_size_reply, sizeof(le_read_buffer_size_reply),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_LE_READ_BUFFER_SIZE set event mask on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;		
	}
	bt_shell_printf("OCF_LE_READ_BUFFER_SIZE status is %x\n", *(uint8_t*)&le_read_buffer_size_reply);
    // Read Buffer Size
	read_buffer_size_rp read_buffer_size_reply;
	memset(&read_buffer_size_reply, 0, sizeof(read_buffer_size_reply));
 	if (hci_write_comon_cmd(devfd, OGF_INFO_PARAM, OCF_READ_BUFFER_SIZE, 
								EVT_CMD_COMPLETE, NULL, 0, 
								(uint8_t*)&read_buffer_size_reply, sizeof(read_buffer_size_reply),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_READ_BUFFER_SIZE set event mask on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;		
	}
	bt_shell_printf("OCF_READ_BUFFER_SIZE status is %x\n", *(uint8_t*)&read_buffer_size_reply);
    // LE Read Local Support Features
	le_read_local_supported_features_rp le_read_local_supported_features_reply;
	memset(&le_read_local_supported_features_reply, 0, sizeof(le_read_local_supported_features_reply));
 	if (hci_write_comon_cmd(devfd, OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES, 
								EVT_CMD_COMPLETE, NULL, 0, 
								(uint8_t*)&le_read_local_supported_features_reply, sizeof(le_read_local_supported_features_reply),
								1000) <0)
	{
		bt_shell_printf("Can't OCF_LE_READ_LOCAL_SUPPORTED_FEATURES set event mask on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;		
	}
	bt_shell_printf("OCF_LE_READ_LOCAL_SUPPORTED_FEATURES status is %x\n", *(uint8_t*)&le_read_local_supported_features_reply);
    // Read BT_ADDR
	read_bd_addr_rp read_bd_addr_reply;
	memset(&read_bd_addr_reply, 0, sizeof(read_bd_addr_reply));
	if (hci_write_comon_cmd(devfd, OGF_INFO_PARAM, OCF_READ_BD_ADDR, 
								EVT_CMD_COMPLETE, NULL, 0, 
								(uint8_t*)&read_bd_addr_reply, sizeof(read_bd_addr_reply),
								1000) <0)
	{
		bt_shell_printf("Can't hci_write_comon_cmd set event mask on hci%d: %s (%d)\n",
					hci_dev, strerror(errno), errno);
		return;		
	}
	bt_shell_printf("OCF_READ_BD_ADDR status is %x\n", *(uint8_t*)&read_bd_addr_reply);
 }

void msc_Random_Device_address(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Filter_Accept_List(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Adding_IRK_to_resolving_list(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Default_data_length(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Periodic_Advertiser_List(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Undirected_advertising(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Directed_advertising(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Advertising_using_ADV_EXT_IND(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Scan_request_notifications(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Advertising_duration_ended(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Periodic_advertising(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Connectionless_Constant_Tone_Extension_transmission(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Isochronous_Broadcasting_State(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Create_a_Broadcast_Isochronous_Group(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Terminate_a_Broadcast_Isochronous_Group(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Periodic_advertising_with_responses_PAwR(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Transmitting_PAwR_subevents(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Using_a_response_slot_in_PAwR(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Connecting_from_PAwR(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Failed_Connection_Attempts_From_PAWR(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Scanning_state(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Passive_scanning(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Active_scanning(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Passive_scanning_for_directed_advertisements_with_Privacy(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Active_scanning_with_Privacy(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Active_scanning_with_Privacy_and_Controller_based_resolvable_private_address_generatio(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Active_scanning_on_the_secondary_advertising_Physical_channel(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Scan_timeout(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Scanning_for_periodic_advertisements(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Cancel_scanning_for_periodic_advertisements(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Periodic_advertising_synchronization_timeout(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Terminate_reception_of_periodic_advertising(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Connectionless_Constant_Tone_Extension_reception(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Synchronization_with_separate_enable_of_reports(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Initiating_state(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Initiating_a_connection(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Canceling_an_initiation(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Initiating_a_connection_using_undirected_advertising_with_Privacy(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Initiating_a_connection_using_directed_advertising_with_Privacy(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Initiating_a_connection_that_fails_to_establish(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Initiating_a_connection_on_the_secondary_advertising_physical_channel(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Initiating_a_Channel_Selection_algorithm_2_connection(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Sending_data(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Connection_update(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Channel_map_update(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Features_exchange(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Version_exchange(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Start_encryption(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Start_encryption_without_long_term_key(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Start_encryption_with_event_masked(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Start_encryption_without_Peripheral_supporting_encryption(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Restart_encryption(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Disconnect(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Connection_parameters_request(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_LE_Ping(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Data_length_update(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_PHY_update(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Minimum_number_of_used_channels_request(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_LL_procedure_collision(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Constant_Tone_Extension_Request(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Connected_Isochronous_Group_Setup(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Host_Rejects_Connected_Isochronous_Stream(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Link_Layer_Rejects_Connected_Isochronous_Stream_1(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Link_Layer_Rejects_Connected_Isochronous_Stream_2(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Host_A_Terminates_Connected_Isochronous_Stream(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_ACL_disconnected(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Host_A_Removes_Connected_Isochronous_Group(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Request_Sleep_Clock_Accuracy(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Power_Control(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Data_path_setup_for_a_music_stream_over_a_CIS(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Data_path_setup_for_bidirectional_voice_over_a_CIS(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Modifying_the_subrate_of_a_connection(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Channel_Classification_Enable(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Channel_Classification_Reporting(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Periodic_advertising_sync_transfer(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Transfer_by_scanner_reports_initially_disabled(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Transfer_by_scanner_reports_initially_enabled(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Transfer_by_the_advertiser(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Synchronization_state(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Synchronizing_with_a_Broadcast_Isochronous_Group(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Terminate_Synchronization_with_a_BIG(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_New_Channel_Map_for_Broadcast_Isochronous_Group(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Lost_Synchronization_with_a_Broadcast_Isochronous_Group(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void msc_Data_path_setup_for_a_BIS(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

/* msc menu is test all the le features define bluetooth core spec
 * most apis is to verify the hci msc
 * some api will use the bluetooth api, and some api will directly write hci command
 */
const struct bt_shell_menu msc_menu = {
	.name = "msc",
	.desc = "msc Submenu",
	.entries = {
	{ "msc_init_env", "[]", msc_init_env, "Init le hci command test environment" },
	{ "msc_clear_env", "[]", msc_clear_env, "Clear le hci command test environment" },
	{ "msc_Initial_setup", "[]", msc_Initial_setup, "" },
	{ "msc_Random_Device_address", "[]", msc_Random_Device_address, "" },
#if 0
	{ "msc_Filter_Accept_List", "[]", msc_Filter_Accept_List, "" },
	{ "msc_Adding_IRK_to_resolving_list", "[]", msc_Adding_IRK_to_resolving_list, "" },
	{ "msc_Default_data_length", "[]", msc_Default_data_length, "" },
	{ "msc_Periodic_Advertiser_List", "[]", msc_Periodic_Advertiser_List, "" },
	{ "msc_Undirected_advertising", "[]", msc_Undirected_advertising, "" },
	{ "msc_Directed_advertising", "[]", msc_Directed_advertising, "" },
	{ "msc_Advertising_using_ADV_EXT_IND", "[]", msc_Advertising_using_ADV_EXT_IND, "" },
	{ "msc_Scan_request_notifications", "[]", msc_Scan_request_notifications, "" },
	{ "msc_Advertising_duration_ended", "[]", msc_Advertising_duration_ended, "" },
	{ "msc_Periodic_advertising", "[]", msc_Periodic_advertising, "" },
	{ "msc_Connectionless_Constant_Tone_Extension_transmission", "[]", msc_Connectionless_Constant_Tone_Extension_transmission, "" },
	{ "msc_Isochronous_Broadcasting_State", "[]", msc_Isochronous_Broadcasting_State, "" },
	{ "msc_Create_a_Broadcast_Isochronous_Group", "[]", msc_Create_a_Broadcast_Isochronous_Group, "" },
	{ "msc_Terminate_a_Broadcast_Isochronous_Group", "[]", msc_Terminate_a_Broadcast_Isochronous_Group, "" },
	{ "msc_Periodic_advertising_with_responses_PAwR", "[]", msc_Periodic_advertising_with_responses_PAwR, "" },
	{ "msc_Transmitting_PAwR_subevents", "[]", msc_Transmitting_PAwR_subevents, "" },
	{ "msc_Using_a_response_slot_in_PAwR", "[]", msc_Using_a_response_slot_in_PAwR, "" },
	{ "msc_Connecting_from_PAwR", "[]", msc_Connecting_from_PAwR, "" },
	{ "msc_Failed_Connection_Attempts_From_PAWR", "[]", msc_Failed_Connection_Attempts_From_PAWR, "" },
	{ "msc_Scanning_state", "[]", msc_Scanning_state, "" },
	{ "msc_Passive_scanning", "[]", msc_Passive_scanning, "" },
	{ "msc_Active_scanning", "[]", msc_Active_scanning, "" },
	{ "msc_Passive_scanning_for_directed_advertisements_with_Privacy", "[]", msc_Passive_scanning_for_directed_advertisements_with_Privacy, "" },
	{ "msc_Active_scanning_with_Privacy", "[]", msc_Active_scanning_with_Privacy, "" },
	{ "msc_Active_scanning_with_Privacy_and_Controller_based_resolvable_private_address_generatio", "[]", msc_Active_scanning_with_Privacy_and_Controller_based_resolvable_private_address_generatio, "" },
	{ "msc_Active_scanning_on_the_secondary_advertising_Physical_channel", "[]", msc_Active_scanning_on_the_secondary_advertising_Physical_channel, "" },
	{ "msc_Scan_timeout", "[]", msc_Scan_timeout, "" },
	{ "msc_Scanning_for_periodic_advertisements", "[]", msc_Scanning_for_periodic_advertisements, "" },
	{ "msc_Cancel_scanning_for_periodic_advertisements", "[]", msc_Cancel_scanning_for_periodic_advertisements, "" },
	{ "msc_Periodic_advertising_synchronization_timeout", "[]", msc_Periodic_advertising_synchronization_timeout, "" },
	{ "msc_Terminate_reception_of_periodic_advertising", "[]", msc_Terminate_reception_of_periodic_advertising, "" },
	{ "msc_Connectionless_Constant_Tone_Extension_reception", "[]", msc_Connectionless_Constant_Tone_Extension_reception, "" },
	{ "msc_Synchronization_with_separate_enable_of_reports", "[]", msc_Synchronization_with_separate_enable_of_reports, "" },
	{ "msc_Initiating_state", "[]", msc_Initiating_state, "" },
	{ "msc_Initiating_a_connection", "[]", msc_Initiating_a_connection, "" },
	{ "msc_Canceling_an_initiation", "[]", msc_Canceling_an_initiation, "" },
	{ "msc_Initiating_a_connection_using_undirected_advertising_with_Privacy", "[]", msc_Initiating_a_connection_using_undirected_advertising_with_Privacy, "" },
	{ "msc_Initiating_a_connection_using_directed_advertising_with_Privacy", "[]", msc_Initiating_a_connection_using_directed_advertising_with_Privacy, "" },
	{ "msc_Initiating_a_connection_that_fails_to_establish", "[]", msc_Initiating_a_connection_that_fails_to_establish, "" },
	{ "msc_Initiating_a_connection_on_the_secondary_advertising_physical_channel", "[]", msc_Initiating_a_connection_on_the_secondary_advertising_physical_channel, "" },
	{ "msc_Initiating_a_Channel_Selection_algorithm_2_connection", "[]", msc_Initiating_a_Channel_Selection_algorithm_2_connection, "" },
	{ "msc_Sending_data", "[]", msc_Sending_data, "" },
	{ "msc_Connection_update", "[]", msc_Connection_update, "" },
	{ "msc_Channel_map_update", "[]", msc_Channel_map_update, "" },
	{ "msc_Features_exchange", "[]", msc_Features_exchange, "" },
	{ "msc_Version_exchange", "[]", msc_Version_exchange, "" },
	{ "msc_Start_encryption", "[]", msc_Start_encryption, "" },
	{ "msc_Start_encryption_without_long_term_key", "[]", msc_Start_encryption_without_long_term_key, "" },
	{ "msc_Start_encryption_with_event_masked", "[]", msc_Start_encryption_with_event_masked, "" },
	{ "msc_Start_encryption_without_Peripheral_supporting_encryption", "[]", msc_Start_encryption_without_Peripheral_supporting_encryption, "" },
	{ "msc_Restart_encryption", "[]", msc_Restart_encryption, "" },
	{ "msc_Disconnect", "[]", msc_Disconnect, "" },
	{ "msc_Connection_parameters_request", "[]", msc_Connection_parameters_request, "" },
	{ "msc_LE_Ping", "[]", msc_LE_Ping, "" },
	{ "msc_Data_length_update", "[]", msc_Data_length_update, "" },
	{ "msc_PHY_update", "[]", msc_PHY_update, "" },
	{ "msc_Minimum_number_of_used_channels_request", "[]", msc_Minimum_number_of_used_channels_request, "" },
	{ "msc_LL_procedure_collision", "[]", msc_LL_procedure_collision, "" },
	{ "msc_Constant_Tone_Extension_Request", "[]", msc_Constant_Tone_Extension_Request, "" },
	{ "msc_Connected_Isochronous_Group_Setup", "[]", msc_Connected_Isochronous_Group_Setup, "" },
	{ "msc_Host_Rejects_Connected_Isochronous_Stream", "[]", msc_Host_Rejects_Connected_Isochronous_Stream, "" },
	{ "msc_Link_Layer_Rejects_Connected_Isochronous_Stream_1", "[]", msc_Link_Layer_Rejects_Connected_Isochronous_Stream_1, "" },
	{ "msc_Link_Layer_Rejects_Connected_Isochronous_Stream_2", "[]", msc_Link_Layer_Rejects_Connected_Isochronous_Stream_2, "" },
	{ "msc_Host_A_Terminates_Connected_Isochronous_Stream", "[]", msc_Host_A_Terminates_Connected_Isochronous_Stream, "" },
	{ "msc_ACL_disconnected", "[]", msc_ACL_disconnected, "" },
	{ "msc_Host_A_Removes_Connected_Isochronous_Group", "[]", msc_Host_A_Removes_Connected_Isochronous_Group, "" },
	{ "msc_Request_Sleep_Clock_Accuracy", "[]", msc_Request_Sleep_Clock_Accuracy, "" },
	{ "msc_Power_Control", "[]", msc_Power_Control, "" },
	{ "msc_Data_path_setup_for_a_music_stream_over_a_CIS", "[]", msc_Data_path_setup_for_a_music_stream_over_a_CIS, "" },
	{ "msc_Data_path_setup_for_bidirectional_voice_over_a_CIS", "[]", msc_Data_path_setup_for_bidirectional_voice_over_a_CIS, "" },
	{ "msc_Modifying_the_subrate_of_a_connection", "[]", msc_Modifying_the_subrate_of_a_connection, "" },
	{ "msc_Channel_Classification_Enable", "[]", msc_Channel_Classification_Enable, "" },
	{ "msc_Channel_Classification_Reporting", "[]", msc_Channel_Classification_Reporting, "" },
	{ "msc_Periodic_advertising_sync_transfer", "[]", msc_Periodic_advertising_sync_transfer, "" },
	{ "msc_Transfer_by_scanner_reports_initially_disabled", "[]", msc_Transfer_by_scanner_reports_initially_disabled, "" },
	{ "msc_Transfer_by_scanner_reports_initially_enabled", "[]", msc_Transfer_by_scanner_reports_initially_enabled, "" },
	{ "msc_Transfer_by_the_advertiser", "[]", msc_Transfer_by_the_advertiser, "" },
	{ "msc_Synchronization_state", "[]", msc_Synchronization_state, "" },
	{ "msc_Synchronizing_with_a_Broadcast_Isochronous_Group", "[]", msc_Synchronizing_with_a_Broadcast_Isochronous_Group, "" },
	{ "msc_Terminate_Synchronization_with_a_BIG", "[]", msc_Terminate_Synchronization_with_a_BIG, "" },
	{ "msc_New_Channel_Map_for_Broadcast_Isochronous_Group", "[]", msc_New_Channel_Map_for_Broadcast_Isochronous_Group, "" },
	{ "msc_Lost_Synchronization_with_a_Broadcast_Isochronous_Group", "[]", msc_Lost_Synchronization_with_a_Broadcast_Isochronous_Group, "" },
	{ "msc_Data_path_setup_for_a_BIS", "[]", msc_Data_path_setup_for_a_BIS, "" },
#endif //if 0
	{ } },
};
