/**
 * @copyright Copyright (c) 2023, ThunderSoft, Ltd.
 * @file lehcicmdtest.c
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

/* in lehcicmdtest, some LE commands are supported by blueZ and others are not.
 * if a LE hci command are not supported in BlueZ, then will use hcicommand directly 
 * to handle.
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

#include "main.h"
#include "lehcicmdtest.h"

void LE_init_env(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_clear_env(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Event_Mask_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Buffer_Size_cmd_v1(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Buffer_Size_cmd_v2(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Local_Supported_Features_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Random_Address_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Advertising_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Advertising_Channel_Tx_Power_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Advertising_Data_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Scan_Response_Data_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Advertising_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Scan_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Scan_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Create_Connection_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Create_Connection_Cancel_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Filter_Accept_List_Size_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Clear_Filter_Accept_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Add_Device_To_Filter_Accept_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remove_Device_From_Filter_Accept_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Connection_Update_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Host_Channel_Classification_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Channel_Map_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Remote_Features_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Encrypt_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Rand_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Enable_Encryption_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Long_Term_Key_Request_Reply_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Long_Term_Key_Request_Negative_Reply_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Supported_States_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Receiver_Test_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Transmitter_Test_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Test_End_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remote_Connection_Parameter_Request_Replycmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remote_Connection_Parameter_Request_NegativeReply_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Data_Length_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Suggested_Default_Data_Length_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Write_Suggested_Default_Data_Length_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Local_P_256_Public_Key_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Generate_DHKey_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Add_Device_To_Resolving_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remove_Device_From_Resolving_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Clear_Resolving_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Resolving_List_Size_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Peer_Resolvable_Address_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Local_Resolvable_Address_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Address_Resolution_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Resolvable_Private_Address_Timeout_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Maximum_Data_Length_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_PHY_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Default_PHY_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_PHY_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Advertising_Set_Random_Address_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Extended_Advertising_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Extended_Advertising_Data_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Extended_Scan_Response_Data_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Extended_Advertising_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Maximum_Advertising_Data_Length_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Number_of_Supported_Advertising_Setscmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remove_Advertising_Set_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Clear_Advertising_Sets_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Advertising_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Advertising_Data_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Advertising_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Extended_Scan_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Extended_Scan_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Extended_Create_Connection_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Periodic_Advertising_Create_Sync_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Periodic_Advertising_Create_Sync_Cancel_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Periodic_Advertising_Terminate_Sync_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Add_Device_To_Periodic_Advertiser_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remove_Device_From_Periodic_Advertiser_Listcmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Clear_Periodic_Advertiser_List_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Periodic_Advertiser_List_Size_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Transmit_Power_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_RF_Path_Compensation_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Write_RF_Path_Compensation_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Privacy_Mode_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Connectionless_CTE_Transmit_Parameterscmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Connectionless_CTE_Transmit_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Connectionless_IQ_Sampling_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Connection_CTE_Receive_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Connection_CTE_Transmit_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Connection_CTE_Request_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Connection_CTE_Response_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Antenna_Information_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Advertising_Receive_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Periodic_Advertising_Sync_Transfer_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Periodic_Advertising_Set_Info_Transfer_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Advertising_Sync_Transfer_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Default_Periodic_Advertising_Sync_TransferParameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Modify_Sleep_Clock_Accuracy_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_ISO_TX_Sync_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_CIG_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_CIG_Parameters_Test_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Create_CIS_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remove_CIG_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Accept_CIS_Request_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Reject_CIS_Request_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Create_BIG_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Create_BIG_Test_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Terminate_BIG_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_BIG_Create_Sync_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_BIG_Terminate_Sync_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Request_Peer_SCA_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Setup_ISO_Data_Path_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Remove_ISO_Data_Path_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_ISO_Transmit_Test_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_ISO_Receive_Test_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_ISO_Read_Test_Counters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_ISO_Test_End_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Host_Feature_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_ISO_Link_Quality_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Enhanced_Read_Transmit_Power_Level_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Read_Remote_Transmit_Power_Level_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Path_Loss_Reporting_Parameters_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Path_Loss_Reporting_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Transmit_Power_Reporting_Enable_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Data_Related_Address_Changes_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Default_Subrate_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Subrate_Request_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Advertising_Subevent_Data_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Advertising_Response_Data_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}

void LE_Set_Periodic_Sync_Subevent_cmd(int argc, char *argv[])
{
    bt_shell_printf("%s\n", __func__);
}


/* lehcicmd menu is test all the le features define bluetooth core spec
 * most apis is to verify the hci command
 * some api will use the bluetooth api, and some api will directly write hci command
 */
const struct bt_shell_menu lehcicmd_menu = {
	.name = "lehcicmd",
	.desc = "LE hci command Submenu",
	.entries = {
	{ "LE_init_env", "[]", LE_init_env, "Init le hci command test environment" },
	{ "LE_clear_env", "[]", LE_clear_env, "Clear le hci command test environment" },
	{ "LE_Set_Event_Mask_cmd", "[uint16]", LE_Set_Event_Mask_cmd, "" },
	{ "LE_Read_Buffer_Size_cmd", "[]", LE_Read_Buffer_Size_cmd_v1, "" },
	{ "LE_Read_Buffer_Size_cmd", "[]", LE_Read_Buffer_Size_cmd_v2, "" },
	{ "LE_Read_Local_Supported_Features_cmd", "", LE_Read_Local_Supported_Features_cmd, "" },
	{ "LE_Set_Random_Address_cmd", "[Random_Address]", LE_Set_Random_Address_cmd, "" },
	{ "HCI_LE_Set_Advertising_Parameters_cmd", "[]", LE_Set_Advertising_Parameters_cmd, "" },
	{ "HCI_LE_Read_Advertising_Channel_Tx_Power_cmd", "[]", LE_Read_Advertising_Channel_Tx_Power_cmd, "" },
	{ "LE_Set_Advertising_Data_cmd", "[]", LE_Set_Advertising_Data_cmd, "" },
	{ "LE_Set_Scan_Response_Data_cmd", "[]", LE_Set_Scan_Response_Data_cmd, "" },
	{ "LE_Set_Advertising_Enable_cmd", "[]", LE_Set_Advertising_Enable_cmd, "" },
	{ "LE_Set_Scan_Parameters_cmd", "[]", LE_Set_Scan_Parameters_cmd, "" },
	{ "LE_Set_Scan_Enable_cmd", "[]", LE_Set_Scan_Enable_cmd, "" },
	{ "LE_Create_Connection_cmd", "[]", LE_Create_Connection_cmd, "" },
	{ "LE_Create_Connection_Cancel_cmd", "[]", LE_Create_Connection_Cancel_cmd, "" },
	{ "LE_Read_Filter_Accept_List_Size_cmd", "[]", LE_Read_Filter_Accept_List_Size_cmd, "" },
	{ "LE_Clear_Filter_Accept_List_cmd", "[]", LE_Clear_Filter_Accept_List_cmd, "" },
	{ "LE_Add_Device_To_Filter_Accept_List_cmd", "[]", LE_Add_Device_To_Filter_Accept_List_cmd, "" },
	{ "LE_Remove_Device_From_Filter_Accept_List_cmd", "[]", LE_Remove_Device_From_Filter_Accept_List_cmd, "" },
	{ "LE_Connection_Update_cmd", "[]", LE_Connection_Update_cmd, "" },
	{ "LE_Set_Host_Channel_Classification_cmd", "[]", LE_Set_Host_Channel_Classification_cmd, "" },
	{ "LE_Read_Channel_Map_cmd", "[]", LE_Read_Channel_Map_cmd, "" },
	{ "LE_Read_Remote_Features_cmd", "[]", LE_Read_Remote_Features_cmd, "" },
	{ "LE_Encrypt_cmd", "[]", LE_Encrypt_cmd, "" },
	{ "LE_Rand_cmd", "[]", LE_Rand_cmd, "" },
	{ "LE_Enable_Encryption_cmd", "[]", LE_Enable_Encryption_cmd, "" },
	{ "LE_Long_Term_Key_Request_Reply_cmd", "[]", LE_Long_Term_Key_Request_Reply_cmd, "" },
	{ "LE_Long_Term_Key_Request_Negative_Reply_cmd", "[]", LE_Long_Term_Key_Request_Negative_Reply_cmd, "" },
	{ "LE_Read_Supported_States_cmd", "[]", LE_Read_Supported_States_cmd, "" },
	{ "LE_Receiver_Test_cmd", "[]", LE_Receiver_Test_cmd, "" },
	{ "LE_Transmitter_Test_cmd", "[]", LE_Transmitter_Test_cmd, "" },
	{ "LE_Test_End_cmd", "[]", LE_Test_End_cmd, "" },
	{ "LE_Remote_Connection_Parameter_Request_Replycmd", "[]", LE_Remote_Connection_Parameter_Request_Replycmd, "" },
	{ "LE_Remote_Connection_Parameter_Request_NegativeReply_cmd", "[]", LE_Remote_Connection_Parameter_Request_NegativeReply_cmd, "" },
	{ "LE_Set_Data_Length_cmd", "[]", LE_Set_Data_Length_cmd, "" },
	{ "LE_Read_Suggested_Default_Data_Length_cmd", "[]", LE_Read_Suggested_Default_Data_Length_cmd, "" },
	{ "LE_Write_Suggested_Default_Data_Length_cmd", "[]", LE_Write_Suggested_Default_Data_Length_cmd, "" },
	{ "LE_Read_Local_P_256_Public_Key_cmd", "[]", LE_Read_Local_P_256_Public_Key_cmd, "" },
	{ "LE_Generate_DHKey_cmd", "[]", LE_Generate_DHKey_cmd, "" },
	{ "LE_Add_Device_To_Resolving_List_cmd", "[]", LE_Add_Device_To_Resolving_List_cmd, "" },
	{ "LE_Remove_Device_From_Resolving_List_cmd", "[]", LE_Remove_Device_From_Resolving_List_cmd, "" },
	{ "LE_Clear_Resolving_List_cmd", "[]", LE_Clear_Resolving_List_cmd, "" },
	{ "LE_Read_Resolving_List_Size_cmd", "[]", LE_Read_Resolving_List_Size_cmd, "" },
	{ "LE_Read_Peer_Resolvable_Address_cmd", "[]", LE_Read_Peer_Resolvable_Address_cmd, "" },
	{ "LE_Read_Local_Resolvable_Address_cmd", "[]", LE_Read_Local_Resolvable_Address_cmd, "" },
	{ "LE_Set_Address_Resolution_Enable_cmd", "[]", LE_Set_Address_Resolution_Enable_cmd, "" },
	{ "LE_Set_Resolvable_Private_Address_Timeout_cmd", "[]", LE_Set_Resolvable_Private_Address_Timeout_cmd, "" },
	{ "LE_Read_Maximum_Data_Length_cmd", "[]", LE_Read_Maximum_Data_Length_cmd, "" },
	{ "LE_Read_PHY_cmd", "[]", LE_Read_PHY_cmd, "" },
	{ "LE_Set_Default_PHY_cmd", "[]", LE_Set_Default_PHY_cmd, "" },
	{ "LE_Set_PHY_cmd", "[]", LE_Set_PHY_cmd, "" },
	{ "LE_Set_Advertising_Set_Random_Address_cmd", "[]", LE_Set_Advertising_Set_Random_Address_cmd, "" },
	{ "LE_Set_Extended_Advertising_Parameters_cmd", "[]", LE_Set_Extended_Advertising_Parameters_cmd, "" },
	{ "LE_Set_Extended_Advertising_Data_cmd", "[]", LE_Set_Extended_Advertising_Data_cmd, "" },
	{ "LE_Set_Extended_Scan_Response_Data_cmd", "[]", LE_Set_Extended_Scan_Response_Data_cmd, "" },
	{ "LE_Set_Extended_Advertising_Enable_cmd", "[]", LE_Set_Extended_Advertising_Enable_cmd, "" },
	{ "LE_Read_Maximum_Advertising_Data_Length_cmd", "[]", LE_Read_Maximum_Advertising_Data_Length_cmd, "" },
	{ "LE_Read_Number_of_Supported_Advertising_Setscmd", "[]", LE_Read_Number_of_Supported_Advertising_Setscmd, "" },
	{ "LE_Remove_Advertising_Set_cmd", "[]", LE_Remove_Advertising_Set_cmd, "" },
	{ "LE_Clear_Advertising_Sets_cmd", "[]", LE_Clear_Advertising_Sets_cmd, "" },
	{ "LE_Set_Periodic_Advertising_Parameters_cmd", "[]", LE_Set_Periodic_Advertising_Parameters_cmd, "" },
	{ "LE_Set_Periodic_Advertising_Data_cmd", "[]", LE_Set_Periodic_Advertising_Data_cmd, "" },
	{ "LE_Set_Periodic_Advertising_Enable_cmd", "[]", LE_Set_Periodic_Advertising_Enable_cmd, "" },
	{ "LE_Set_Extended_Scan_Parameters_cmd", "[]", LE_Set_Extended_Scan_Parameters_cmd, "" },
	{ "LE_Set_Extended_Scan_Enable_cmd", "[]", LE_Set_Extended_Scan_Enable_cmd, "" },
	{ "LE_Extended_Create_Connection_cmd", "[]", LE_Extended_Create_Connection_cmd, "" },
	{ "LE_Periodic_Advertising_Create_Sync_cmd", "[]", LE_Periodic_Advertising_Create_Sync_cmd, "" },
	{ "LE_Periodic_Advertising_Create_Sync_Cancel_cmd", "[]", LE_Periodic_Advertising_Create_Sync_Cancel_cmd, "" },
	{ "LE_Periodic_Advertising_Terminate_Sync_cmd", "[]", LE_Periodic_Advertising_Terminate_Sync_cmd, "" },
	{ "LE_Add_Device_To_Periodic_Advertiser_List_cmd", "[]", LE_Add_Device_To_Periodic_Advertiser_List_cmd, "" },
	{ "LE_Remove_Device_From_Periodic_Advertiser_Listcmd", "[]", LE_Remove_Device_From_Periodic_Advertiser_Listcmd, "" },
	{ "LE_Clear_Periodic_Advertiser_List_cmd", "[]", LE_Clear_Periodic_Advertiser_List_cmd, "" },
	{ "LE_Read_Periodic_Advertiser_List_Size_cmd", "[]", LE_Read_Periodic_Advertiser_List_Size_cmd, "" },
	{ "LE_Read_Transmit_Power_cmd", "[]", LE_Read_Transmit_Power_cmd, "" },
	{ "LE_Read_RF_Path_Compensation_cmd", "[]", LE_Read_RF_Path_Compensation_cmd, "" },
	{ "LE_Write_RF_Path_Compensation_cmd", "[]", LE_Write_RF_Path_Compensation_cmd, "" },
	{ "LE_Set_Privacy_Mode_cmd", "[]", LE_Set_Privacy_Mode_cmd, "" },
	{ "LE_Set_Connectionless_CTE_Transmit_Parameterscmd", "[]", LE_Set_Connectionless_CTE_Transmit_Parameterscmd, "" },
	{ "LE_Set_Connectionless_CTE_Transmit_Enable_cmd", "[]", LE_Set_Connectionless_CTE_Transmit_Enable_cmd, "" },
	{ "LE_Set_Connectionless_IQ_Sampling_Enable_cmd", "[]", LE_Set_Connectionless_IQ_Sampling_Enable_cmd, "" },
	{ "LE_Set_Connection_CTE_Receive_Parameters_cmd", "[]", LE_Set_Connection_CTE_Receive_Parameters_cmd, "" },
	{ "LE_Set_Connection_CTE_Transmit_Parameters_cmd", "[]", LE_Set_Connection_CTE_Transmit_Parameters_cmd, "" },
	{ "LE_Connection_CTE_Request_Enable_cmd", "[]", LE_Connection_CTE_Request_Enable_cmd, "" },
	{ "LE_Connection_CTE_Response_Enable_cmd", "[]", LE_Connection_CTE_Response_Enable_cmd, "" },
	{ "LE_Read_Antenna_Information_cmd", "[]", LE_Read_Antenna_Information_cmd, "" },
	{ "LE_Set_Periodic_Advertising_Receive_Enable_cmd", "[]", LE_Set_Periodic_Advertising_Receive_Enable_cmd, "" },
	{ "LE_Periodic_Advertising_Sync_Transfer_cmd", "[]", LE_Periodic_Advertising_Sync_Transfer_cmd, "" },
	{ "LE_Periodic_Advertising_Set_Info_Transfer_cmd", "[]", LE_Periodic_Advertising_Set_Info_Transfer_cmd, "" },
	{ "LE_Set_Periodic_Advertising_Sync_Transfer_Parameters_cmd", "[]", LE_Set_Periodic_Advertising_Sync_Transfer_Parameters_cmd, "" },
	{ "LE_Set_Default_Periodic_Advertising_Sync_TransferParameters_cmd", "[]", LE_Set_Default_Periodic_Advertising_Sync_TransferParameters_cmd, "" },
	{ "LE_Modify_Sleep_Clock_Accuracy_cmd", "[]", LE_Modify_Sleep_Clock_Accuracy_cmd, "" },
	{ "LE_Read_ISO_TX_Sync_cmd", "[]", LE_Read_ISO_TX_Sync_cmd, "" },
	{ "LE_Set_CIG_Parameters_cmd", "[]", LE_Set_CIG_Parameters_cmd, "" },
	{ "LE_Set_CIG_Parameters_Test_cmd", "[]", LE_Set_CIG_Parameters_Test_cmd, "" },
	{ "LE_Create_CIS_cmd", "[]", LE_Create_CIS_cmd, "" },
	{ "LE_Remove_CIG_cmd", "[]", LE_Remove_CIG_cmd, "" },
	{ "LE_Accept_CIS_Request_cmd", "[]", LE_Accept_CIS_Request_cmd, "" },
	{ "LE_Reject_CIS_Request_cmd", "[]", LE_Reject_CIS_Request_cmd, "" },
	{ "LE_Create_BIG_cmd", "[]", LE_Create_BIG_cmd, "" },
	{ "LE_Create_BIG_Test_cmd", "[]", LE_Create_BIG_Test_cmd, "" },
	{ "LE_Terminate_BIG_cmd", "[]", LE_Terminate_BIG_cmd, "" },
	{ "LE_BIG_Create_Sync_cmd", "[]", LE_BIG_Create_Sync_cmd, "" },
	{ "LE_BIG_Terminate_Sync_cmd", "[]", LE_BIG_Terminate_Sync_cmd, "" },
	{ "LE_Request_Peer_SCA_cmd", "[]", LE_Request_Peer_SCA_cmd, "" },
	{ "LE_Setup_ISO_Data_Path_cmd", "[]", LE_Setup_ISO_Data_Path_cmd, "" },
	{ "LE_Remove_ISO_Data_Path_cmd", "[]", LE_Remove_ISO_Data_Path_cmd, "" },
	{ "LE_ISO_Transmit_Test_cmd", "[]", LE_ISO_Transmit_Test_cmd, "" },
	{ "LE_ISO_Receive_Test_cmd", "[]", LE_ISO_Receive_Test_cmd, "" },
	{ "LE_ISO_Read_Test_Counters_cmd", "[]", LE_ISO_Read_Test_Counters_cmd, "" },
	{ "LE_ISO_Test_End_cmd", "[]", LE_ISO_Test_End_cmd, "" },
	{ "LE_Set_Host_Feature_cmd", "[]", LE_Set_Host_Feature_cmd, "" },
	{ "LE_Read_ISO_Link_Quality_cmd", "[]", LE_Read_ISO_Link_Quality_cmd, "" },
	{ "LE_Enhanced_Read_Transmit_Power_Level_cmd", "[]", LE_Enhanced_Read_Transmit_Power_Level_cmd, "" },
	{ "LE_Read_Remote_Transmit_Power_Level_cmd", "[]", LE_Read_Remote_Transmit_Power_Level_cmd, "" },
	{ "LE_Set_Path_Loss_Reporting_Parameters_cmd", "[]", LE_Set_Path_Loss_Reporting_Parameters_cmd, "" },
	{ "LE_Set_Path_Loss_Reporting_Enable_cmd", "[]", LE_Set_Path_Loss_Reporting_Enable_cmd, "" },
	{ "LE_Set_Transmit_Power_Reporting_Enable_cmd", "[]", LE_Set_Transmit_Power_Reporting_Enable_cmd, "" },
	{ "LE_Set_Data_Related_Address_Changes_cmd", "[]", LE_Set_Data_Related_Address_Changes_cmd, "" },
	{ "LE_Set_Default_Subrate_cmd", "[]", LE_Set_Default_Subrate_cmd, "" },
	{ "LE_Subrate_Request_cmd", "[]", LE_Subrate_Request_cmd, "" },
	{ "LE_Set_Periodic_Advertising_Subevent_Data_cmd", "[]", LE_Set_Periodic_Advertising_Subevent_Data_cmd, "" },
	{ "LE_Set_Periodic_Advertising_Response_Data_cmd", "[]", LE_Set_Periodic_Advertising_Response_Data_cmd, "" },
	{ "LE_Set_Periodic_Sync_Subevent_cmd", "[]", LE_Set_Periodic_Sync_Subevent_cmd, "" },
	{ } },
};
