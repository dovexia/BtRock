/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifndef __HCI_LIB_H
#define __HCI_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

struct hci_request {
	uint16_t ogf;
	uint16_t ocf;
	int      event;
	void     *cparam;
	int      clen;
	void     *rparam;
	int      rlen;
};

struct hci_version {
	uint16_t manufacturer;
	uint8_t  hci_ver;
	uint16_t hci_rev;
	uint8_t  lmp_ver;
	uint16_t lmp_subver;
};

int hci_open_dev(int dev_id);
int hci_close_dev(int dd);
int hci_reset_dev(int dd);
int hci_send_req(int dd, struct hci_request *req, int timeout);

int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, uint8_t plen, void *param);
int hci_create_connection(int dd, const bdaddr_t *bdaddr, uint16_t ptype, uint16_t clkoffset, uint8_t rswitch, uint16_t *handle, int to);
int hci_disconnect(int dd, uint16_t handle, uint8_t reason, int to);

int hci_inquiry(int dev_id, int len, int num_rsp, const uint8_t *lap, inquiry_info **ii, long flags);
int hci_devinfo(int dev_id, struct hci_dev_info *di);
int hci_devba(int dev_id, bdaddr_t *bdaddr);
int hci_devid(const char *str);

int hci_read_local_name(int dd, int len, char *name, int to);
int hci_write_local_name(int dd, const char *name, int to);
int hci_read_remote_name(int dd, const bdaddr_t *bdaddr, int len, char *name, int to);
int hci_read_remote_name_with_clock_offset(int dd, const bdaddr_t *bdaddr, uint8_t pscan_rep_mode, uint16_t clkoffset, int len, char *name, int to);
int hci_read_remote_name_cancel(int dd, const bdaddr_t *bdaddr, int to);
int hci_read_remote_version(int dd, uint16_t handle, struct hci_version *ver, int to);
int hci_read_remote_features(int dd, uint16_t handle, uint8_t *features, int to);
int hci_read_remote_ext_features(int dd, uint16_t handle, uint8_t page, uint8_t *max_page, uint8_t *features, int to);
int hci_read_clock_offset(int dd, uint16_t handle, uint16_t *clkoffset, int to);
int hci_read_local_version(int dd, struct hci_version *ver, int to);
int hci_read_local_commands(int dd, uint8_t *commands, int to);
int hci_read_local_features(int dd, uint8_t *features, int to);
int hci_read_local_ext_features(int dd, uint8_t page, uint8_t *max_page, uint8_t *features, int to);
int hci_read_bd_addr(int dd, bdaddr_t *bdaddr, int to);
int hci_read_class_of_dev(int dd, uint8_t *cls, int to);
int hci_write_class_of_dev(int dd, uint32_t cls, int to);
int hci_read_voice_setting(int dd, uint16_t *vs, int to);
int hci_write_voice_setting(int dd, uint16_t vs, int to);
int hci_read_current_iac_lap(int dd, uint8_t *num_iac, uint8_t *lap, int to);
int hci_write_current_iac_lap(int dd, uint8_t num_iac, uint8_t *lap, int to);
int hci_read_stored_link_key(int dd, bdaddr_t *bdaddr, uint8_t all, int to);
int hci_write_stored_link_key(int dd, bdaddr_t *bdaddr, uint8_t *key, int to);
int hci_delete_stored_link_key(int dd, bdaddr_t *bdaddr, uint8_t all, int to);
int hci_authenticate_link(int dd, uint16_t handle, int to);
int hci_encrypt_link(int dd, uint16_t handle, uint8_t encrypt, int to);
int hci_change_link_key(int dd, uint16_t handle, int to);
int hci_switch_role(int dd, bdaddr_t *bdaddr, uint8_t role, int to);
int hci_park_mode(int dd, uint16_t handle, uint16_t max_interval, uint16_t min_interval, int to);
int hci_exit_park_mode(int dd, uint16_t handle, int to);
int hci_read_inquiry_scan_type(int dd, uint8_t *type, int to);
int hci_write_inquiry_scan_type(int dd, uint8_t type, int to);
int hci_read_inquiry_mode(int dd, uint8_t *mode, int to);
int hci_write_inquiry_mode(int dd, uint8_t mode, int to);
int hci_read_afh_mode(int dd, uint8_t *mode, int to);
int hci_write_afh_mode(int dd, uint8_t mode, int to);
int hci_read_ext_inquiry_response(int dd, uint8_t *fec, uint8_t *data, int to);
int hci_write_ext_inquiry_response(int dd, uint8_t fec, uint8_t *data, int to);
int hci_read_simple_pairing_mode(int dd, uint8_t *mode, int to);
int hci_write_simple_pairing_mode(int dd, uint8_t mode, int to);
int hci_read_local_oob_data(int dd, uint8_t *hash, uint8_t *randomizer, int to);
int hci_read_inq_response_tx_power_level(int dd, int8_t *level, int to);
int hci_read_inquiry_transmit_power_level(int dd, int8_t *level, int to);
int hci_write_inquiry_transmit_power_level(int dd, int8_t level, int to);
int hci_read_transmit_power_level(int dd, uint16_t handle, uint8_t type, int8_t *level, int to);
int hci_read_link_policy(int dd, uint16_t handle, uint16_t *policy, int to);
int hci_write_link_policy(int dd, uint16_t handle, uint16_t policy, int to);
int hci_read_link_supervision_timeout(int dd, uint16_t handle, uint16_t *timeout, int to);
int hci_write_link_supervision_timeout(int dd, uint16_t handle, uint16_t timeout, int to);
int hci_set_afh_classification(int dd, uint8_t *map, int to);
int hci_read_link_quality(int dd, uint16_t handle, uint8_t *link_quality, int to);
int hci_read_rssi(int dd, uint16_t handle, int8_t *rssi, int to);
int hci_read_afh_map(int dd, uint16_t handle, uint8_t *mode, uint8_t *map, int to);
int hci_read_clock(int dd, uint16_t handle, uint8_t which, uint32_t *clock, uint16_t *accuracy, int to);

int hci_le_set_scan_enable(int dev_id, uint8_t enable, uint8_t filter_dup, int to);
int hci_le_set_scan_parameters(int dev_id, uint8_t type, uint16_t interval,
					uint16_t window, uint8_t own_type,
					uint8_t filter, int to);
int hci_le_set_advertise_enable(int dev_id, uint8_t enable, int to);
int hci_le_create_conn(int dd, uint16_t interval, uint16_t window,
		uint8_t initiator_filter, uint8_t peer_bdaddr_type,
		bdaddr_t peer_bdaddr, uint8_t own_bdaddr_type,
		uint16_t min_interval, uint16_t max_interval,
		uint16_t latency, uint16_t supervision_timeout,
		uint16_t min_ce_length, uint16_t max_ce_length,
		uint16_t *handle, int to);
int hci_le_conn_update(int dd, uint16_t handle, uint16_t min_interval,
			uint16_t max_interval, uint16_t latency,
			uint16_t supervision_timeout, int to);
int hci_le_add_white_list(int dd, const bdaddr_t *bdaddr, uint8_t type, int to);
int hci_le_rm_white_list(int dd, const bdaddr_t *bdaddr, uint8_t type, int to);
int hci_le_read_white_list_size(int dd, uint8_t *size, int to);
int hci_le_clear_white_list(int dd, int to);
int hci_le_add_resolving_list(int dd, const bdaddr_t *bdaddr, uint8_t type,
				uint8_t *peer_irk, uint8_t *local_irk, int to);
int hci_le_rm_resolving_list(int dd, const bdaddr_t *bdaddr, uint8_t type, int to);
int hci_le_clear_resolving_list(int dd, int to);
int hci_le_read_resolving_list_size(int dd, uint8_t *size, int to);
int hci_le_set_address_resolution_enable(int dev_id, uint8_t enable, int to);
int hci_le_read_remote_features(int dd, uint16_t handle, uint8_t *features, int to);

int hci_for_each_dev(int flag, int(*func)(int dd, int dev_id, long arg), long arg);
int hci_get_route(bdaddr_t *bdaddr);

char *hci_bustostr(int bus);
char *hci_typetostr(int type);
char *hci_dtypetostr(int type);
char *hci_dflagstostr(uint32_t flags);
char *hci_ptypetostr(unsigned int ptype);
int hci_strtoptype(char *str, unsigned int *val);
char *hci_scoptypetostr(unsigned int ptype);
int hci_strtoscoptype(char *str, unsigned int *val);
char *hci_lptostr(unsigned int ptype);
int hci_strtolp(char *str, unsigned int *val);
char *hci_lmtostr(unsigned int ptype);
int hci_strtolm(char *str, unsigned int *val);

char *hci_cmdtostr(unsigned int cmd);
char *hci_commandstostr(uint8_t *commands, char *pref, int width);

char *hci_vertostr(unsigned int ver);
int hci_strtover(char *str, unsigned int *ver);
char *lmp_vertostr(unsigned int ver);
int lmp_strtover(char *str, unsigned int *ver);
char *pal_vertostr(unsigned int ver);
int pal_strtover(char *str, unsigned int *ver);

char *lmp_featurestostr(uint8_t *features, char *pref, int width);

/* Start hci le command apis*/
void hci_set_device_fd(int dd);
void hci_clear_device_fd(int dd);
int hci_le_cmd_set_event_mask(uint8_t * mask);
int hci_le_cmd_read_buffer_size(le_read_buffer_size_rp* reply);
int hci_le_cmd_read_buffer_size_v2(le_read_buffer_size_v2_rp* reply);
int hci_le_cmd_read_local_supported_features(le_read_local_supported_features_rp * reply);
int hci_le_cmd_set_random_address(bdaddr_t * bdaddr);
int hci_le_cmd_set_advertising_parameters(uint16_t min_interval, uint16_t max_interval, uint8_t advtype, uint8_t own_bdaddr_type,
            uint8_t direct_bdaddr_type, bdaddr_t * direct_bdaddr, uint8_t chan_map, uint8_t filter);
int hci_le_cmd_read_advertising_physical_channel_tx_power(le_read_advertising_channel_tx_power_rp * reply);
int hci_le_cmd_set_advertising_data(uint8_t length, uint8_t	* data);
int hci_le_cmd_set_scan_response_data(uint8_t length, uint8_t * data);
int hci_le_cmd_set_advertising_enable(uint8_t enable);
int hci_le_cmd_set_scan_parameters(uint8_t type, uint16_t interval, uint16_t window, uint8_t own_bdaddr_type, uint8_t filter);
int hci_le_cmd_set_scan_enable(uint8_t enable, uint8_t filter_dup);
int hci_le_cmd_create_connection(uint16_t interval, uint16_t window, uint8_t initiator_filter, uint8_t peer_bdaddr_type, bdaddr_t * peer_bdaddr,
            uint8_t own_bdaddr_type, uint16_t min_interval, uint16_t max_interval, uint16_t latency, uint16_t supervision_timeout,
            uint16_t min_ce_length, uint16_t max_ce_length);
int hci_le_cmd_create_connection_cancel(void);
int hci_le_cmd_read_filter_accept_list_size(le_read_white_list_size_rp * reply);
int hci_le_cmd_clear_filter_accept_list(void);
int hci_le_cmd_add_device_to_filter_accept_list(uint8_t bdaddr_type, bdaddr_t * bdaddr);
int hci_le_cmd_remove_device_from_filter_accept_list(uint8_t bdaddr_type, bdaddr_t * bdaddr);
int hci_le_cmd_connection_update(uint16_t handle, uint16_t min_interval, uint16_t max_interval, uint16_t latency,
            uint16_t supervision_timeout, uint16_t min_ce_length, uint16_t max_ce_length);
int hci_le_cmd_set_host_channel_classification(uint8_t * map);
int hci_le_cmd_read_channel_map(uint16_t handle, le_read_channel_map_rp * reply);
int hci_le_cmd_read_remote_features(uint16_t handle);
int hci_le_cmd_encrypt(	uint8_t * key, uint8_t plaintext, le_encrypt_rp * reply);
int hci_le_cmd_rand(le_rand_rp * reply);
int hci_le_cmd_enable_encryption(uint16_t handl, uint64_t random, uint16_t diversifier, uint8_t * key);
int hci_le_cmd_long_term_key_request_reply(uint16_t handle, uint8_t * key, le_ltk_reply_rp * reply);
int hci_le_cmd_long_term_key_request_negative_reply(uint16_t handle, le_ltk_neg_reply_rp * reply);
int hci_le_cmd_read_supported_states(le_read_supported_states_rp * reply);
int hci_le_cmd_receiver_test_v1(uint8_t frequency);
int hci_le_cmd_receiver_test_v2(uint8_t frequency, uint8_t phy, uint8_t modulation_index);
int hci_le_cmd_receiver_test_v3(uint8_t frequency, uint8_t phy, uint8_t modulation_index, uint8_t expected_cte_length,
            uint8_t expected_cte_type, uint8_t slot_durations, uint8_t switching_pattern_length, uint8_t *antenna_ids);
int hci_le_cmd_transmitter_test_v1(uint8_t frequency, uint8_t length, uint8_t payload);
int hci_le_cmd_transmitter_test_v2(uint8_t frequency, uint8_t length, uint8_t payload, uint8_t phy);
int hci_le_cmd_transmitter_test_v3(uint8_t frequency, uint8_t length, uint8_t payload, uint8_t phy,uint8_t cte_length,
            uint8_t cte_type, uint8_t switching_pattern_length, uint8_t * antenna_ids);
int hci_le_cmd_transmitter_test_v4(uint8_t frequency, uint8_t length, uint8_t payload, uint8_t phy, uint8_t cte_length,
            uint8_t cte_type, uint8_t switching_pattern_length, uint8_t * antenna_ids, uint8_t tx_power_level);
int hci_le_cmd_test_end(le_test_end_rp * reply);
int hci_le_cmd_remote_connection_parameter_request_replycommand(uint16_t connection_handle, uint16_t interval_min, uint16_t interval_max,
            uint16_t max_latency, uint16_t timeout, uint16_t min_ce_length, uint16_t max_ce_length);
int hci_le_cmd_remote_connection_parameter_request_negativereply(uint16_t connection_handle, uint8_t reason,
            le_remote_connection_parameter_request_negative_reply_rp * reply);
int hci_le_cmd_set_data_length(uint16_t conn_handle, uint16_t tx_octets, uint16_t tx_time, le_set_data_length_rp * reply);
int hci_le_cmd_read_suggested_default_data_length(le_read_suggested_default_data_length_rp * reply);
int hci_le_cmd_write_suggested_default_data_length(uint16_t suggest_max_tx_octets, uint16_t suggest_max_tx_time);
int hci_le_cmd_read_local_p256_public_key(void);
int hci_le_cmd_generate_dhkey_v1(uint8_t * key_x_coordinate, uint8_t key_y_coordinate);
int hci_le_cmd_generate_dhkey_v2(uint8_t * key_x_coordinate, uint8_t key_y_coordinate, uint8_t key_type);
int hci_le_cmd_add_device_to_resolving_list(uint8_t bdaddr_type, bdaddr_t * bdaddr, uint8_t * peer_irk, uint8_t * local_irk);
int hci_le_cmd_remove_device_from_resolving_list(uint8_t bdaddr_type, bdaddr_t * bdaddr);
int hci_le_cmd_clear_resolving_list(void);
int hci_le_cmd_read_resolving_list_size(le_read_resolv_list_size_rp * reply);
int hci_le_cmd_read_peer_resolvable_address(uint8_t peer_identity_address_type, bdaddr_t * peer_identity_address,
            le_read_local_resolvable_address_cp * reply);
int hci_le_cmd_read_local_resolvable_address(uint8_t peer_identity_address_type, bdaddr_t * peer_identity_address,
            le_read_local_resolvable_address_rp * reply);
int hci_le_cmd_set_address_resolution_enable(uint8_t enable);
int hci_le_cmd_set_resolvable_private_address_timeout(uint8_t rpa_timeout);
int hci_le_cmd_read_maximum_data_length(le_read_maximum_data_length_rp * reply);
int hci_le_cmd_read_phy(uint16_t connection_handle, le_read_phy_rp * reply);
int hci_le_cmd_set_default_phy(uint8_t status, uint8_t tx_phy, uint8_t rx_phy);
int hci_le_cmd_set_phy(uint16_t connection_handle, uint8_t all_phys, uint8_t tx_phys, uint8_t rx_phys, uint16_t phy_options);
int hci_le_cmd_set_advertising_set_random_address(uint8_t advertising_handle, bdaddr_t * random_address);
int hci_le_cmd_set_extended_advertising_parameters_v1(uint8_t advertising_handle, uint16_t advertising_event_properties,
            uint24_t primary_advertising_interval_min, uint24_t primary_advertising_interval_max,
            uint8_t primary_advertising_channel_map, uint8_t own_address_type,
            uint8_t peer_address_type, bdaddr_t * peer_address,
            uint8_t advertising_filter_policy, uint8_t advertising_tx_power,
            uint8_t primary_advertising_phy, uint8_t secondary_advertising_max_skip,
            uint8_t secondary_advertising_phy, uint8_t advertising_sid,
            uint8_t scan_request_notification_enable, le_set_extended_advertising_parameters_rp * reply);
int hci_le_cmd_set_extended_advertising_parameters_v2(uint8_t advertising_handle, uint16_t advertising_event_properties,
            uint24_t primary_advertising_interval_min, uint24_t primary_advertising_interval_max,
            uint8_t primary_advertising_channel_map, uint8_t own_address_type,
            uint8_t peer_address_type, bdaddr_t * peer_address,
            uint8_t advertising_filter_policy, uint8_t advertising_tx_power,
            uint8_t primary_advertising_phy, uint8_t secondary_advertising_max_skip,
            uint8_t secondary_advertising_phy, uint8_t advertising_sid,
            uint8_t scan_request_notification_enable, uint8_t primary_advertising_phy_options,
            uint8_t econdary_advertising_phy_options, le_set_extended_advertising_parameters_rp * reply);
int hci_le_cmd_set_extended_advertising_data(uint8_t advertising_handle, uint8_t operation, uint8_t fragment_preference,
            uint8_t advertising_data_length, uint8_t * advertising_data);
int hci_le_cmd_set_extended_scan_response_data(uint8_t advertising_handle, uint8_t operation, uint8_t fragment_preference,
            uint8_t can_response_data_length, uint8_t * scan_response_data);
int hci_le_cmd_set_extended_advertising_enable(uint8_t enable, uint8_t num_sets,
            uint8_t * advertising_handle, uint16_t * duration, uint8_t * max_extended_advertising_events);
int hci_le_cmd_read_maximum_advertising_data_length(le_read_maximum_advertising_data_length_rp * reply);
int hci_le_cmd_read_number_of_supported_advertising_sets(le_read_number_of_supported_advertising_sets_rp * reply);
int hci_le_cmd_remove_advertising_set(uint8_t advertising_handle);
int hci_le_cmd_clear_advertising_sets(void);
int hci_le_cmd_set_periodic_advertising_parameters_v1(uint8_t advertising_handle, uint16_t periodic_advertising_interval_min,
            uint16_t periodic_advertising_interval_max, uint16_t periodic_advertising_properties);
int hci_le_cmd_set_periodic_advertising_parameters_v2(uint8_t advertising_handle, uint16_t periodic_advertising_interval_min,
            uint16_t periodic_advertising_interval_max, uint16_t periodic_advertising_properties,
            uint8_t num_subevents, uint8_t subevent_interval, uint8_t response_slot_delay,
            uint8_t response_slot_spacing, uint8_t num_response_slots);
int hci_le_cmd_set_periodic_advertising_data(uint8_t advertising_handle, uint8_t operation,
            uint8_t advertising_data_length, uint8_t advertising_data);
int hci_le_cmd_set_periodic_advertising_enable(uint8_t enable, uint8_t advertising_handle);
int hci_le_cmd_set_extended_scan_parameters(uint8_t own_address_type, uint8_t scanning_filter_policy, uint8_t scanning_phys,
            uint8_t * scan_type, uint16_t* scan_interval, uint16_t * scan_window);
int hci_le_cmd_set_extended_scan_enable(uint8_t enable, uint8_t filter_duplicates, uint16_t duration, uint16_t period);
int hci_le_cmd_extended_create_connection_v1(uint8_t initiator_filter_policy, uint8_t own_address_type, uint8_t peer_address_type,
            bdaddr_t * peer_address, uint8_t initiating_phys, uint16_t * scan_interval, uint16_t * scan_window,
            uint16_t * connection_interval_min, uint16_t * connection_interval_max, uint16_t * max_latency,
            uint16_t * supervision_timeout, uint16_t * min_ce_length, uint16_t * max_ce_length);
int hci_le_cmd_extended_create_connection_v2(uint8_t advertising_handle, uint8_t subevent,
            uint8_t initiator_filter_policy, uint8_t own_address_type, uint8_t peer_address_type,
            bdaddr_t * peer_address, uint8_t initiating_phys, uint16_t * scan_interval, uint16_t * scan_window,
            uint16_t * connection_interval_min, uint16_t * connection_interval_max, uint16_t * max_latency,
            uint16_t * supervision_timeout, uint16_t * min_ce_length, uint16_t * max_ce_length);
int hci_le_cmd_periodic_advertising_create_sync(uint8_t options, uint8_t advertising_sid, uint8_t advertiser_address_type,
            bdaddr_t * advertiser_address, uint16_t skip, uint16_t sync_timeout, uint8_t sync_cte_type);
int hci_le_cmd_periodic_advertising_create_sync_cancel(void);
int hci_le_cmd_periodic_advertising_terminate_sync(uint16_t sync_handle);
int hci_le_cmd_add_device_to_periodic_advertiser_list(uint8_t advertiser_address_type, bdaddr_t * advertiser_address, uint8_t advertising_sid);
int hci_le_cmd_remove_device_from_periodic_advertiser_list(uint8_t advertiser_address_type, bdaddr_t * advertiser_address, uint8_t advertising_sid);
int hci_le_cmd_clear_periodic_advertiser_list(void);
int hci_le_cmd_read_periodic_advertiser_list_size(le_read_periodic_advertiser_list_size_rp * reply);
int hci_le_cmd_read_transmit_power(le_read_transmit_power_rp * reply);
int hci_le_cmd_read_rf_path_compensation(le_read_rf_path_compensation_rp * reply);
int hci_le_cmd_write_rf_path_compensation(uint16_t rf_tx_path_compensation_value, uint16_t rf_rx_path_compensation_value);
int hci_le_cmd_set_privacy_mode(uint8_t peer_identity_address_type, bdaddr_t * peer_identity_address, uint8_t privacy_mode);
int hci_le_cmd_set_connectionless_cte_transmit_parameters(uint8_t advertising_handle, uint8_t cte_length, uint8_t cte_type, uint8_t cte_count,
            uint8_t switching_pattern_length, uint8_t * antenna_ids);
int hci_le_cmd_set_connectionless_cte_transmit_enable(uint8_t advertising_handle, uint8_t cte_enable);
int hci_le_cmd_set_connectionless_iq_sampling_enable(uint16_t ync_handle, uint8_t sampling_enable, uint8_t slot_durations,
            uint8_t max_sampled_ctes, uint8_t switching_pattern_length, uint8_t * antenna_ids,
            le_set_connectionless_iq_sampling_enable_rp * reply);
int hci_le_cmd_set_connection_cte_receive_parameters(uint16_t connection_handle, uint8_t sampling_enable, uint8_t slot_durations,
            uint8_t switching_pattern_length, uint8_t * antenna_ids, le_set_connection_cte_receive_parameters_rp reply);
int hci_le_cmd_set_connection_cte_transmit_parameters(uint16_t connection_handle, uint8_t cte_types, uint8_t switching_pattern_length,
            uint8_t antenna_ids, le_set_connection_cte_transmit_parameters_rp * reply);
int hci_le_cmd_connection_cte_request_enable(uint16_t connection_handle, uint8_t enable, uint16_t cte_request_interval,
            uint8_t requested_cte_length, uint8_t requested_cte_type, le_connection_cte_request_enable_rp * reply);
int hci_le_cmd_connection_cte_response_enable(uint16_t connection_handl, uint8_t enable, le_connection_cte_response_enable_rp * reply);
int hci_le_cmd_read_antenna_information(le_connection_cte_response_enable_rp * reply);
int hci_le_cmd_set_periodic_advertising_receive_enable(uint16_t sync_handle, uint8_t enable);
int hci_le_cmd_periodic_advertising_sync_transfer(uint16_t connection_handle, uint16_t service_data, uint16_t sync_handle,
            le_periodic_advertising_sync_transfer_rp * reply);
int hci_le_cmd_periodic_advertising_set_info_transfer(uint16_t connection_handle, uint16_t service_data, uint16_t sync_handle,
            le_periodic_advertising_set_info_transfer_rp * reply);
int hci_le_cmd_set_periodic_advertising_sync_transfer_parameters(uint16_t connection_handle, uint8_t mode, uint16_t skip,
            uint16_t sync_timeout, uint8_t cte_type, le_set_periodic_advertising_sync_transfer_parameters_rp * reply);
int hci_le_cmd_set_default_periodic_advertising_sync_transfer_parameters(uint8_t mode, uint16_t skip, uint16_t sync_timeout, uint8_t cte_type);
int hci_le_cmd_modify_sleep_clock_accuracy(uint8_t action);
int hci_le_cmd_read_iso_tx_sync(uint16_t connection_handle, le_read_iso_tx_sync_rp * reply);
int hci_le_cmd_set_cig_parameters(uint8_t cig_id, uint24_t sdu_interval_c_to_p,uint24_t sdu_interval_p_to_c, uint8_t worst_case_sca,
            uint8_t packing, uint8_t framing, uint16_t max_transport_latency_c_to_p, uint16_t max_transport_latency_p_to_c, uint8_t cis_count,
            uint8_t * cis_id, uint8_t * max_sdu_c_to_p, uint8_t * max_sdu_p_to_c, uint8_t *  phy_c_to_p,
            uint8_t * phy_p_to_c, uint8_t * rtn_c_to_p, uint8_t * rtn_p_to_c,
            le_set_cig_parameters_rp * reply);
int hci_le_cmd_set_cig_parameters_test(uint8_t cig_id, uint24_t sdu_interval_c_to_p, uint24_t sdu_interval_p_to_c, uint8_t ft_c_to_p,
            uint8_t ft_p_to_c, uint16_t iso_interval, uint8_t worst_case_sca, uint8_t packing, uint8_t framing, uint8_t cis_count,
            uint8_t * cis_id, uint8_t * nse, uint16_t *  max_sdu_c_to_p, uint16_t * max_sdu_p_to_c, uint16_t * max_pdu_c_to_p,
            uint16_t * max_pdu_p_to_c, uint8_t * phy_c_to_p, uint8_t * phy_p_to_c, uint8_t * bn_c_to_p, uint8_t * bn_p_to_c,
            le_set_cig_parameters_test_rp * reply);
int hci_le_cmd_create_cis(uint8_t cis_count, uint16_t * cis_connection_handle, uint16_t * acl_connection_handle);
int hci_le_cmd_remove_cig(uint8_t status, le_remove_cig_rp * reply);
int hci_le_cmd_accept_cis_request(uint16_t connection_handle);
int hci_le_cmd_reject_cis_request(uint16_t connection_handle, uint8_t reason, le_reject_cis_request_rp * reply);
int hci_le_cmd_create_big(uint8_t big_handle, uint8_t advertising_handle, uint8_t num_bis, uint24_t sdu_interval, uint16_t max_sdu,
            uint16_t max_transport_latency, uint8_t rtn, uint8_t phy, uint8_t packing, uint8_t framing, uint8_t encryption,
            uint8_t * broadcast_code);
int hci_le_cmd_create_big_test(uint8_t big_handl, uint8_t advertising_handle, uint8_t num_bis, uint24_t sdu_interval,
            uint16_t iso_interval, uint8_t nse, uint16_t max_sdu, uint16_t max_pdu, uint8_t phy, uint8_t packing,
            uint8_t framing, uint8_t bn, uint8_t irc, uint8_t pto, uint8_t encryption, uint8_t * broadcast_code);
int hci_le_cmd_terminate_big(uint8_t big_handle, uint8_t reason);
int hci_le_cmd_big_create_sync(uint8_t big_handle, uint16_t sync_handle, uint8_t encryption, uint8_t * broadcast_code,
            uint8_t mse, uint16_t big_sync_timeout, uint8_t num_bis, uint8_t * bis);
int hci_le_cmd_big_terminate_sync(uint8_t big_handle, le_big_terminate_sync_rp * reply);
int hci_le_cmd_request_peer_sca(uint16_t connection_handle);
int hci_le_cmd_setup_iso_data_path(uint16_t connection_handle, uint8_t data_path_direction, uint8_t data_path_id,
            uint8_t * codec_id, uint24_t controller_delay, uint8_t codec_configuration_length, uint8_t * codec_configuration,
            le_setup_iso_data_path_rp * reply);
int hci_le_cmd_remove_iso_data_path(uint8_t status, uint16_t connection_handle, le_remove_iso_data_path_rp * reply);
int hci_le_cmd_iso_transmit_test(uint16_t connection_handle, uint8_t payload_type, le_iso_transmit_test_rp * reply);
int hci_le_cmd_iso_receive_test(uint16_t connection_handle, uint8_t payload_type, le_iso_receive_test_rp * reply);
int hci_le_cmd_iso_read_test_counters(uint16_t connection_handle, le_iso_read_test_counters_cp * reply);
int hci_le_cmd_iso_test_end(uint16_t connection_handle, le_iso_test_end_rp * reply);
int hci_le_cmd_set_host_feature(uint8_t bit_number, uint8_t bit_value);
int hci_le_cmd_read_iso_link_quality(uint16_t connection_handle, le_read_iso_link_quality_rp * reply);
int hci_le_cmd_enhanced_read_transmit_power_level(uint16_t connection_handle, uint8_t phy, le_enhanced_read_transmit_power_level_rp * reply);
int hci_le_cmd_read_remote_transmit_power_level(uint16_t connection_handle, uint8_t phy);
int hci_le_cmd_set_path_loss_reporting_parameters(uint16_t connection_handle, uint8_t high_threshold, uint8_t high_hysteresis,
            uint8_t low_threshold, uint8_t low_hysteresis, uint16_t min_time_spent, le_set_path_loss_reporting_parameters_rp * reply);
int hci_le_cmd_set_path_loss_reporting_enable(uint8_t status, uint8_t enable, le_set_path_loss_reporting_enable_rp * reply);
int hci_le_cmd_set_transmit_power_reporting_enable(uint8_t status, uint8_t local_enable, uint8_t remote_enable,
            le_set_transmit_power_reporting_enable_rp * reply);
int hci_le_cmd_set_data_related_address_changes(uint8_t advertising_handle, uint8_t change_reasons);
int hci_le_cmd_set_default_subrate(uint16_t subrate_min, uint16_t subrate_max, uint16_t max_latency,
            uint16_t continuation_number, uint16_t supervision_timeout);
int hci_le_cmd_subrate_request(uint16_t connection_handle, uint16_t subrate_min, uint16_t subrate_max,
            uint16_t max_latency, uint16_t continuation_number, uint16_t supervision_timeout);
int hci_le_cmd_set_periodic_advertising_subevent_data(uint8_t advertising_handle, uint8_t num_subevents,
            uint8_t * subevent, uint8_t * response_slot_start, uint8_t response_slot_count,
            uint8_t ubevent_data_length, uint8_t * subevent_data,
            le_set_periodic_advertising_subevent_data_rp * reply);
int hci_le_cmd_set_periodic_advertising_response_data(uint16_t sync_handle, uint16_t request_event, uint8_t request_subevent,
            uint8_t response_subevent, uint8_t response_slot, uint8_t response_data_length, uint8_t * response_data,
            le_set_periodic_advertising_response_data_rp* reply);
int hci_le_cmd_set_periodic_sync_subevent(uint16_t sync_handle, uint8_t periodic_advertising_properties,
            uint8_t num_subevents, uint8_t * subevent, le_set_periodic_sync_subevent_rp* reply);

/* command api for user self-call*/
int hci_write_common_cmd(int dd, uint16_t ogf, uint16_t ocf, uint32_t expect_event,
                                uint8_t * cparam, uint32_t c_len,
								uint8_t * rparam, uint32_t r_len,
								int timeout);

/* End hci le command apis*/

static inline void hci_set_bit(int nr, void *addr)
{
	*((uint32_t *) addr + (nr >> 5)) |= (1 << (nr & 31));
}

static inline void hci_clear_bit(int nr, void *addr)
{
	*((uint32_t *) addr + (nr >> 5)) &= ~(1 << (nr & 31));
}

static inline int hci_test_bit(int nr, void *addr)
{
	return *((uint32_t *) addr + (nr >> 5)) & (1 << (nr & 31));
}

/* HCI filter tools */
static inline void hci_filter_clear(struct hci_filter *f)
{
	memset(f, 0, sizeof(*f));
}
static inline void hci_filter_set_ptype(int t, struct hci_filter *f)
{
	hci_set_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline void hci_filter_clear_ptype(int t, struct hci_filter *f)
{
	hci_clear_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline int hci_filter_test_ptype(int t, struct hci_filter *f)
{
	return hci_test_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline void hci_filter_all_ptypes(struct hci_filter *f)
{
	memset((void *) &f->type_mask, 0xff, sizeof(f->type_mask));
}
static inline void hci_filter_set_event(int e, struct hci_filter *f)
{
	hci_set_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_clear_event(int e, struct hci_filter *f)
{
	hci_clear_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline int hci_filter_test_event(int e, struct hci_filter *f)
{
	return hci_test_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_all_events(struct hci_filter *f)
{
	memset((void *) f->event_mask, 0xff, sizeof(f->event_mask));
}
static inline void hci_filter_set_opcode(int opcode, struct hci_filter *f)
{
	f->opcode = opcode;
}
static inline void hci_filter_clear_opcode(struct hci_filter *f)
{
	f->opcode = 0;
}
static inline int hci_filter_test_opcode(int opcode, struct hci_filter *f)
{
	return (f->opcode == opcode);
}

#ifdef __cplusplus
}
#endif

#endif /* __HCI_LIB_H */
