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

#ifndef __HCI_H
#define __HCI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>

#define HCI_MAX_DEV	16

#define HCI_MAX_AMP_SIZE	(1492 + 4)
#define HCI_MAX_ACL_SIZE	1024
#define HCI_MAX_SCO_SIZE	255
#define HCI_MAX_EVENT_SIZE	260
#define HCI_MAX_FRAME_SIZE	(HCI_MAX_AMP_SIZE + 4)

/* HCI dev events */
#define HCI_DEV_REG	1
#define HCI_DEV_UNREG	2
#define HCI_DEV_UP	3
#define HCI_DEV_DOWN	4
#define HCI_DEV_SUSPEND	5
#define HCI_DEV_RESUME	6

/* HCI bus types */
#define HCI_VIRTUAL	0
#define HCI_USB		1
#define HCI_PCCARD	2
#define HCI_UART	3
#define HCI_RS232	4
#define HCI_PCI		5
#define HCI_SDIO	6
#define HCI_SPI		7
#define HCI_I2C		8
#define HCI_SMD		9
#define HCI_VIRTIO	10

/* HCI controller types */
#define HCI_PRIMARY	0x00
#define HCI_AMP		0x01
#define HCI_BREDR	HCI_PRIMARY

/* HCI device flags */
enum {
	HCI_UP,
	HCI_INIT,
	HCI_RUNNING,

	HCI_PSCAN,
	HCI_ISCAN,
	HCI_AUTH,
	HCI_ENCRYPT,
	HCI_INQUIRY,

	HCI_RAW,
};

/* LE address type */
enum {
	LE_PUBLIC_ADDRESS = 0x00,
	LE_RANDOM_ADDRESS = 0x01
};

/* HCI ioctl defines */
#define HCIDEVUP	_IOW('H', 201, int)
#define HCIDEVDOWN	_IOW('H', 202, int)
#define HCIDEVRESET	_IOW('H', 203, int)
#define HCIDEVRESTAT	_IOW('H', 204, int)

#define HCIGETDEVLIST	_IOR('H', 210, int)
#define HCIGETDEVINFO	_IOR('H', 211, int)
#define HCIGETCONNLIST	_IOR('H', 212, int)
#define HCIGETCONNINFO	_IOR('H', 213, int)
#define HCIGETAUTHINFO	_IOR('H', 215, int)

#define HCISETRAW	_IOW('H', 220, int)
#define HCISETSCAN	_IOW('H', 221, int)
#define HCISETAUTH	_IOW('H', 222, int)
#define HCISETENCRYPT	_IOW('H', 223, int)
#define HCISETPTYPE	_IOW('H', 224, int)
#define HCISETLINKPOL	_IOW('H', 225, int)
#define HCISETLINKMODE	_IOW('H', 226, int)
#define HCISETACLMTU	_IOW('H', 227, int)
#define HCISETSCOMTU	_IOW('H', 228, int)

#define HCIBLOCKADDR	_IOW('H', 230, int)
#define HCIUNBLOCKADDR	_IOW('H', 231, int)

#define HCIINQUIRY	_IOR('H', 240, int)

#ifndef __NO_HCI_DEFS

/* HCI Packet types */
#define HCI_COMMAND_PKT		0x01
#define HCI_ACLDATA_PKT		0x02
#define HCI_SCODATA_PKT		0x03
#define HCI_EVENT_PKT		0x04
#define HCI_ISODATA_PKT		0x05
#define HCI_VENDOR_PKT		0xff

/* HCI Packet types */
#define HCI_2DH1	0x0002
#define HCI_3DH1	0x0004
#define HCI_DM1		0x0008
#define HCI_DH1		0x0010
#define HCI_2DH3	0x0100
#define HCI_3DH3	0x0200
#define HCI_DM3		0x0400
#define HCI_DH3		0x0800
#define HCI_2DH5	0x1000
#define HCI_3DH5	0x2000
#define HCI_DM5		0x4000
#define HCI_DH5		0x8000

#define HCI_HV1		0x0020
#define HCI_HV2		0x0040
#define HCI_HV3		0x0080

#define HCI_EV3		0x0008
#define HCI_EV4		0x0010
#define HCI_EV5		0x0020
#define HCI_2EV3	0x0040
#define HCI_3EV3	0x0080
#define HCI_2EV5	0x0100
#define HCI_3EV5	0x0200

#define SCO_PTYPE_MASK	(HCI_HV1 | HCI_HV2 | HCI_HV3)
#define ACL_PTYPE_MASK	(HCI_DM1 | HCI_DH1 | HCI_DM3 | HCI_DH3 | HCI_DM5 | HCI_DH5)

/* HCI Error codes */
#define HCI_UNKNOWN_COMMAND			0x01
#define HCI_NO_CONNECTION			0x02
#define HCI_HARDWARE_FAILURE			0x03
#define HCI_PAGE_TIMEOUT			0x04
#define HCI_AUTHENTICATION_FAILURE		0x05
#define HCI_PIN_OR_KEY_MISSING			0x06
#define HCI_MEMORY_FULL				0x07
#define HCI_CONNECTION_TIMEOUT			0x08
#define HCI_MAX_NUMBER_OF_CONNECTIONS		0x09
#define HCI_MAX_NUMBER_OF_SCO_CONNECTIONS	0x0a
#define HCI_ACL_CONNECTION_EXISTS		0x0b
#define HCI_COMMAND_DISALLOWED			0x0c
#define HCI_REJECTED_LIMITED_RESOURCES		0x0d
#define HCI_REJECTED_SECURITY			0x0e
#define HCI_REJECTED_PERSONAL			0x0f
#define HCI_HOST_TIMEOUT			0x10
#define HCI_UNSUPPORTED_FEATURE			0x11
#define HCI_INVALID_PARAMETERS			0x12
#define HCI_OE_USER_ENDED_CONNECTION		0x13
#define HCI_OE_LOW_RESOURCES			0x14
#define HCI_OE_POWER_OFF			0x15
#define HCI_CONNECTION_TERMINATED		0x16
#define HCI_REPEATED_ATTEMPTS			0x17
#define HCI_PAIRING_NOT_ALLOWED			0x18
#define HCI_UNKNOWN_LMP_PDU			0x19
#define HCI_UNSUPPORTED_REMOTE_FEATURE		0x1a
#define HCI_SCO_OFFSET_REJECTED			0x1b
#define HCI_SCO_INTERVAL_REJECTED		0x1c
#define HCI_AIR_MODE_REJECTED			0x1d
#define HCI_INVALID_LMP_PARAMETERS		0x1e
#define HCI_UNSPECIFIED_ERROR			0x1f
#define HCI_UNSUPPORTED_LMP_PARAMETER_VALUE	0x20
#define HCI_ROLE_CHANGE_NOT_ALLOWED		0x21
#define HCI_LMP_RESPONSE_TIMEOUT		0x22
#define HCI_LMP_ERROR_TRANSACTION_COLLISION	0x23
#define HCI_LMP_PDU_NOT_ALLOWED			0x24
#define HCI_ENCRYPTION_MODE_NOT_ACCEPTED	0x25
#define HCI_UNIT_LINK_KEY_USED			0x26
#define HCI_QOS_NOT_SUPPORTED			0x27
#define HCI_INSTANT_PASSED			0x28
#define HCI_PAIRING_NOT_SUPPORTED		0x29
#define HCI_TRANSACTION_COLLISION		0x2a
#define HCI_QOS_UNACCEPTABLE_PARAMETER		0x2c
#define HCI_QOS_REJECTED			0x2d
#define HCI_CLASSIFICATION_NOT_SUPPORTED	0x2e
#define HCI_INSUFFICIENT_SECURITY		0x2f
#define HCI_PARAMETER_OUT_OF_RANGE		0x30
#define HCI_ROLE_SWITCH_PENDING			0x32
#define HCI_SLOT_VIOLATION			0x34
#define HCI_ROLE_SWITCH_FAILED			0x35
#define HCI_EIR_TOO_LARGE			0x36
#define HCI_SIMPLE_PAIRING_NOT_SUPPORTED	0x37
#define HCI_HOST_BUSY_PAIRING			0x38

/* ACL flags */
#define ACL_START_NO_FLUSH	0x00
#define ACL_CONT		0x01
#define ACL_START		0x02
#define ACL_ACTIVE_BCAST	0x04
#define ACL_PICO_BCAST		0x08

/* Baseband links */
#define SCO_LINK	0x00
#define ACL_LINK	0x01
#define ESCO_LINK	0x02

/* LMP features */
#define LMP_3SLOT	0x01
#define LMP_5SLOT	0x02
#define LMP_ENCRYPT	0x04
#define LMP_SOFFSET	0x08
#define LMP_TACCURACY	0x10
#define LMP_RSWITCH	0x20
#define LMP_HOLD	0x40
#define LMP_SNIFF	0x80

#define LMP_PARK	0x01
#define LMP_RSSI	0x02
#define LMP_QUALITY	0x04
#define LMP_SCO		0x08
#define LMP_HV2		0x10
#define LMP_HV3		0x20
#define LMP_ULAW	0x40
#define LMP_ALAW	0x80

#define LMP_CVSD	0x01
#define LMP_PSCHEME	0x02
#define LMP_PCONTROL	0x04
#define LMP_TRSP_SCO	0x08
#define LMP_BCAST_ENC	0x80

#define LMP_EDR_ACL_2M	0x02
#define LMP_EDR_ACL_3M	0x04
#define LMP_ENH_ISCAN	0x08
#define LMP_ILACE_ISCAN	0x10
#define LMP_ILACE_PSCAN	0x20
#define LMP_RSSI_INQ	0x40
#define LMP_ESCO	0x80

#define LMP_EV4		0x01
#define LMP_EV5		0x02
#define LMP_AFH_CAP_SLV	0x08
#define LMP_AFH_CLS_SLV	0x10
#define LMP_NO_BREDR	0x20
#define LMP_LE		0x40
#define LMP_EDR_3SLOT	0x80

#define LMP_EDR_5SLOT	0x01
#define LMP_SNIFF_SUBR	0x02
#define LMP_PAUSE_ENC	0x04
#define LMP_AFH_CAP_MST	0x08
#define LMP_AFH_CLS_MST	0x10
#define LMP_EDR_ESCO_2M	0x20
#define LMP_EDR_ESCO_3M	0x40
#define LMP_EDR_3S_ESCO	0x80

#define LMP_EXT_INQ	0x01
#define LMP_LE_BREDR	0x02
#define LMP_SIMPLE_PAIR	0x08
#define LMP_ENCAPS_PDU	0x10
#define LMP_ERR_DAT_REP	0x20
#define LMP_NFLUSH_PKTS	0x40

#define LMP_LSTO	0x01
#define LMP_INQ_TX_PWR	0x02
#define LMP_EPC		0x04
#define LMP_EXT_FEAT	0x80

/* Extended LMP features */
#define LMP_HOST_SSP		0x01
#define LMP_HOST_LE		0x02
#define LMP_HOST_LE_BREDR	0x04

/* Link policies */
#define HCI_LP_RSWITCH	0x0001
#define HCI_LP_HOLD	0x0002
#define HCI_LP_SNIFF	0x0004
#define HCI_LP_PARK	0x0008

/* Link mode */
#define HCI_LM_ACCEPT	0x8000
#define HCI_LM_MASTER	0x0001
#define HCI_LM_AUTH	0x0002
#define HCI_LM_ENCRYPT	0x0004
#define HCI_LM_TRUSTED	0x0008
#define HCI_LM_RELIABLE	0x0010
#define HCI_LM_SECURE	0x0020

/* Link Key types */
#define HCI_LK_COMBINATION		0x00
#define HCI_LK_LOCAL_UNIT		0x01
#define HCI_LK_REMOTE_UNIT		0x02
#define HCI_LK_DEBUG_COMBINATION	0x03
#define HCI_LK_UNAUTH_COMBINATION	0x04
#define HCI_LK_AUTH_COMBINATION		0x05
#define HCI_LK_CHANGED_COMBINATION	0x06
#define HCI_LK_INVALID			0xFF

/* -----  HCI Commands ----- */

/* Link Control */
#define OGF_LINK_CTL		0x01

#define OCF_INQUIRY			0x0001
typedef struct {
	uint8_t		lap[3];
	uint8_t		length;		/* 1.28s units */
	uint8_t		num_rsp;
} __attribute__ ((packed)) inquiry_cp;
#define INQUIRY_CP_SIZE 5

typedef struct {
	uint8_t		status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) status_bdaddr_rp;
#define STATUS_BDADDR_RP_SIZE 7

#define OCF_INQUIRY_CANCEL		0x0002

#define OCF_PERIODIC_INQUIRY		0x0003
typedef struct {
	uint16_t	max_period;	/* 1.28s units */
	uint16_t	min_period;	/* 1.28s units */
	uint8_t		lap[3];
	uint8_t		length;		/* 1.28s units */
	uint8_t		num_rsp;
} __attribute__ ((packed)) periodic_inquiry_cp;
#define PERIODIC_INQUIRY_CP_SIZE 9

#define OCF_EXIT_PERIODIC_INQUIRY	0x0004

#define OCF_CREATE_CONN			0x0005
typedef struct {
	bdaddr_t	bdaddr;
	uint16_t	pkt_type;
	uint8_t		pscan_rep_mode;
	uint8_t		pscan_mode;
	uint16_t	clock_offset;
	uint8_t		role_switch;
} __attribute__ ((packed)) create_conn_cp;
#define CREATE_CONN_CP_SIZE 13

#define OCF_DISCONNECT			0x0006
typedef struct {
	uint16_t	handle;
	uint8_t		reason;
} __attribute__ ((packed)) disconnect_cp;
#define DISCONNECT_CP_SIZE 3

#define OCF_ADD_SCO			0x0007
typedef struct {
	uint16_t	handle;
	uint16_t	pkt_type;
} __attribute__ ((packed)) add_sco_cp;
#define ADD_SCO_CP_SIZE 4

#define OCF_CREATE_CONN_CANCEL		0x0008
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) create_conn_cancel_cp;
#define CREATE_CONN_CANCEL_CP_SIZE 6

#define OCF_ACCEPT_CONN_REQ		0x0009
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		role;
} __attribute__ ((packed)) accept_conn_req_cp;
#define ACCEPT_CONN_REQ_CP_SIZE	7

#define OCF_REJECT_CONN_REQ		0x000A
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		reason;
} __attribute__ ((packed)) reject_conn_req_cp;
#define REJECT_CONN_REQ_CP_SIZE	7

#define OCF_LINK_KEY_REPLY		0x000B
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		link_key[16];
} __attribute__ ((packed)) link_key_reply_cp;
#define LINK_KEY_REPLY_CP_SIZE 22

#define OCF_LINK_KEY_NEG_REPLY		0x000C

#define OCF_PIN_CODE_REPLY		0x000D
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pin_len;
	uint8_t		pin_code[16];
} __attribute__ ((packed)) pin_code_reply_cp;
#define PIN_CODE_REPLY_CP_SIZE 23

#define OCF_PIN_CODE_NEG_REPLY		0x000E

#define OCF_SET_CONN_PTYPE		0x000F
typedef struct {
	uint16_t	 handle;
	uint16_t	 pkt_type;
} __attribute__ ((packed)) set_conn_ptype_cp;
#define SET_CONN_PTYPE_CP_SIZE 4

#define OCF_AUTH_REQUESTED		0x0011
typedef struct {
	uint16_t	 handle;
} __attribute__ ((packed)) auth_requested_cp;
#define AUTH_REQUESTED_CP_SIZE 2

#define OCF_SET_CONN_ENCRYPT		0x0013
typedef struct {
	uint16_t	handle;
	uint8_t		encrypt;
} __attribute__ ((packed)) set_conn_encrypt_cp;
#define SET_CONN_ENCRYPT_CP_SIZE 3

#define OCF_CHANGE_CONN_LINK_KEY	0x0015
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) change_conn_link_key_cp;
#define CHANGE_CONN_LINK_KEY_CP_SIZE 2

#define OCF_MASTER_LINK_KEY		0x0017
typedef struct {
	uint8_t		key_flag;
} __attribute__ ((packed)) master_link_key_cp;
#define MASTER_LINK_KEY_CP_SIZE 1

#define OCF_REMOTE_NAME_REQ		0x0019
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pscan_rep_mode;
	uint8_t		pscan_mode;
	uint16_t	clock_offset;
} __attribute__ ((packed)) remote_name_req_cp;
#define REMOTE_NAME_REQ_CP_SIZE 10

#define OCF_REMOTE_NAME_REQ_CANCEL	0x001A
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) remote_name_req_cancel_cp;
#define REMOTE_NAME_REQ_CANCEL_CP_SIZE 6

#define OCF_READ_REMOTE_FEATURES	0x001B
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) read_remote_features_cp;
#define READ_REMOTE_FEATURES_CP_SIZE 2

#define OCF_READ_REMOTE_EXT_FEATURES	0x001C
typedef struct {
	uint16_t	handle;
	uint8_t		page_num;
} __attribute__ ((packed)) read_remote_ext_features_cp;
#define READ_REMOTE_EXT_FEATURES_CP_SIZE 3

#define OCF_READ_REMOTE_VERSION		0x001D
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) read_remote_version_cp;
#define READ_REMOTE_VERSION_CP_SIZE 2

#define OCF_READ_CLOCK_OFFSET		0x001F
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) read_clock_offset_cp;
#define READ_CLOCK_OFFSET_CP_SIZE 2

#define OCF_READ_LMP_HANDLE		0x0020

#define OCF_SETUP_SYNC_CONN		0x0028
typedef struct {
	uint16_t	handle;
	uint32_t	tx_bandwith;
	uint32_t	rx_bandwith;
	uint16_t	max_latency;
	uint16_t	voice_setting;
	uint8_t		retrans_effort;
	uint16_t	pkt_type;
} __attribute__ ((packed)) setup_sync_conn_cp;
#define SETUP_SYNC_CONN_CP_SIZE 17

#define OCF_ACCEPT_SYNC_CONN_REQ	0x0029
typedef struct {
	bdaddr_t	bdaddr;
	uint32_t	tx_bandwith;
	uint32_t	rx_bandwith;
	uint16_t	max_latency;
	uint16_t	voice_setting;
	uint8_t		retrans_effort;
	uint16_t	pkt_type;
} __attribute__ ((packed)) accept_sync_conn_req_cp;
#define ACCEPT_SYNC_CONN_REQ_CP_SIZE 21

#define OCF_REJECT_SYNC_CONN_REQ	0x002A
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		reason;
} __attribute__ ((packed)) reject_sync_conn_req_cp;
#define REJECT_SYNC_CONN_REQ_CP_SIZE 7

#define OCF_IO_CAPABILITY_REPLY		0x002B
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		capability;
	uint8_t		oob_data;
	uint8_t		authentication;
} __attribute__ ((packed)) io_capability_reply_cp;
#define IO_CAPABILITY_REPLY_CP_SIZE 9

#define OCF_USER_CONFIRM_REPLY		0x002C
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) user_confirm_reply_cp;
#define USER_CONFIRM_REPLY_CP_SIZE 6

#define OCF_USER_CONFIRM_NEG_REPLY	0x002D

#define OCF_USER_PASSKEY_REPLY		0x002E
typedef struct {
	bdaddr_t	bdaddr;
	uint32_t	passkey;
} __attribute__ ((packed)) user_passkey_reply_cp;
#define USER_PASSKEY_REPLY_CP_SIZE 10

#define OCF_USER_PASSKEY_NEG_REPLY	0x002F

#define OCF_REMOTE_OOB_DATA_REPLY	0x0030
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		hash[16];
	uint8_t		randomizer[16];
} __attribute__ ((packed)) remote_oob_data_reply_cp;
#define REMOTE_OOB_DATA_REPLY_CP_SIZE 38

#define OCF_REMOTE_OOB_DATA_NEG_REPLY	0x0033

#define OCF_IO_CAPABILITY_NEG_REPLY	0x0034
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		reason;
} __attribute__ ((packed)) io_capability_neg_reply_cp;
#define IO_CAPABILITY_NEG_REPLY_CP_SIZE 7

#define OCF_CREATE_PHYSICAL_LINK		0x0035
typedef struct {
	uint8_t		handle;
	uint8_t		key_length;
	uint8_t		key_type;
	uint8_t		key[32];
} __attribute__ ((packed)) create_physical_link_cp;
#define CREATE_PHYSICAL_LINK_CP_SIZE 35

#define OCF_ACCEPT_PHYSICAL_LINK		0x0036
typedef struct {
	uint8_t		handle;
	uint8_t		key_length;
	uint8_t		key_type;
	uint8_t		key[32];
} __attribute__ ((packed)) accept_physical_link_cp;
#define ACCEPT_PHYSICAL_LINK_CP_SIZE 35

#define OCF_DISCONNECT_PHYSICAL_LINK		0x0037
typedef struct {
	uint8_t		handle;
	uint8_t		reason;
} __attribute__ ((packed)) disconnect_physical_link_cp;
#define DISCONNECT_PHYSICAL_LINK_CP_SIZE 2

#define OCF_CREATE_LOGICAL_LINK		0x0038
typedef struct {
	uint8_t		handle;
	uint8_t		tx_flow[16];
	uint8_t		rx_flow[16];
} __attribute__ ((packed)) create_logical_link_cp;
#define CREATE_LOGICAL_LINK_CP_SIZE 33

#define OCF_ACCEPT_LOGICAL_LINK		0x0039

#define OCF_DISCONNECT_LOGICAL_LINK		0x003A
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) disconnect_logical_link_cp;
#define DISCONNECT_LOGICAL_LINK_CP_SIZE 2

#define OCF_LOGICAL_LINK_CANCEL		0x003B
typedef struct {
	uint8_t		handle;
	uint8_t		tx_flow_id;
} __attribute__ ((packed)) cancel_logical_link_cp;
#define LOGICAL_LINK_CANCEL_CP_SIZE 2
typedef struct {
	uint8_t		status;
	uint8_t		handle;
	uint8_t		tx_flow_id;
} __attribute__ ((packed)) cancel_logical_link_rp;
#define LOGICAL_LINK_CANCEL_RP_SIZE 3

#define OCF_FLOW_SPEC_MODIFY		0x003C

/* Link Policy */
#define OGF_LINK_POLICY		0x02

#define OCF_HOLD_MODE			0x0001
typedef struct {
	uint16_t	handle;
	uint16_t	max_interval;
	uint16_t	min_interval;
} __attribute__ ((packed)) hold_mode_cp;
#define HOLD_MODE_CP_SIZE 6

#define OCF_SNIFF_MODE			0x0003
typedef struct {
	uint16_t	handle;
	uint16_t	max_interval;
	uint16_t	min_interval;
	uint16_t	attempt;
	uint16_t	timeout;
} __attribute__ ((packed)) sniff_mode_cp;
#define SNIFF_MODE_CP_SIZE 10

#define OCF_EXIT_SNIFF_MODE		0x0004
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) exit_sniff_mode_cp;
#define EXIT_SNIFF_MODE_CP_SIZE 2

#define OCF_PARK_MODE			0x0005
typedef struct {
	uint16_t	handle;
	uint16_t	max_interval;
	uint16_t	min_interval;
} __attribute__ ((packed)) park_mode_cp;
#define PARK_MODE_CP_SIZE 6

#define OCF_EXIT_PARK_MODE		0x0006
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) exit_park_mode_cp;
#define EXIT_PARK_MODE_CP_SIZE 2

#define OCF_QOS_SETUP			0x0007
typedef struct {
	uint8_t		service_type;		/* 1 = best effort */
	uint32_t	token_rate;		/* Byte per seconds */
	uint32_t	peak_bandwidth;		/* Byte per seconds */
	uint32_t	latency;		/* Microseconds */
	uint32_t	delay_variation;	/* Microseconds */
} __attribute__ ((packed)) hci_qos;
#define HCI_QOS_CP_SIZE 17
typedef struct {
	uint16_t	handle;
	uint8_t		flags;			/* Reserved */
	hci_qos		qos;
} __attribute__ ((packed)) qos_setup_cp;
#define QOS_SETUP_CP_SIZE (3 + HCI_QOS_CP_SIZE)

#define OCF_ROLE_DISCOVERY		0x0009
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) role_discovery_cp;
#define ROLE_DISCOVERY_CP_SIZE 2
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		role;
} __attribute__ ((packed)) role_discovery_rp;
#define ROLE_DISCOVERY_RP_SIZE 4

#define OCF_SWITCH_ROLE			0x000B
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		role;
} __attribute__ ((packed)) switch_role_cp;
#define SWITCH_ROLE_CP_SIZE 7

#define OCF_READ_LINK_POLICY		0x000C
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) read_link_policy_cp;
#define READ_LINK_POLICY_CP_SIZE 2
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint16_t	policy;
} __attribute__ ((packed)) read_link_policy_rp;
#define READ_LINK_POLICY_RP_SIZE 5

#define OCF_WRITE_LINK_POLICY		0x000D
typedef struct {
	uint16_t	handle;
	uint16_t	policy;
} __attribute__ ((packed)) write_link_policy_cp;
#define WRITE_LINK_POLICY_CP_SIZE 4
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) write_link_policy_rp;
#define WRITE_LINK_POLICY_RP_SIZE 3

#define OCF_READ_DEFAULT_LINK_POLICY	0x000E

#define OCF_WRITE_DEFAULT_LINK_POLICY	0x000F

#define OCF_FLOW_SPECIFICATION		0x0010

#define OCF_SNIFF_SUBRATING		0x0011
typedef struct {
	uint16_t	handle;
	uint16_t	max_latency;
	uint16_t	min_remote_timeout;
	uint16_t	min_local_timeout;
} __attribute__ ((packed)) sniff_subrating_cp;
#define SNIFF_SUBRATING_CP_SIZE 8

/* Host Controller and Baseband */
#define OGF_HOST_CTL		0x03

#define OCF_SET_EVENT_MASK		0x0001
typedef struct {
	uint8_t		mask[8];
} __attribute__ ((packed)) set_event_mask_cp;
#define SET_EVENT_MASK_CP_SIZE 8

#define OCF_RESET			0x0003

#define OCF_SET_EVENT_FLT		0x0005
typedef struct {
	uint8_t		flt_type;
	uint8_t		cond_type;
	uint8_t		condition[];
} __attribute__ ((packed)) set_event_flt_cp;
#define SET_EVENT_FLT_CP_SIZE 2

/* Filter types */
#define FLT_CLEAR_ALL			0x00
#define FLT_INQ_RESULT			0x01
#define FLT_CONN_SETUP			0x02
/* INQ_RESULT Condition types */
#define INQ_RESULT_RETURN_ALL		0x00
#define INQ_RESULT_RETURN_CLASS		0x01
#define INQ_RESULT_RETURN_BDADDR	0x02
/* CONN_SETUP Condition types */
#define CONN_SETUP_ALLOW_ALL		0x00
#define CONN_SETUP_ALLOW_CLASS		0x01
#define CONN_SETUP_ALLOW_BDADDR		0x02
/* CONN_SETUP Conditions */
#define CONN_SETUP_AUTO_OFF		0x01
#define CONN_SETUP_AUTO_ON		0x02

#define OCF_FLUSH			0x0008

#define OCF_READ_PIN_TYPE		0x0009
typedef struct {
	uint8_t		status;
	uint8_t		pin_type;
} __attribute__ ((packed)) read_pin_type_rp;
#define READ_PIN_TYPE_RP_SIZE 2

#define OCF_WRITE_PIN_TYPE		0x000A
typedef struct {
	uint8_t		pin_type;
} __attribute__ ((packed)) write_pin_type_cp;
#define WRITE_PIN_TYPE_CP_SIZE 1

#define OCF_CREATE_NEW_UNIT_KEY		0x000B

#define OCF_READ_STORED_LINK_KEY	0x000D
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		read_all;
} __attribute__ ((packed)) read_stored_link_key_cp;
#define READ_STORED_LINK_KEY_CP_SIZE 7
typedef struct {
	uint8_t		status;
	uint16_t	max_keys;
	uint16_t	num_keys;
} __attribute__ ((packed)) read_stored_link_key_rp;
#define READ_STORED_LINK_KEY_RP_SIZE 5

#define OCF_WRITE_STORED_LINK_KEY	0x0011
typedef struct {
	uint8_t		num_keys;
	/* variable length part */
} __attribute__ ((packed)) write_stored_link_key_cp;
#define WRITE_STORED_LINK_KEY_CP_SIZE 1
typedef struct {
	uint8_t		status;
	uint8_t		num_keys;
} __attribute__ ((packed)) write_stored_link_key_rp;
#define READ_WRITE_LINK_KEY_RP_SIZE 2

#define OCF_DELETE_STORED_LINK_KEY	0x0012
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		delete_all;
} __attribute__ ((packed)) delete_stored_link_key_cp;
#define DELETE_STORED_LINK_KEY_CP_SIZE 7
typedef struct {
	uint8_t		status;
	uint16_t	num_keys;
} __attribute__ ((packed)) delete_stored_link_key_rp;
#define DELETE_STORED_LINK_KEY_RP_SIZE 3

#define HCI_MAX_NAME_LENGTH		248

#define OCF_CHANGE_LOCAL_NAME		0x0013
typedef struct {
	uint8_t		name[HCI_MAX_NAME_LENGTH];
} __attribute__ ((packed)) change_local_name_cp;
#define CHANGE_LOCAL_NAME_CP_SIZE 248

#define OCF_READ_LOCAL_NAME		0x0014
typedef struct {
	uint8_t		status;
	uint8_t		name[HCI_MAX_NAME_LENGTH];
} __attribute__ ((packed)) read_local_name_rp;
#define READ_LOCAL_NAME_RP_SIZE 249

#define OCF_READ_CONN_ACCEPT_TIMEOUT	0x0015
typedef struct {
	uint8_t		status;
	uint16_t	timeout;
} __attribute__ ((packed)) read_conn_accept_timeout_rp;
#define READ_CONN_ACCEPT_TIMEOUT_RP_SIZE 3

#define OCF_WRITE_CONN_ACCEPT_TIMEOUT	0x0016
typedef struct {
	uint16_t	timeout;
} __attribute__ ((packed)) write_conn_accept_timeout_cp;
#define WRITE_CONN_ACCEPT_TIMEOUT_CP_SIZE 2

#define OCF_READ_PAGE_TIMEOUT		0x0017
typedef struct {
	uint8_t		status;
	uint16_t	timeout;
} __attribute__ ((packed)) read_page_timeout_rp;
#define READ_PAGE_TIMEOUT_RP_SIZE 3

#define OCF_WRITE_PAGE_TIMEOUT		0x0018
typedef struct {
	uint16_t	timeout;
} __attribute__ ((packed)) write_page_timeout_cp;
#define WRITE_PAGE_TIMEOUT_CP_SIZE 2

#define OCF_READ_SCAN_ENABLE		0x0019
typedef struct {
	uint8_t		status;
	uint8_t		enable;
} __attribute__ ((packed)) read_scan_enable_rp;
#define READ_SCAN_ENABLE_RP_SIZE 2

#define OCF_WRITE_SCAN_ENABLE		0x001A
	#define SCAN_DISABLED		0x00
	#define SCAN_INQUIRY		0x01
	#define SCAN_PAGE		0x02

#define OCF_READ_PAGE_ACTIVITY		0x001B
typedef struct {
	uint8_t		status;
	uint16_t	interval;
	uint16_t	window;
} __attribute__ ((packed)) read_page_activity_rp;
#define READ_PAGE_ACTIVITY_RP_SIZE 5

#define OCF_WRITE_PAGE_ACTIVITY		0x001C
typedef struct {
	uint16_t	interval;
	uint16_t	window;
} __attribute__ ((packed)) write_page_activity_cp;
#define WRITE_PAGE_ACTIVITY_CP_SIZE 4

#define OCF_READ_INQ_ACTIVITY		0x001D
typedef struct {
	uint8_t		status;
	uint16_t	interval;
	uint16_t	window;
} __attribute__ ((packed)) read_inq_activity_rp;
#define READ_INQ_ACTIVITY_RP_SIZE 5

#define OCF_WRITE_INQ_ACTIVITY		0x001E
typedef struct {
	uint16_t	interval;
	uint16_t	window;
} __attribute__ ((packed)) write_inq_activity_cp;
#define WRITE_INQ_ACTIVITY_CP_SIZE 4

#define OCF_READ_AUTH_ENABLE		0x001F

#define OCF_WRITE_AUTH_ENABLE		0x0020
	#define AUTH_DISABLED		0x00
	#define AUTH_ENABLED		0x01

#define OCF_READ_ENCRYPT_MODE		0x0021

#define OCF_WRITE_ENCRYPT_MODE		0x0022
	#define ENCRYPT_DISABLED	0x00
	#define ENCRYPT_P2P		0x01
	#define ENCRYPT_BOTH		0x02

#define OCF_READ_CLASS_OF_DEV		0x0023
typedef struct {
	uint8_t		status;
	uint8_t		dev_class[3];
} __attribute__ ((packed)) read_class_of_dev_rp;
#define READ_CLASS_OF_DEV_RP_SIZE 4

#define OCF_WRITE_CLASS_OF_DEV		0x0024
typedef struct {
	uint8_t		dev_class[3];
} __attribute__ ((packed)) write_class_of_dev_cp;
#define WRITE_CLASS_OF_DEV_CP_SIZE 3

#define OCF_READ_VOICE_SETTING		0x0025
typedef struct {
	uint8_t		status;
	uint16_t	voice_setting;
} __attribute__ ((packed)) read_voice_setting_rp;
#define READ_VOICE_SETTING_RP_SIZE 3

#define OCF_WRITE_VOICE_SETTING		0x0026
typedef struct {
	uint16_t	voice_setting;
} __attribute__ ((packed)) write_voice_setting_cp;
#define WRITE_VOICE_SETTING_CP_SIZE 2

#define OCF_READ_AUTOMATIC_FLUSH_TIMEOUT	0x0027

#define OCF_WRITE_AUTOMATIC_FLUSH_TIMEOUT	0x0028

#define OCF_READ_NUM_BROADCAST_RETRANS	0x0029

#define OCF_WRITE_NUM_BROADCAST_RETRANS	0x002A

#define OCF_READ_HOLD_MODE_ACTIVITY	0x002B

#define OCF_WRITE_HOLD_MODE_ACTIVITY	0x002C

#define OCF_READ_TRANSMIT_POWER_LEVEL	0x002D
typedef struct {
	uint16_t	handle;
	uint8_t		type;
} __attribute__ ((packed)) read_transmit_power_level_cp;
#define READ_TRANSMIT_POWER_LEVEL_CP_SIZE 3
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	int8_t		level;
} __attribute__ ((packed)) read_transmit_power_level_rp;
#define READ_TRANSMIT_POWER_LEVEL_RP_SIZE 4

#define OCF_READ_SYNC_FLOW_ENABLE	0x002E

#define OCF_WRITE_SYNC_FLOW_ENABLE	0x002F

#define OCF_SET_CONTROLLER_TO_HOST_FC	0x0031

#define OCF_HOST_BUFFER_SIZE		0x0033
typedef struct {
	uint16_t	acl_mtu;
	uint8_t		sco_mtu;
	uint16_t	acl_max_pkt;
	uint16_t	sco_max_pkt;
} __attribute__ ((packed)) host_buffer_size_cp;
#define HOST_BUFFER_SIZE_CP_SIZE 7

#define OCF_HOST_NUM_COMP_PKTS		0x0035
typedef struct {
	uint8_t		num_hndl;
	/* variable length part */
} __attribute__ ((packed)) host_num_comp_pkts_cp;
#define HOST_NUM_COMP_PKTS_CP_SIZE 1

#define OCF_READ_LINK_SUPERVISION_TIMEOUT	0x0036
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint16_t	timeout;
} __attribute__ ((packed)) read_link_supervision_timeout_rp;
#define READ_LINK_SUPERVISION_TIMEOUT_RP_SIZE 5

#define OCF_WRITE_LINK_SUPERVISION_TIMEOUT	0x0037
typedef struct {
	uint16_t	handle;
	uint16_t	timeout;
} __attribute__ ((packed)) write_link_supervision_timeout_cp;
#define WRITE_LINK_SUPERVISION_TIMEOUT_CP_SIZE 4
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) write_link_supervision_timeout_rp;
#define WRITE_LINK_SUPERVISION_TIMEOUT_RP_SIZE 3

#define OCF_READ_NUM_SUPPORTED_IAC	0x0038

#define MAX_IAC_LAP 0x40
#define OCF_READ_CURRENT_IAC_LAP	0x0039
typedef struct {
	uint8_t		status;
	uint8_t		num_current_iac;
	uint8_t		lap[MAX_IAC_LAP][3];
} __attribute__ ((packed)) read_current_iac_lap_rp;
#define READ_CURRENT_IAC_LAP_RP_SIZE 2+3*MAX_IAC_LAP

#define OCF_WRITE_CURRENT_IAC_LAP	0x003A
typedef struct {
	uint8_t		num_current_iac;
	uint8_t		lap[MAX_IAC_LAP][3];
} __attribute__ ((packed)) write_current_iac_lap_cp;
#define WRITE_CURRENT_IAC_LAP_CP_SIZE 1+3*MAX_IAC_LAP

#define OCF_READ_PAGE_SCAN_PERIOD_MODE	0x003B

#define OCF_WRITE_PAGE_SCAN_PERIOD_MODE	0x003C

#define OCF_READ_PAGE_SCAN_MODE		0x003D

#define OCF_WRITE_PAGE_SCAN_MODE	0x003E

#define OCF_SET_AFH_CLASSIFICATION	0x003F
typedef struct {
	uint8_t		map[10];
} __attribute__ ((packed)) set_afh_classification_cp;
#define SET_AFH_CLASSIFICATION_CP_SIZE 10
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) set_afh_classification_rp;
#define SET_AFH_CLASSIFICATION_RP_SIZE 1

#define OCF_READ_INQUIRY_SCAN_TYPE	0x0042
typedef struct {
	uint8_t		status;
	uint8_t		type;
} __attribute__ ((packed)) read_inquiry_scan_type_rp;
#define READ_INQUIRY_SCAN_TYPE_RP_SIZE 2

#define OCF_WRITE_INQUIRY_SCAN_TYPE	0x0043
typedef struct {
	uint8_t		type;
} __attribute__ ((packed)) write_inquiry_scan_type_cp;
#define WRITE_INQUIRY_SCAN_TYPE_CP_SIZE 1
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_inquiry_scan_type_rp;
#define WRITE_INQUIRY_SCAN_TYPE_RP_SIZE 1

#define OCF_READ_INQUIRY_MODE		0x0044
typedef struct {
	uint8_t		status;
	uint8_t		mode;
} __attribute__ ((packed)) read_inquiry_mode_rp;
#define READ_INQUIRY_MODE_RP_SIZE 2

#define OCF_WRITE_INQUIRY_MODE		0x0045
typedef struct {
	uint8_t		mode;
} __attribute__ ((packed)) write_inquiry_mode_cp;
#define WRITE_INQUIRY_MODE_CP_SIZE 1
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_inquiry_mode_rp;
#define WRITE_INQUIRY_MODE_RP_SIZE 1

#define OCF_READ_PAGE_SCAN_TYPE		0x0046

#define OCF_WRITE_PAGE_SCAN_TYPE	0x0047
	#define PAGE_SCAN_TYPE_STANDARD		0x00
	#define PAGE_SCAN_TYPE_INTERLACED	0x01

#define OCF_READ_AFH_MODE		0x0048
typedef struct {
	uint8_t		status;
	uint8_t		mode;
} __attribute__ ((packed)) read_afh_mode_rp;
#define READ_AFH_MODE_RP_SIZE 2

#define OCF_WRITE_AFH_MODE		0x0049
typedef struct {
	uint8_t		mode;
} __attribute__ ((packed)) write_afh_mode_cp;
#define WRITE_AFH_MODE_CP_SIZE 1
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_afh_mode_rp;
#define WRITE_AFH_MODE_RP_SIZE 1

#define HCI_MAX_EIR_LENGTH		240

#define OCF_READ_EXT_INQUIRY_RESPONSE	0x0051
typedef struct {
	uint8_t		status;
	uint8_t		fec;
	uint8_t		data[HCI_MAX_EIR_LENGTH];
} __attribute__ ((packed)) read_ext_inquiry_response_rp;
#define READ_EXT_INQUIRY_RESPONSE_RP_SIZE 242

#define OCF_WRITE_EXT_INQUIRY_RESPONSE	0x0052
typedef struct {
	uint8_t		fec;
	uint8_t		data[HCI_MAX_EIR_LENGTH];
} __attribute__ ((packed)) write_ext_inquiry_response_cp;
#define WRITE_EXT_INQUIRY_RESPONSE_CP_SIZE 241
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_ext_inquiry_response_rp;
#define WRITE_EXT_INQUIRY_RESPONSE_RP_SIZE 1

#define OCF_REFRESH_ENCRYPTION_KEY	0x0053
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) refresh_encryption_key_cp;
#define REFRESH_ENCRYPTION_KEY_CP_SIZE 2
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) refresh_encryption_key_rp;
#define REFRESH_ENCRYPTION_KEY_RP_SIZE 1

#define OCF_READ_SIMPLE_PAIRING_MODE	0x0055
typedef struct {
	uint8_t		status;
	uint8_t		mode;
} __attribute__ ((packed)) read_simple_pairing_mode_rp;
#define READ_SIMPLE_PAIRING_MODE_RP_SIZE 2

#define OCF_WRITE_SIMPLE_PAIRING_MODE	0x0056
typedef struct {
	uint8_t		mode;
} __attribute__ ((packed)) write_simple_pairing_mode_cp;
#define WRITE_SIMPLE_PAIRING_MODE_CP_SIZE 1
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_simple_pairing_mode_rp;
#define WRITE_SIMPLE_PAIRING_MODE_RP_SIZE 1

#define OCF_READ_LOCAL_OOB_DATA		0x0057
typedef struct {
	uint8_t		status;
	uint8_t		hash[16];
	uint8_t		randomizer[16];
} __attribute__ ((packed)) read_local_oob_data_rp;
#define READ_LOCAL_OOB_DATA_RP_SIZE 33

#define OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL	0x0058
typedef struct {
	uint8_t		status;
	int8_t		level;
} __attribute__ ((packed)) read_inq_response_tx_power_level_rp;
#define READ_INQ_RESPONSE_TX_POWER_LEVEL_RP_SIZE 2

#define OCF_READ_INQUIRY_TRANSMIT_POWER_LEVEL	0x0058
typedef struct {
	uint8_t		status;
	int8_t		level;
} __attribute__ ((packed)) read_inquiry_transmit_power_level_rp;
#define READ_INQUIRY_TRANSMIT_POWER_LEVEL_RP_SIZE 2

#define OCF_WRITE_INQUIRY_TRANSMIT_POWER_LEVEL	0x0059
typedef struct {
	int8_t		level;
} __attribute__ ((packed)) write_inquiry_transmit_power_level_cp;
#define WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_CP_SIZE 1
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_inquiry_transmit_power_level_rp;
#define WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_RP_SIZE 1

#define OCF_READ_DEFAULT_ERROR_DATA_REPORTING	0x005A
typedef struct {
	uint8_t		status;
	uint8_t		reporting;
} __attribute__ ((packed)) read_default_error_data_reporting_rp;
#define READ_DEFAULT_ERROR_DATA_REPORTING_RP_SIZE 2

#define OCF_WRITE_DEFAULT_ERROR_DATA_REPORTING	0x005B
typedef struct {
	uint8_t		reporting;
} __attribute__ ((packed)) write_default_error_data_reporting_cp;
#define WRITE_DEFAULT_ERROR_DATA_REPORTING_CP_SIZE 1
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_default_error_data_reporting_rp;
#define WRITE_DEFAULT_ERROR_DATA_REPORTING_RP_SIZE 1

#define OCF_ENHANCED_FLUSH		0x005F
typedef struct {
	uint16_t	handle;
	uint8_t		type;
} __attribute__ ((packed)) enhanced_flush_cp;
#define ENHANCED_FLUSH_CP_SIZE 3

#define OCF_SEND_KEYPRESS_NOTIFY	0x0060
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		type;
} __attribute__ ((packed)) send_keypress_notify_cp;
#define SEND_KEYPRESS_NOTIFY_CP_SIZE 7
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) send_keypress_notify_rp;
#define SEND_KEYPRESS_NOTIFY_RP_SIZE 1

#define OCF_READ_LOGICAL_LINK_ACCEPT_TIMEOUT	 0x0061
typedef struct {
	uint8_t		status;
	uint16_t	timeout;
} __attribute__ ((packed)) read_log_link_accept_timeout_rp;
#define READ_LOGICAL_LINK_ACCEPT_TIMEOUT_RP_SIZE 3

#define OCF_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT	0x0062
typedef struct {
	uint16_t	timeout;
} __attribute__ ((packed)) write_log_link_accept_timeout_cp;
#define WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT_CP_SIZE 2

#define OCF_SET_EVENT_MASK_PAGE_2	0x0063

#define OCF_READ_LOCATION_DATA		0x0064

#define OCF_WRITE_LOCATION_DATA	0x0065

#define OCF_READ_FLOW_CONTROL_MODE	0x0066

#define OCF_WRITE_FLOW_CONTROL_MODE	0x0067

#define OCF_READ_ENHANCED_TRANSMIT_POWER_LEVEL	0x0068
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	int8_t		level_gfsk;
	int8_t		level_dqpsk;
	int8_t		level_8dpsk;
} __attribute__ ((packed)) read_enhanced_transmit_power_level_rp;
#define READ_ENHANCED_TRANSMIT_POWER_LEVEL_RP_SIZE 6

#define OCF_READ_BEST_EFFORT_FLUSH_TIMEOUT	0x0069
typedef struct {
	uint8_t		status;
	uint32_t	timeout;
} __attribute__ ((packed)) read_best_effort_flush_timeout_rp;
#define READ_BEST_EFFORT_FLUSH_TIMEOUT_RP_SIZE 5

#define OCF_WRITE_BEST_EFFORT_FLUSH_TIMEOUT	0x006A
typedef struct {
	uint16_t	handle;
	uint32_t	timeout;
} __attribute__ ((packed)) write_best_effort_flush_timeout_cp;
#define WRITE_BEST_EFFORT_FLUSH_TIMEOUT_CP_SIZE 6
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_best_effort_flush_timeout_rp;
#define WRITE_BEST_EFFORT_FLUSH_TIMEOUT_RP_SIZE 1

#define OCF_READ_LE_HOST_SUPPORTED	0x006C
typedef struct {
	uint8_t		status;
	uint8_t		le;
	uint8_t		simul;
} __attribute__ ((packed)) read_le_host_supported_rp;
#define READ_LE_HOST_SUPPORTED_RP_SIZE 3

#define OCF_WRITE_LE_HOST_SUPPORTED	0x006D
typedef struct {
	uint8_t		le;
	uint8_t		simul;
} __attribute__ ((packed)) write_le_host_supported_cp;
#define WRITE_LE_HOST_SUPPORTED_CP_SIZE 2

/* Informational Parameters */
#define OGF_INFO_PARAM		0x04

#define OCF_READ_LOCAL_VERSION		0x0001
typedef struct {
	uint8_t		status;
	uint8_t		hci_ver;
	uint16_t	hci_rev;
	uint8_t		lmp_ver;
	uint16_t	manufacturer;
	uint16_t	lmp_subver;
} __attribute__ ((packed)) read_local_version_rp;
#define READ_LOCAL_VERSION_RP_SIZE 9

#define OCF_READ_LOCAL_COMMANDS		0x0002
typedef struct {
	uint8_t		status;
	uint8_t		commands[64];
} __attribute__ ((packed)) read_local_commands_rp;
#define READ_LOCAL_COMMANDS_RP_SIZE 65

#define OCF_READ_LOCAL_FEATURES		0x0003
typedef struct {
	uint8_t		status;
	uint8_t		features[8];
} __attribute__ ((packed)) read_local_features_rp;
#define READ_LOCAL_FEATURES_RP_SIZE 9

#define OCF_READ_LOCAL_EXT_FEATURES	0x0004
typedef struct {
	uint8_t		page_num;
} __attribute__ ((packed)) read_local_ext_features_cp;
#define READ_LOCAL_EXT_FEATURES_CP_SIZE 1
typedef struct {
	uint8_t		status;
	uint8_t		page_num;
	uint8_t		max_page_num;
	uint8_t		features[8];
} __attribute__ ((packed)) read_local_ext_features_rp;
#define READ_LOCAL_EXT_FEATURES_RP_SIZE 11

#define OCF_READ_BUFFER_SIZE		0x0005
typedef struct {
	uint8_t		status;
	uint16_t	acl_mtu;
	uint8_t		sco_mtu;
	uint16_t	acl_max_pkt;
	uint16_t	sco_max_pkt;
} __attribute__ ((packed)) read_buffer_size_rp;
#define READ_BUFFER_SIZE_RP_SIZE 8

#define OCF_READ_COUNTRY_CODE		0x0007

#define OCF_READ_BD_ADDR		0x0009
typedef struct {
	uint8_t		status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) read_bd_addr_rp;
#define READ_BD_ADDR_RP_SIZE 7

#define OCF_READ_DATA_BLOCK_SIZE	0x000A
typedef struct {
	uint8_t		status;
	uint16_t	max_acl_len;
	uint16_t	data_block_len;
	uint16_t	num_blocks;
} __attribute__ ((packed)) read_data_block_size_rp;

/* Status params */
#define OGF_STATUS_PARAM	0x05

#define OCF_READ_FAILED_CONTACT_COUNTER		0x0001
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		counter;
} __attribute__ ((packed)) read_failed_contact_counter_rp;
#define READ_FAILED_CONTACT_COUNTER_RP_SIZE 4

#define OCF_RESET_FAILED_CONTACT_COUNTER	0x0002
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) reset_failed_contact_counter_rp;
#define RESET_FAILED_CONTACT_COUNTER_RP_SIZE 3

#define OCF_READ_LINK_QUALITY		0x0003
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		link_quality;
} __attribute__ ((packed)) read_link_quality_rp;
#define READ_LINK_QUALITY_RP_SIZE 4

#define OCF_READ_RSSI			0x0005
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	int8_t		rssi;
} __attribute__ ((packed)) read_rssi_rp;
#define READ_RSSI_RP_SIZE 4

#define OCF_READ_AFH_MAP		0x0006
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		mode;
	uint8_t		map[10];
} __attribute__ ((packed)) read_afh_map_rp;
#define READ_AFH_MAP_RP_SIZE 14

#define OCF_READ_CLOCK			0x0007
typedef struct {
	uint16_t	handle;
	uint8_t		which_clock;
} __attribute__ ((packed)) read_clock_cp;
#define READ_CLOCK_CP_SIZE 3
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint32_t	clock;
	uint16_t	accuracy;
} __attribute__ ((packed)) read_clock_rp;
#define READ_CLOCK_RP_SIZE 9

#define OCF_READ_LOCAL_AMP_INFO	0x0009
typedef struct {
	uint8_t		status;
	uint8_t		amp_status;
	uint32_t	total_bandwidth;
	uint32_t	max_guaranteed_bandwidth;
	uint32_t	min_latency;
	uint32_t	max_pdu_size;
	uint8_t		controller_type;
	uint16_t	pal_caps;
	uint16_t	max_amp_assoc_length;
	uint32_t	max_flush_timeout;
	uint32_t	best_effort_flush_timeout;
} __attribute__ ((packed)) read_local_amp_info_rp;
#define READ_LOCAL_AMP_INFO_RP_SIZE 31

#define OCF_READ_LOCAL_AMP_ASSOC	0x000A
typedef struct {
	uint8_t		handle;
	uint16_t	length_so_far;
	uint16_t	assoc_length;
} __attribute__ ((packed)) read_local_amp_assoc_cp;
#define READ_LOCAL_AMP_ASSOC_CP_SIZE 5
typedef struct {
	uint8_t		status;
	uint8_t		handle;
	uint16_t	length;
	uint8_t		fragment[HCI_MAX_NAME_LENGTH];
} __attribute__ ((packed)) read_local_amp_assoc_rp;
#define READ_LOCAL_AMP_ASSOC_RP_SIZE 252

#define OCF_WRITE_REMOTE_AMP_ASSOC	0x000B
typedef struct {
	uint8_t		handle;
	uint16_t	length_so_far;
	uint16_t	remaining_length;
	uint8_t		fragment[HCI_MAX_NAME_LENGTH];
} __attribute__ ((packed)) write_remote_amp_assoc_cp;
#define WRITE_REMOTE_AMP_ASSOC_CP_SIZE 253
typedef struct {
	uint8_t		status;
	uint8_t		handle;
} __attribute__ ((packed)) write_remote_amp_assoc_rp;
#define WRITE_REMOTE_AMP_ASSOC_RP_SIZE 2

/* Testing commands */
#define OGF_TESTING_CMD		0x3e

#define OCF_READ_LOOPBACK_MODE			0x0001

#define OCF_WRITE_LOOPBACK_MODE			0x0002

#define OCF_ENABLE_DEVICE_UNDER_TEST_MODE	0x0003

#define OCF_WRITE_SIMPLE_PAIRING_DEBUG_MODE	0x0004
typedef struct {
	uint8_t		mode;
} __attribute__ ((packed)) write_simple_pairing_debug_mode_cp;
#define WRITE_SIMPLE_PAIRING_DEBUG_MODE_CP_SIZE 1
typedef struct {
	uint8_t		status;
} __attribute__ ((packed)) write_simple_pairing_debug_mode_rp;
#define WRITE_SIMPLE_PAIRING_DEBUG_MODE_RP_SIZE 1

/* LE commands */
#define OGF_LE_CTL		0x08

#define OCF_LE_SET_EVENT_MASK			0x0001
typedef struct {
	uint8_t		mask[8];
} __attribute__ ((packed)) le_set_event_mask_cp;
#define LE_SET_EVENT_MASK_CP_SIZE 8

#define OCF_LE_READ_BUFFER_SIZE			0x0002
typedef struct {
	uint8_t		status;
	uint16_t	pkt_len;
	uint8_t		max_pkt;
} __attribute__ ((packed)) le_read_buffer_size_rp;
#define LE_READ_BUFFER_SIZE_RP_SIZE 4
#define OCF_LE_READ_BUFFER_SIZE_V1              0x0002
#define OCF_LE_READ_BUFFER_SIZE_V2              0x0060
typedef struct {
    uint8_t	    status;
    uint16_t    le_acl_data_packet_length;
    uint8_t     total_num_le_acl_data_packets;
    uint16_t    iso_data_packet_length;
    uint8_t     total_num_iso_data_packets;
} __attribute__ ((packed)) le_read_buffer_size_v2_rp;
#define LE_READ_BUFFER_SIZE_V2_RP_SIZE 7

#define OCF_LE_READ_LOCAL_SUPPORTED_FEATURES	0x0003
typedef struct {
	uint8_t		status;
	uint8_t		features[8];
} __attribute__ ((packed)) le_read_local_supported_features_rp;
#define LE_READ_LOCAL_SUPPORTED_FEATURES_RP_SIZE 9

#define OCF_LE_SET_RANDOM_ADDRESS		0x0005
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) le_set_random_address_cp;
#define LE_SET_RANDOM_ADDRESS_CP_SIZE 6

#define OCF_LE_SET_ADVERTISING_PARAMETERS	0x0006
typedef struct {
	uint16_t	min_interval;
	uint16_t	max_interval;
	uint8_t		advtype;
	uint8_t		own_bdaddr_type;
	uint8_t		direct_bdaddr_type;
	bdaddr_t	direct_bdaddr;
	uint8_t		chan_map;
	uint8_t		filter;
} __attribute__ ((packed)) le_set_advertising_parameters_cp;
#define LE_SET_ADVERTISING_PARAMETERS_CP_SIZE 15

#define OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER	0x0007
typedef struct {
	uint8_t		status;
	int8_t		level;
} __attribute__ ((packed)) le_read_advertising_channel_tx_power_rp;
#define LE_READ_ADVERTISING_CHANNEL_TX_POWER_RP_SIZE 2

#define OCF_LE_SET_ADVERTISING_DATA		0x0008
typedef struct {
	uint8_t		length;
	uint8_t		data[31];
} __attribute__ ((packed)) le_set_advertising_data_cp;
#define LE_SET_ADVERTISING_DATA_CP_SIZE 32

#define OCF_LE_SET_SCAN_RESPONSE_DATA		0x0009
typedef struct {
	uint8_t		length;
	uint8_t		data[31];
} __attribute__ ((packed)) le_set_scan_response_data_cp;
#define LE_SET_SCAN_RESPONSE_DATA_CP_SIZE 32

#define OCF_LE_SET_ADVERTISE_ENABLE		0x000A
typedef struct {
	uint8_t		enable;
} __attribute__ ((packed)) le_set_advertise_enable_cp;
#define LE_SET_ADVERTISE_ENABLE_CP_SIZE 1

#define OCF_LE_SET_SCAN_PARAMETERS		0x000B
typedef struct {
	uint8_t		type;
	uint16_t	interval;
	uint16_t	window;
	uint8_t		own_bdaddr_type;
	uint8_t		filter;
} __attribute__ ((packed)) le_set_scan_parameters_cp;
#define LE_SET_SCAN_PARAMETERS_CP_SIZE 7

#define OCF_LE_SET_SCAN_ENABLE			0x000C
typedef struct {
	uint8_t		enable;
	uint8_t		filter_dup;
} __attribute__ ((packed)) le_set_scan_enable_cp;
#define LE_SET_SCAN_ENABLE_CP_SIZE 2

#define OCF_LE_CREATE_CONN			0x000D
typedef struct {
	uint16_t	interval;
	uint16_t	window;
	uint8_t		initiator_filter;
	uint8_t		peer_bdaddr_type;
	bdaddr_t	peer_bdaddr;
	uint8_t		own_bdaddr_type;
	uint16_t	min_interval;
	uint16_t	max_interval;
	uint16_t	latency;
	uint16_t	supervision_timeout;
	uint16_t	min_ce_length;
	uint16_t	max_ce_length;
} __attribute__ ((packed)) le_create_connection_cp;
#define LE_CREATE_CONN_CP_SIZE 25

#define OCF_LE_CREATE_CONN_CANCEL		0x000E

#define OCF_LE_READ_WHITE_LIST_SIZE		0x000F
#define OCF_LE_READ_FILTER_ACCEPT_SIZE      0x000F
typedef struct {
	uint8_t		status;
	uint8_t		size;
} __attribute__ ((packed)) le_read_white_list_size_rp;
#define LE_READ_WHITE_LIST_SIZE_RP_SIZE 2


#define OCF_LE_CLEAR_WHITE_LIST			0x0010
#define OCF_LE_CLEAR_FILTER_ACCEPT_LIST			0x0010

#define OCF_LE_ADD_DEVICE_TO_WHITE_LIST		0x0011
#define OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST		0x0011
typedef struct {
	uint8_t		bdaddr_type;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) le_add_device_to_white_list_cp;
#define LE_ADD_DEVICE_TO_WHITE_LIST_CP_SIZE 7
#define LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST_CP_SIZE 7

#define OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST	0x0012
typedef struct {
	uint8_t		bdaddr_type;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) le_remove_device_from_white_list_cp;
#define LE_REMOVE_DEVICE_FROM_WHITE_LIST_CP_SIZE 7

#define OCF_LE_CONN_UPDATE			0x0013
typedef struct {
	uint16_t	handle;
	uint16_t	min_interval;
	uint16_t	max_interval;
	uint16_t	latency;
	uint16_t	supervision_timeout;
	uint16_t	min_ce_length;
	uint16_t	max_ce_length;
} __attribute__ ((packed)) le_connection_update_cp;
#define LE_CONN_UPDATE_CP_SIZE 14

#define OCF_LE_SET_HOST_CHANNEL_CLASSIFICATION	0x0014
typedef struct {
	uint8_t		map[5];
} __attribute__ ((packed)) le_set_host_channel_classification_cp;
#define LE_SET_HOST_CHANNEL_CLASSIFICATION_CP_SIZE 5

#define OCF_LE_READ_CHANNEL_MAP			0x0015
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) le_read_channel_map_cp;
#define LE_READ_CHANNEL_MAP_CP_SIZE 2
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		map[5];
} __attribute__ ((packed)) le_read_channel_map_rp;
#define LE_READ_CHANNEL_MAP_RP_SIZE 8

#define OCF_LE_READ_REMOTE_USED_FEATURES	0x0016
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) le_read_remote_used_features_cp;
#define LE_READ_REMOTE_USED_FEATURES_CP_SIZE 2

#define OCF_LE_ENCRYPT				0x0017
typedef struct {
	uint8_t		key[16];
	uint8_t		plaintext[16];
} __attribute__ ((packed)) le_encrypt_cp;
#define LE_ENCRYPT_CP_SIZE 32
typedef struct {
	uint8_t		status;
	uint8_t		data[16];
} __attribute__ ((packed)) le_encrypt_rp;
#define LE_ENCRYPT_RP_SIZE 17

#define OCF_LE_RAND				0x0018
typedef struct {
	uint8_t		status;
	uint64_t	random;
} __attribute__ ((packed)) le_rand_rp;
#define LE_RAND_RP_SIZE 9

#define OCF_LE_START_ENCRYPTION			0x0019
typedef struct {
	uint16_t	handle;
	uint64_t	random;
	uint16_t	diversifier;
	uint8_t		key[16];
} __attribute__ ((packed)) le_start_encryption_cp;
#define LE_START_ENCRYPTION_CP_SIZE 28

#define OCF_LE_LTK_REPLY			0x001A
typedef struct {
	uint16_t	handle;
	uint8_t		key[16];
} __attribute__ ((packed)) le_ltk_reply_cp;
#define LE_LTK_REPLY_CP_SIZE 18
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) le_ltk_reply_rp;
#define LE_LTK_REPLY_RP_SIZE 3

#define OCF_LE_LTK_NEG_REPLY			0x001B
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) le_ltk_neg_reply_cp;
#define LE_LTK_NEG_REPLY_CP_SIZE 2
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) le_ltk_neg_reply_rp;
#define LE_LTK_NEG_REPLY_RP_SIZE 3

#define OCF_LE_READ_SUPPORTED_STATES		0x001C
typedef struct {
	uint8_t		status;
	uint64_t	states;
} __attribute__ ((packed)) le_read_supported_states_rp;
#define LE_READ_SUPPORTED_STATES_RP_SIZE 9

#define OCF_LE_RECEIVER_TEST			0x001D
#define OCF_LE_Receiver_Test_v1 0x001D
typedef struct {
	uint8_t		frequency;
} __attribute__ ((packed)) le_receiver_test_cp;
#define LE_RECEIVER_TEST_CP_SIZE 1
#define OCF_LE_Receiver_Test_v2 0x0033
typedef struct {
	uint8_t		frequency;
    uint8_t     phy;
    uint8_t     modulation_index;
} __attribute__ ((packed)) le_receiver_test_v2_cp;
#define OCF_LE_Receiver_Test_v3 0x004F
typedef struct {
	uint8_t		frequency;
    uint8_t     phy;
    uint8_t     modulation_index;
    uint8_t     expected_cte_length;
    uint8_t     expected_cte_type;
    uint8_t     slot_durations;
    uint8_t     switching_pattern_length;
    uint8_t     antenna_ids[0];  // expected_cte_length *1
} __attribute__ ((packed)) le_receiver_test_v3_cp;

#define OCF_LE_TRANSMITTER_TEST			0x001E
#define OCF_LE_TRANSMITTER_TEST_V1 0x001E
typedef struct {
	uint8_t		frequency;
	uint8_t		length;
	uint8_t		payload;
} __attribute__ ((packed)) le_transmitter_test_cp;
#define LE_TRANSMITTER_TEST_CP_SIZE 3

#define OCF_LE_TRANSMITTER_TEST_V2 0x0034
typedef struct {
	uint8_t		frequency;
	uint8_t		length;
	uint8_t		payload;
    uint8_t		phy;
} __attribute__ ((packed)) le_transmitter_test_v2_cp;
#define LE_TRANSMITTER_TEST_CP_SIZE_V2 3
#define OCF_LE_TRANSMITTER_TEST_V3 0x0050
typedef struct {
	uint8_t		frequency;
	uint8_t		length;
	uint8_t		payload;
    uint8_t		phy;
    uint8_t     cte_length;
    uint8_t     cte_type;
    uint8_t     switching_pattern_length;
    uint8_t     antenna_ids[0]; //switching_pattern_length × 1 octet
} __attribute__ ((packed)) le_transmitter_test_v3_cp;
#define LE_TRANSMITTER_TEST_CP_SIZE_V3
#define OCF_LE_TRANSMITTER_TEST_V4 0x007B
typedef struct {
	uint8_t		frequency;
	uint8_t		length;
	uint8_t		payload;
    uint8_t		phy;
    uint8_t     cte_length;
    uint8_t     cte_type;
    uint8_t     switching_pattern_length;
    uint8_t     antenna_ids[0]; //switching_pattern_length × 1 octet
    uint8_t     tx_power_level;
} __attribute__ ((packed)) le_transmitter_test_v4_cp;
#define LE_TRANSMITTER_TEST_CP_SIZE_V4


#define OCF_LE_TEST_END				0x001F
typedef struct {
	uint8_t		status;
	uint16_t	num_pkts;
} __attribute__ ((packed)) le_test_end_rp;
#define LE_TEST_END_RP_SIZE 3

#define OCF_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY 0x0020
typedef struct {
    uint16_t    connection_handle;
    uint16_t    interval_min;
    uint16_t    interval_max;
    uint16_t    max_latency;
    uint16_t    timeout;
    uint16_t    min_ce_length;
    uint16_t    max_ce_length;
} __attribute__ ((packed)) le_remote_connection_parameter_request_reply_cp;
#define LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY_CP_SIZE 14

#define OCF_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY 0x0021
typedef struct {
    uint16_t    connection_handle;
    uint8_t     reason;
} __attribute__ ((packed)) le_remote_connection_parameter_request_negative_reply_cp;
#define LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_CP_SIZE 3
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_remote_connection_parameter_request_negative_reply_rp;
#define LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_RP_SIZE 3

#define OCF_LE_SET_DATA_EENGTH 0x0022
typedef struct {
	uint16_t	conn_handle;
	uint16_t	tx_octets;
    uint16_t	tx_time;
} __attribute__ ((packed)) le_set_data_length_cp;
#define LE_SET_DATA_LENGTH_CP_SIZE 6

typedef struct {
	uint8_t		status;
	uint16_t	conn_handle;
} __attribute__ ((packed)) le_set_data_length_rp;
#define LE_SET_DATA_LENGTH_RP_SIZE 3

#define OCF_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH 0x0023
typedef struct {
	uint8_t		status;
	uint16_t	suggest_max_tx_octets;
    uint16_t	suggest_max_tx_time;
} __attribute__ ((packed)) le_read_suggested_default_data_length_rp;
#define LE_read_suggest_default_data_length_rp 5

#define OCF_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH 0x0024
typedef struct {
	uint16_t	suggest_max_tx_octets;
    uint16_t	suggest_max_tx_time;
} __attribute__ ((packed)) le_write_suggest_default_data_length_cp;
#define LE_WRITE_SUGGEST_DEFAULT_DATA_LENGTH_CP_SIZE 4

#define OCF_LE_READ_LOCAL_P_256_PUBLIC_KEY 0x0025
#define OCF_LE_GENERATE_DHKEY 0x0026
#define OCF_LE_GENERATE_DHKEY_V1 0x0026
typedef struct {
	uint8_t	    key_x_coordinate[32];
    uint8_t     key_y_coordinate[32];
} __attribute__ ((packed)) le_generate_dhkey_v1_cp;
#define LE_GENERATE_DHKEY_V1_SIZE  64
#define OCF_LE_GENERATE_DHKEY_V2 0x005E
typedef struct {
	uint8_t	    key_x_coordinate[32];
    uint8_t     key_y_coordinate[32];
    uint8_t     key_type;
} __attribute__ ((packed)) le_generate_dhkey_v2_cp;
#define LE_GENERATE_DHKEY_V2_SIZE  65

#define OCF_LE_ADD_DEVICE_TO_RESOLV_LIST	0x0027
typedef struct {
	uint8_t		bdaddr_type;
	bdaddr_t	bdaddr;
	uint8_t		peer_irk[16];
	uint8_t		local_irk[16];
} __attribute__ ((packed)) le_add_device_to_resolv_list_cp;
#define LE_ADD_DEVICE_TO_RESOLV_LIST_CP_SIZE 39

#define OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST	0x0028
typedef struct {
	uint8_t		bdaddr_type;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) le_remove_device_from_resolv_list_cp;
#define LE_REMOVE_DEVICE_FROM_RESOLV_LIST_CP_SIZE 7

#define OCF_LE_CLEAR_RESOLV_LIST		0x0029

#define OCF_LE_READ_RESOLV_LIST_SIZE		0x002A
typedef struct {
	uint8_t		status;
	uint8_t		size;
} __attribute__ ((packed)) le_read_resolv_list_size_rp;
#define LE_READ_RESOLV_LIST_SIZE_RP_SIZE 2
#define OCF_LE_READ_PEER_RESOLVABLE_ADDRESS 0x002B
typedef struct {
	uint8_t		peer_identity_address_type;
	bdaddr_t	peer_identity_address;
} __attribute__ ((packed)) le_read_peer_resolvable_address_cp;
#define LE_READ_PEER_RESOLVABLE_ADDRESS_CP_SIZE 7

typedef struct {
	uint8_t		status;
	bdaddr_t	peer_resolvable_address;
} __attribute__ ((packed)) le_read_peer_resolvable_address_rp;
#define LE_READ_PEER_RESOLVABLE_ADDRESS_RP_SIZE 7

#define OCF_LE_READ_LOCAL_RESOLVABLE_ADDRESS 0x002c
typedef struct {
	uint8_t		peer_identity_address_type;
	bdaddr_t	peer_identity_address;
} __attribute__ ((packed)) le_read_local_resolvable_address_cp;
#define LE_READ_LOCAL_RESOLVABLE_ADDRESS_CP_SIZE 7

typedef struct {
	uint8_t		status;
	bdaddr_t	local_resolvable_address;
} __attribute__ ((packed)) le_read_local_resolvable_address_rp;
#define LE_READ_LOCAL_RESOLVABLE_ADDRESS_RP_SIZE 7


#define OCF_LE_SET_ADDRESS_RESOLUTION_ENABLE	0x002D
typedef struct {
	uint8_t		enable;
} __attribute__ ((packed)) le_set_address_resolution_enable_cp;
#define LE_SET_ADDRESS_RESOLUTION_ENABLE_CP_SIZE 1


#define OCF_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT 002E
typedef struct {
	uint8_t		rpa_timeout;
} __attribute__ ((packed)) le_set_resolvable_private_address_timeout_cp;
#define LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT_CP_SIZE 1

#define OCF_LE_READ_MAXIMUM_DATA_LENGTH 0x002F
typedef struct {
    uint8_t     status;
    uint16_t    supported_max_tx_octets;
    uint16_t    supported_max_tx_time;
    uint16_t    supported_max_rx_octets;
    uint16_t    supported_max_rx_tim;
} __attribute__ ((packed)) le_read_maximum_data_length_rp;
#define LE_READ_MAXIMUM_DATA_LENGTH_RP_SIZE 9

#define OCF_LE_READ_PHY 0x0030
typedef struct {
    uint8_t     status;
    uint16_t    Connection_Handle;
} __attribute__ ((packed)) le_read_phy_cp;
#define LE_READ_PHY_CP_SIZE 3

typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
    uint8_t     tx_phy;
    uint8_t     rx_ph;
} __attribute__ ((packed)) le_read_phy_rp;
#define LE_READ_PHY_RP_SIZE 5

#define OCF_LE_SET_DEFAULT_PHY 0x0031
typedef struct {
    uint8_t     status;
    uint8_t     tx_phy;
    uint8_t     rx_ph;
} __attribute__ ((packed)) le_set_default_phy_cp;
#define LE_SET_DEFAULT_PHY_SIZE 3

#define OCF_LE_SET_PHY 0x0032
typedef struct {
    uint16_t    connection_handle;
    uint8_t     all_phys;
    uint8_t     tx_phys;
    uint8_t     rx_phys;
    uint16_t     phy_options;
} __attribute__ ((packed)) le_set_phy_cp;
#define LE_SET_PHY_CP_SIZE 7

#define OCF_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS 0x0035
typedef struct {
    uint8_t     advertising_handle;
    bdaddr_t    random_address;
} __attribute__ ((packed)) le_set_advertising_set_random_address_cp;
#define LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_CP_SIZE  7

#define OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS 0x0036
#define OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V1 0x0036
typedef struct {
    uint8_t     advertising_handle;
    uint16_t    advertising_event_properties;
    uint24_t    primary_advertising_interval_min;
    uint24_t    primary_advertising_interval_max;
    uint8_t     primary_advertising_channel_map;
    uint8_t     own_address_type;
    uint8_t     peer_address_type;
    bdaddr_t    peer_address;
    uint8_t     advertising_filter_policy;
    uint8_t     advertising_tx_power;
    uint8_t     primary_advertising_phy;
    uint8_t     secondary_advertising_max_skip;
    uint8_t     secondary_advertising_phy;
    uint8_t     advertising_sid;
    uint8_t     scan_request_notification_enable;
} __attribute__ ((packed)) le_set_extended_advertising_parameters_v1_cp;
#define LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V1_CP_SIZE 25

#define OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2 0x007F
typedef struct {
    uint8_t     advertising_handle;
    uint16_t    advertising_event_properties;
    uint24_t    primary_advertising_interval_min;
    uint24_t    primary_advertising_interval_max;
    uint8_t     primary_advertising_channel_map;
    uint8_t     own_address_type;
    uint8_t     peer_address_type;
    bdaddr_t    peer_address;
    uint8_t     advertising_filter_policy;
    uint8_t     advertising_tx_power;
    uint8_t     primary_advertising_phy;
    uint8_t     secondary_advertising_max_skip;
    uint8_t     secondary_advertising_phy;
    uint8_t     advertising_sid;
    uint8_t     scan_request_notification_enable;
    uint8_t     primary_advertising_phy_options;
    uint8_t     secondary_advertising_phy_options;
} __attribute__ ((packed)) le_set_extended_advertising_parameters_v2_cp;
#define LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2_CP_SIZE 27

typedef struct {
    uint8_t     status;
    uint8_t     selected_tx_power;
} __attribute__ ((packed)) le_set_extended_advertising_parameters_rp;
#define LE_SET_EXTENDED_ADVERTISING_PARAMETERS_RP_SIZE 7

#define OCF_LE_SET_EXTENDED_ADVERTISING_DATA 0x0037
typedef struct {
    uint8_t     advertising_handle;
    uint8_t     operation;
    uint8_t     fragment_preference;
    uint8_t     advertising_data_length;
    uint8_t     advertising_data[0];
} __attribute__ ((packed)) le_set_extended_advertising_data_cp;
#define LE_SET_EXTENDED_ADVERTISING_DATA_CP_SIZE 5

#define OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA 0x0038
typedef struct {
    uint8_t     advertising_handle;
    uint8_t     operation;
    uint8_t     fragment_preference;
    uint8_t     scan_response_data_length;
    uint8_t     scan_response_data[0];
} __attribute__ ((packed)) le_set_extended_scan_response_data_cp;
#define LE_SET_EXTENDED_SCAN_RESPONSE_DATA_CP_SIZE 5

#define OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE 0x0039
typedef struct {
    uint8_t     enable;
    uint8_t     num_sets;   //default set to 1 and alloc defined buffer
    uint8_t     advertising_handle[1];  // num_sets *1
    uint16_t    duration[1];    // num_sets *1
    uint8_t     max_extended_advertising_events[1];     // num_sets *1
} __attribute__ ((packed)) le_set_extended_advertising_enable_cp;
#define LE_SET_EXTENDED_ADVERTISING_ENABLE_CP_SIZE 6

#define OCF_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH 0x003A
typedef struct {
    uint8_t     status;
    uint16_t    max_advertising_data_length;
} __attribute__ ((packed)) le_read_maximum_advertising_data_length_rp;
#define LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_RP_SIZE 7

#define OCF_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS 0x003B
typedef struct {
    uint8_t     status;
    uint8_t     num_supported_advertising_sets;
} __attribute__ ((packed)) le_read_number_of_supported_advertising_sets_rp;
#define LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_RP_SIZE 2

#define OCF_LE_REMOVE_ADVERTISING_SET 0x003C
typedef struct {
    uint8_t     advertising_handle;
} __attribute__ ((packed)) le_remove_advertising_set_cp;
#define LE_REMOVE_ADVERTISING_SET_CP_SIZE 1

#define OCF_LE_CLEAR_ADVERTISING_SETS 0x003D

#define OCF_LE_SET_PERIODIC_ADVERTISING_PARAMETERS 0x003E
#define OCF_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V1 0x003E
typedef struct {
    uint8_t     advertising_handle;
    uint16_t    periodic_advertising_interval_min;
    uint16_t    periodic_advertising_interval_max;
    uint16_t    periodic_advertising_properties;
} __attribute__ ((packed)) le_set_periodic_advertising_parameters_v1_cp;
#define LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V1_CP_SIZE 7

#define OCF_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2 0x0086
typedef struct {
    uint8_t     advertising_handle;
    uint16_t    periodic_advertising_interval_min;
    uint16_t    periodic_advertising_interval_max;
    uint16_t    periodic_advertising_properties;
    uint8_t     num_subevents;
    uint8_t     subevent_interval;
    uint8_t     response_slot_delay;
    uint8_t     response_slot_spacing;
    uint8_t     num_response_slots;
} __attribute__ ((packed)) le_set_periodic_advertising_parameters_v2_cp;
#define LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2_CP_SIZE   12

#define OCF_LE_SET_PERIODIC_ADVERTISING_DATA 0x003F
typedef struct {
    uint8_t     advertising_handle;
    uint8_t     operation;
    uint8_t     advertising_data_length;
    uint8_t     advertising_data;
} __attribute__ ((packed)) le_set_periodic_advertising_data_cp;
#define LE_SET_PERIODIC_ADVERTISING_DATA_CP_SIZE   4

#define OCF_LE_SET_PERIODIC_ADVERTISING_ENABLE 0x0040
typedef struct {
    uint8_t     enable;
    uint8_t     advertising_handle;
} __attribute__ ((packed)) le_set_periodic_advertising_enable_cp;
#define LE_SET_PERIODIC_ADVERTISING_ENABLE_CP_SIZE   2

#define OCF_LE_SET_EXTENDED_SCAN_PARAMETERS 0x0041
typedef struct {
    uint8_t     own_address_type;
    uint8_t     scanning_filter_policy;
    uint8_t     scanning_phys;
    uint8_t     scan_type[1];
    uint16_t    scan_interval[1];
    uint16_t    scan_window[1];
} __attribute__ ((packed)) le_set_extended_scan_parameters_cp;
#define LE_SET_EXTENDED_SCAN_PARAMETERS_CP_SIZE 8

#define OCF_LE_SET_EXTENDED_SCAN_ENABLE 0x0042
typedef struct {
    uint8_t     enable;
    uint8_t     filter_duplicates;
    uint16_t    duration;
    uint16_t    period;
} __attribute__ ((packed)) le_set_extended_scan_enable_cp;
#define LE_SET_EXTENDED_SCAN_ENABLE_CP_SIZE 6

#define OCF_LE_EXTENDED_CREATE_CONNECTION_V1 0x0043
typedef struct {
    uint8_t     initiator_filter_policy;
    uint8_t     own_address_type;
    uint8_t     peer_address_type;
    bdaddr_t    peer_address;
    uint8_t     initiating_phys;
    uint16_t    scan_interval[1];
    uint16_t    scan_window[1];
    uint16_t    connection_interval_min[1];
    uint16_t    connection_interval_max[1];
    uint16_t    max_latency[7];
    uint16_t    supervision_timeout[1];
    uint16_t    min_ce_length[1];
    uint16_t    max_ce_length[1];
} __attribute__ ((packed)) le_set_extended_scan_enable_v1_cp;
#define LE_SET_EXTENDED_SCAN_ENABLE_V1_CP_SIZE 38

#define OCF_LE_EXTENDED_CREATE_CONNECTION_V2 0x85
typedef struct {
    uint8_t     advertising_handle;
    uint8_t     subevent;
    uint8_t     peer_address_type;
    bdaddr_t    peer_address;
    uint8_t     initiating_phys;
    uint16_t    scan_interval[1];
    uint16_t    scan_window[1];
    uint16_t    connection_interval_min[1];
    uint16_t    connection_interval_max[1];
    uint16_t    max_latency[7];
    uint16_t    supervision_timeout[1];
    uint16_t    min_ce_length[1];
    uint16_t    max_ce_length[1];
} __attribute__ ((packed)) le_set_extended_scan_enable_v2s_cp;
#define LE_SET_EXTENDED_SCAN_ENABLE_V1_CP2_SIZE 38

#define OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC 0x0044
typedef struct {
    uint8_t     options;
    uint8_t     advertising_sid;
    uint8_t     advertiser_address_type;
    bdaddr_t    advertiser_address;
    uint16_t    skip;
    uint16_t    sync_timeout;
    uint8_t     sync_cte_type;
} __attribute__ ((packed)) le_periodic_advertising_create_sync_cp;
#define LE_PERIODIC_ADVERTISING_CREATE_SYNC_CP_SIZE 14


#define OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL 0x0045

#define OCF_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC 0x0046
typedef struct {
    uint16_t    sync_handle;
} __attribute__ ((packed)) le_periodic_advertising_terminate_sync_cp;
#define LE_PERIODIC_ADVERTISING_TERMINATE_SYNC_CP_SIZE 2


#define OCF_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST 0x0047
typedef struct {
	uint8_t		advertiser_address_type;
    bdaddr_t    advertiser_address;
    uint8_t     advertising_sid;
} __attribute__ ((packed)) le_add_device_to_periodic_advertiser_list_cp;
#define LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST_CP_SIZE 8

#define OCF_LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST 0x0048
typedef struct {
	uint8_t		advertiser_address_type;
    bdaddr_t    advertiser_address;
    uint8_t     advertising_sid;
} __attribute__ ((packed)) le_remove_device_from_periodic_advertiser_list_cp;
#define LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST_CP_SIZE 8

#define OCF_LE_CLEAR_PERIODIC_ADVERTISER_LIST 0x0049
#define OCF_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE 0x004A
typedef struct {
	uint8_t		status;
	uint8_t		periodic_advertiser_list_size;
} __attribute__ ((packed)) le_read_periodic_advertiser_list_size_rp;
#define LE_READ_PERIODIC_ADVERTISER_LIST_SIZE_RP_SIZE 2

#define OCF_LE_READ_TRANSMIT_POWER 0x004B
typedef struct {
	uint8_t		status;
	uint8_t		min_tx_power;
    uint8_t     max_tx_power;
} __attribute__ ((packed)) le_read_transmit_power_rp;
#define LE_READ_TRANSMIT_POWER_RP_SIZE 3


#define OCF_LE_READ_RF_PATH_COMPENSATION 0x004C
typedef struct {
	uint8_t		status;
	uint16_t		RF_TX_Path_Compensation_Value;
    uint16_t     RF_RX_Path_Compensation_Value;
} __attribute__ ((packed)) LE_READ_RF_PATH_COMPENSATION_rp;
#define LE_READ_RF_PATH_COMPENSATION_RP_SIZE 5

#define OCF_LE_WRITE_RF_PATH_COMPENSATION 0x004D
typedef struct {
	uint16_t	RF_TX_Path_Compensation_Value;
    uint16_t    RF_RX_Path_Compensation_Value;
} __attribute__ ((packed)) le_write_rf_path_compensation_cp;
#define LE_WRITE_RF_PATH_COMPENSATION_CP  4

#define OCF_LE_SET_PRIVACY_MODE 0x004E
typedef struct {
    uint8_t     peer_identity_address_type;
    bdaddr_t    peer_identity_address;
    uint8_t     privacy_mode;
} __attribute__ ((packed)) le_set_privacy_mode_cp;
#define LE_SET_PRIVACY_MODE_CP_SIZE 8

#define OCF_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS 0x0051
typedef struct {
    uint8_t     advertising_handle;
    uint8_t     cte_length;
    uint8_t     cte_type;
    uint8_t     cte_count;
    uint8_t     switching_pattern_length ;
    uint8_t     antenna_ids[1];
} __attribute__ ((packed)) set_connectionless_cte_transmit_parameters_cp;
#define LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS_CP_SIZE 6

#define OCF_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE 0x0052
typedef struct {
    uint8_t     advertising_handle;
    uint8_t     cte_enable;
} __attribute__ ((packed)) le_set_connectionless_cte_transmit_enable_cp;
#define LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE_CP_SIZE 2

#define OCF_LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE 0x0053
typedef struct {
    uint16_t    ync_handle;
    uint8_t     sampling_enable;
    uint8_t     slot_durations;
    uint8_t     max_sampled_ctes;
    uint8_t     switching_pattern_length;
    uint8_t     antenna_ids[1];
} __attribute__ ((packed)) le_set_connectionless_iq_sampling_enable_cp;
#define LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE_CP_SIZE 7
typedef struct {
    uint8_t     status;
    uint16_t    sync_handle;
} __attribute__ ((packed)) le_set_connectionless_iq_sampling_enable_rp;
#define LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE_RP_SIZE 3


#define OCF_LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS 0x0054
typedef struct {
    uint16_t    connection_handle;
    uint8_t     sampling_enable;
    uint8_t     slot_durations;
    uint8_t     switching_pattern_length;
    uint8_t     antenna_ids[1];
} __attribute__ ((packed)) le_set_connection_cte_receive_parameters_cp;
#define LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS_CP_SIZE 6
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_set_connection_cte_receive_parameters_rp;
#define LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS_RP_SIZE 3


#define OCF_LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS 0x0055
typedef struct {
    uint16_t    connection_handle;
    uint8_t     cte_types;
    uint8_t     switching_pattern_length;
    uint8_t     antenna_ids[1];
} __attribute__ ((packed)) le_set_connection_cte_transmit_parameters_cp;
#define LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS_CP_SIZE 5
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_set_connection_cte_transmit_parameters_rp;
#define LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS_RP_SIZE 3

#define OCF_LE_CONNECTION_CTE_REQUEST_ENABLE 0x0056
typedef struct {
    uint16_t    connection_handle;
    uint8_t     enable;
    uint16_t    cte_request_interval;
    uint8_t     requested_cte_length;
    uint8_t     requested_cte_type;
} __attribute__ ((packed)) le_connection_cte_request_enable_cp;
#define LE_CONNECTION_CTE_REQUEST_ENABLE_CP_SIZE 7
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_connection_cte_request_enable_rp;
#define LE_CONNECTION_CTE_REQUEST_ENABLE_RP_SIZE 3


#define OCF_LE_CONNECTION_CTE_RESPONSE_ENABLE 0x0057
typedef struct {
    uint16_t    connection_handle;
    uint8_t     enable;
} __attribute__ ((packed)) le_connection_cte_response_enable_cp;
#define LE_CONNECTION_CTE_RESPONSE_ENABLE_CP_SIZE 3

typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_connection_cte_response_enable_rp;
#define LE_CONNECTION_CTE_RESPONSE_ENABLE_RP_SIZE 3

#define OCF_LE_READ_ANTENNA_INFORMATION 0x0058
typedef struct {
    uint8_t     status;
    uint8_t     supported_switching_sampling_rates;
    uint8_t     num_antennae;
    uint8_t     max_switching_pattern_length;
    uint8_t     max_cte_lengt;
} __attribute__ ((packed)) le_read_antenna_information_rp;
#define LE_READ_ANTENNA_INFORMATION_RP_SIZE 5

#define OCF_LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE 0x0059
typedef struct {
    uint16_t    sync_handle;
    uint8_t     enable;
} __attribute__ ((packed)) le_set_periodic_advertising_receive_enable_cp;
#define LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE_CP_SIZE 3

#define OCF_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER 0x005A
typedef struct {
    uint16_t    connection_handle;
    uint16_t    service_data;
    uint16_t    sync_handle;
} __attribute__ ((packed)) le_periodic_advertising_sync_transfer_cp;
#define LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_CP_SIZE 6
typedef struct {
    uint8_t    status;
    uint16_t   connection_handle;
} __attribute__ ((packed)) le_periodic_advertising_sync_transfer_rp;
#define LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RP_SIZE 3

#define OCF_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER 0x005B
typedef struct {
    uint16_t    connection_handle;
    uint16_t    service_data;
    uint8_t     advertising_handle;
} __attribute__ ((packed)) le_periodic_advertising_set_info_transfer_cp;
#define LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER_CP_SIZE 5
typedef struct {
    uint8_t    status;
    uint16_t   connection_handle;
} __attribute__ ((packed)) le_periodic_advertising_set_info_transfer_rp;
#define LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER_RP_SIZE 3

#define OCF_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS 0x005C
typedef struct {
    uint16_t    connection_handle;
    uint8_t     mode;
    uint16_t    skip;
    uint16_t    sync_timeout;
    uint8_t     cte_type;
} __attribute__ ((packed)) le_set_periodic_advertising_sync_transfer_parameters_cp;
#define LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_CP_SIZE 8
typedef struct {
    uint8_t    status;
    uint16_t   connection_handle;
} __attribute__ ((packed)) le_set_periodic_advertising_sync_transfer_parameters_rp;
#define LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_RP_SIZE 3

#define OCF_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS 0x005D
typedef struct {
    uint8_t     mode;
    uint16_t    skip;
    uint16_t    sync_timeout;
    uint8_t     cte_type;
} __attribute__ ((packed)) le_set_default_periodic_advertising_sync_transfer_parameters_cp;
#define LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_CP_SIZE 6


#define OCF_LE_MODIFY_SLEEP_CLOCK_ACCURACY 0x005F
typedef struct {
    uint8_t     action;
} __attribute__ ((packed)) le_modify_sleep_clock_accuracy_cp;
#define LE_MODIFY_SLEEP_CLOCK_ACCURACY_CP_SIZE 1

#define OCF_LE_READ_ISO_TX_SYNC 0x0061
typedef struct {
    uint16_t     connection_handle;
} __attribute__ ((packed)) le_read_iso_tx_sync_cp;
#define LE_READ_ISO_TX_SYNC_CP_SIZE 2
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
    uint16_t    packet_sequence_number;
    uint32_t    tx_time_stamp;
    uint32_t    time_offset;  //in protocol definition, the value is 3 octets, need investigate.
} __attribute__ ((packed)) le_read_iso_tx_sync_rp;
#define LE_READ_ISO_TX_SYNC_RP_SIZE 13

#define OCF_LE_SET_CIG_PARAMETERS 0x0062
typedef struct {
    uint8_t     cig_id;
    uint8_t     sdu_interval_c_to_p[3];
    uint8_t     sdu_interval_p_to_c[3];
    uint8_t     worst_case_sca;
    uint8_t     packing;
    uint8_t     framing;
    uint16_t    max_transport_latency_c_to_p;
    uint16_t    max_transport_latency_p_to_c;
    uint8_t     cis_count;
    uint8_t     cis_id[1];
    uint8_t     max_sdu_c_to_p[1];
    uint8_t     max_sdu_p_to_c[1];
    uint8_t     phy_c_to_p[1];
    uint8_t     phy_p_to_c[1];
    uint8_t     rtn_c_to_p[1];
    uint8_t     rtn_p_to_c[1];
} __attribute__ ((packed)) le_set_cig_parameters_cp;
#define LE_SET_CIG_PARAMETERS_CP_SIZE 22
typedef struct {
    uint8_t     status;
    uint8_t     cig_id;
    uint8_t     cis_count;
    uint16_t    connection_handle[1];
} __attribute__ ((packed)) le_set_cig_parameters_rp;
#define LE_SET_CIG_PARAMETERS_RP_SIZE 5

#define OCF_LE_SET_CIG_PARAMETERS_TEST 0x0063
typedef struct {
    uint8_t     cig_id;
    uint8_t     sdu_interval_c_to_p[3];
    uint8_t     sdu_interval_p_to_c[3];
    uint8_t     ft_c_to_p;
    uint8_t     ft_p_to_c;
    uint16_t    iso_interval;
    uint8_t     worst_case_sca;
    uint8_t     packing;
    uint8_t     framing;
    uint8_t     cis_count;
    uint8_t     cis_id[1];
    uint8_t     nse[1];
    uint16_t    max_sdu_c_to_p[1];
    uint16_t    max_sdu_p_to_c[1];
    uint16_t    max_pdu_c_to_p[1];
    uint16_t    max_pdu_p_to_c[1];
    uint8_t     phy_c_to_p[1];
    uint8_t     phy_p_to_c[1];
    uint8_t     bn_c_to_p[1];
    uint8_t     bn_p_to_c[1];
} __attribute__ ((packed)) le_set_cig_parameters_test_cp;
#define LE_SET_CIG_PARAMETERS_TEST_CP_SIZE 29
typedef struct {
    uint8_t     status;
    uint8_t     cig_id;
    uint8_t     cis_count;
    uint16_t    connection_handle[1];
} __attribute__ ((packed)) le_set_cig_parameters_test_rp;
#define LE_SET_CIG_PARAMETERS_TEST_RP_SIZE 7

#define OCF_LE_CREATE_CIS 0x0064
typedef struct {
    uint8_t     cis_count;
    uint16_t    cis_connection_handle[1];
    uint16_t    acl_connection_handle[1];
} __attribute__ ((packed)) le_create_cis_cp;
#define LE_CREATE_CIS_CP_SIZE 5

#define OCF_LE_REMOVE_CIG 0x0065
typedef struct {
    uint8_t     cig_id;
} __attribute__ ((packed)) le_remove_cig_cp;
#define OCF_LE_REMOVE_CIG_CP_SIZE 1

typedef struct {
    uint8_t     status;
    uint8_t     cig_id;
} __attribute__ ((packed)) le_remove_cig_rp;
#define OCF_LE_REMOVE_CIG_RP_SIZE 2

#define OCF_LE_ACCEPT_CIS_REQUEST 0x0066
typedef struct {
    uint16_t     connection_handle;
} __attribute__ ((packed)) le_accept_cis_request_rp;
#define LE_ACCEPT_CIS_REQUEST_RP_SIZE 2

#define OCF_LE_REJECT_CIS_REQUEST 0x0067
typedef struct {
    uint16_t    connection_handle;
    uint8_t     reason;
} __attribute__ ((packed)) le_reject_cis_request_cp;
#define LE_REJECT_CIS_REQUEST_CP_SIZE 3
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_reject_cis_request_rp;
#define LE_REJECT_CIS_REQUEST_CP_SIZE 3

#define OCF_LE_CREATE_BIG 0x0068
typedef struct {
    uint8_t     big_handle;
    uint8_t     advertising_handle;
    uint8_t     num_bis;
    uint8_t     sdu_interval[3];
    uint16_t    max_sdu;
    uint16_t    max_transport_latency;
    uint8_t     rtn;
    uint8_t     phy;
    uint8_t     packing;
    uint8_t     framing;
    uint8_t     encryption;
    uint8_t     broadcast_code[16];
} __attribute__ ((packed)) le_create_big_cp;
#define LE_CREATE_BIG_CP_SIZE 31

#define OCF_LE_CREATE_BIG_TEST 0x0069
typedef struct {
    uint8_t     big_handle;
    uint8_t     advertising_handle;
    uint8_t     num_bis;
    uint8_t     sdu_interval[3];
    uint16_t    iso_interval;
    uint8_t     nse;
    uint16_t    max_sdu;
    uint16_t    max_pdu;
    uint8_t     phy;
    uint8_t     packing;
    uint8_t     framing;
    uint8_t     bn;
    uint8_t     irc;
    uint8_t     pto;
    uint8_t     encryption;
    uint8_t     broadcast_code[16];
} __attribute__ ((packed)) le_create_big_test_cp;
#define LE_CREATE_BIG_TEST_CP_SIZE 40

#define OCF_LE_TERMINATE_BIG 0x006A
typedef struct {
    uint8_t     big_handle;
    uint8_t     reason;
} __attribute__ ((packed)) le_terminate_big_cp;
#define LE_TERMINATE_BIG_CP_SIZE 2

#define OCF_LE_BIG_CREATE_SYNC 0x006B
typedef struct {
    uint8_t     big_handle;
    uint16_t    sync_handle;
    uint8_t     encryption;
    uint8_t     broadcast_code[16];
    uint8_t     mse;
    uint16_t    big_sync_timeout;
    uint8_t     num_bis;
    uint8_t bis[1];
} __attribute__ ((packed)) le_big_create_sync_cp;
#define LE_BIG_CREATE_SYNC_CP_SIZE 10

#define OCF_LE_BIG_TERMINATE_SYNC 0x006C
typedef struct {
    uint8_t     big_handle;
} __attribute__ ((packed)) le_big_terminate_sync_cp;
#define LE_BIG_TERMINATE_SYNC_CP_SIZE 1
typedef struct {
    uint8_t     status;
    uint8_t     big_handle;
} __attribute__ ((packed)) le_big_terminate_sync_rp;
#define LE_BIG_TERMINATE_SYNC_RO_SIZE 2

#define OCF_LE_REQUEST_PEER_SCA 0x006D
typedef struct {
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_request_peer_sca_cp;
#define LE_REQUEST_PEER_SCA_CP_SIZE   2

#define OCF_LE_SETUP_ISO_DATA_PATH 0x006E
typedef struct {
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_setup_iso_data_path;
#define LE_SETUP_ISO_DATA_PATH_SIZE   2
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_setup_iso_data_path_rp;
#define LE_SETUP_ISO_DATA_PATH_RP_SIZE   3

#define OCF_LE_REMOVE_ISO_DATA_PATH 0x006F
typedef struct {
    uint16_t    connection_handle;
    uint8_t     data_path_direction;
} __attribute__ ((packed)) le_remove_iso_data_path_cp;
#define LE_REMOVE_ISO_DATA_PATH_CP_SIZE   3
typedef struct {
    uint8_t      status;
    uint16_t     connection_handle;
} __attribute__ ((packed)) le_remove_iso_data_path_p;
#define LE_REMOVE_ISO_DATA_PATH_RP_SIZE   3

#define OCF_LE_ISO_TRANSMIT_TEST 0x0070
typedef struct {
    uint16_t    connection_handle;
    uint8_t     payload_type;
} __attribute__ ((packed)) le_iso_transmit_test_cp;
#define LE_ISO_TRANSMIT_TEST_CP_SIZE   3
typedef struct {
    uint8_t      status;
    uint16_t     connection_handle;
} __attribute__ ((packed)) le_iso_transmit_test_rp;
#define LE_ISO_TRANSMIT_TEST_RP_SIZE   3

#define OCF_LE_ISO_RECEIVE_TEST 0x0071
typedef struct {
    uint16_t    connection_handle;
    uint8_t     payload_type;
} __attribute__ ((packed)) le_iso_receive_test_cp;
#define LE_ISO_RECEIVE_TEST_CP_SIZE   3
typedef struct {
    uint8_t      status;
    uint16_t     connection_handle;
} __attribute__ ((packed)) le_iso_receive_test_rp;
#define LE_ISO_RECEIVE_TEST_CP_SIZE   3

#define OCF_LE_ISO_READ_TEST_COUNTERS 0x0072
typedef struct {
    uint16_t    connection_handle;
    uint8_t     payload_type;
} __attribute__ ((packed)) le_iso_read_test_counters_cp;
#define LE_ISO_READ_TEST_COUNTERS_CP_SIZE   3
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
    uint32_t    received_sdu_count;
    uint32_t    missed_sdu_count;
    uint32_t    failed_sdu_count;
} __attribute__ ((packed)) le_iso_read_test_counters_rp;
#define LE_ISO_READ_TEST_COUNTERS_RP_SIZE   15

#define OCF_LE_ISO_TEST_END 0x0073
typedef struct {
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_iso_test_end_cp;
#define LE_ISO_TEST_END_CP_SIZE   2
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
    uint32_t    received_sdu_count;
    uint32_t    missed_sdu_count;
    uint32_t    failed_sdu_count;
} __attribute__ ((packed)) le_iso_test_end_rp;
#define LE_ISO_TEST_END_RP_SIZE   15

#define OCF_LE_SET_HOST_FEATURE 0x0074
typedef struct {
    uint8_t     bit_number;
    uint8_t     bit_value;
} __attribute__ ((packed)) le_set_host_feature_cp;
#define LE_SET_HOST_FEATURE_CP_SIZE   2

#define OCF_LE_READ_ISO_LINK_QUALITY 0x0075
typedef struct {
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_read_iso_link_quality_cp;
#define LE_READ_ISO_LINK_QUALITY_CP_SIZE   2
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
    uint32_t    tx_unacked_packets;
    uint32_t    tx_flushed_packets;
    uint32_t    tx_last_subevent_packets;
    uint32_t    retransmitted_packets;
    uint32_t    crc_error_packets;
    uint32_t    rx_unreceived_packets;
    uint32_t    duplicate_packet;
} __attribute__ ((packed)) le_read_iso_link_quality_rp;
#define LE_READ_ISO_LINK_QUALITY_RP_SIZE   31

#define OCF_LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL 0x0076
typedef struct {
    uint16_t    connection_handle;
    uint8_t     phy;
} __attribute__ ((packed)) le_enhanced_read_transmit_power_level_cp;
#define LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL_CP_SIZE   3
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
    uint32_t    tx_unacked_packets;
    uint32_t    tx_flushed_packets;
    uint32_t    tx_last_subevent_packets;
    uint32_t    retransmitted_packets;
    uint32_t    crc_error_packets;
    uint32_t    rx_unreceived_packets;
    uint32_t    duplicate_packets;
} __attribute__ ((packed)) le_enhanced_read_transmit_power_level_rp;
#define LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL_RP_SIZE   31

#define OCF_LE_READ_REMOTE_TRANSMIT_POWER_LEVEL 0x0077
typedef struct {
    uint16_t    connection_handle;
    uint8_t     phy;
} __attribute__ ((packed)) le_read_remote_transmit_power_level_cp;
#define LE_READ_REMOTE_TRANSMIT_POWER_LEVEL_CP_SIZE   3

#define OCF_LE_SET_PATH_LOSS_REPORTING_PARAMETERS 0x0078
typedef struct {
    uint16_t    connection_handle;
    uint8_t     High_Threshold;
    uint8_t     High_Hysteresis;
    uint8_t     Low_Threshold;
    uint8_t     Low_Hysteresis;
    uint16_t    Min_Time_Spent;
} __attribute__ ((packed)) le_set_path_loss_reporting_parameters_cp;
#define LE_SET_PATH_LOSS_REPORTING_PARAMETERS_CP_SIZE   8

typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_set_path_loss_reporting_parameters_rp;
#define LE_SET_PATH_LOSS_REPORTING_PARAMETERS_RP_SIZE   3

#define OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE 0x0079
typedef struct {
    uint8_t     status;
    uint8_t     enable;
} __attribute__ ((packed)) le_set_path_loss_reporting_enable_cp;
#define LE_SET_PATH_LOSS_REPORTING_ENABLE_CP_SIZE   2
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_set_path_loss_reporting_enable_rp;
#define LE_SET_PATH_LOSS_REPORTING_ENABLE_RP_SIZE   3

#define OCF_LE_SET_TRANSMIT_POWER_REPORTING_ENABLE 0x007A
typedef struct {
    uint8_t     status;
    uint8_t     local_enable;
    uint8_t     remote_enable;
} __attribute__ ((packed)) le_set_transmit_power_reporting_enable_cp;
#define LE_SET_TRANSMIT_POWER_REPORTING_ENABLE_CP_SIZE   3
typedef struct {
    uint8_t     status;
    uint16_t    connection_handle;
} __attribute__ ((packed)) le_set_transmit_power_reporting_enable_rp;
#define LE_SET_TRANSMIT_POWER_REPORTING_ENABLE_RP_SIZE   3

#define OCF_LE_SET_DATA_RELATED_ADDRESS_CHANGES 0x007C
typedef struct {
    uint8_t     Advertising_Handle;
    uint8_t     Change_Reasons;
} __attribute__ ((packed)) le_set_data_related_address_changes_cp;
#define LE_SET_DATA_RELATED_ADDRESS_CHANGES_CP_SIZE   2

#define OCF_LE_SET_DEFAULT_SUBRATE 0x007D
typedef struct {
    uint16_t    subrate_min;
    uint16_t    subrate_max;
    uint16_t    max_latency;
    uint16_t    continuation_number;
    uint16_t    supervision_timeout;
} __attribute__ ((packed)) le_set_default_subrate_cp;
#define OCF_LE_SET_DEFAULT_SUBRATE_CP_SIZE   20

#define OCF_LE_SUBRATE_REQUEST 0x007E
typedef struct {
    uint16_t    connection_handle;
    uint16_t    subrate_min;
    uint16_t    subrate_max;
    uint16_t    max_latency;
    uint16_t    continuation_number;
    uint16_t    supervision_timeout;
} __attribute__ ((packed)) le_subrate_request_cp;
#define OCF_LE_SUBRATE_REQUEST_CP_SIZE   24

#define OCF_LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA 0x82
typedef struct {
    uint8_t     advertising_handle;
    uint8_t     num_subevents;
    uint8_t     subevent[1];
    uint8_t     response_slot_start[1];
    uint8_t     response_slot_count[1];
    uint8_t     subevent_data_length[1];
    uint8_t     subevent_data[1];
} __attribute__ ((packed)) le_set_periodic_advertising_subevent_data_cp;
#define LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA_CP_DIZE   7

typedef struct {
    uint8_t     status;
    uint8_t     advertising_handle;
} __attribute__ ((packed)) le_set_periodic_advertising_subevent_data_rp;
#define LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA_RP_SIZE   2


#define OCF_LE_SET_PERIODIC_ADVERTISING_RESPONSE_DATA 0x83
typedef struct {
    uint16_t    sync_handle;
    uint16_t    request_event;
    uint8_t     request_subevent;
    uint8_t     response_subevent;
    uint8_t     response_slot;
    uint8_t     response_data_length;
    uint8_t     response_data[1];
} __attribute__ ((packed)) le_set_periodic_advertising_response_data_cp;
#define LE_SET_PERIODIC_ADVERTISING_RESPONSE_DATA_CP_SIZE   13

typedef struct {
    uint8_t     status;
    uint16_t    sync_handle;
} __attribute__ ((packed)) le_set_periodic_advertising_response_data_rp;
#define LE_SET_PERIODIC_ADVERTISING_RESPONSE_DATA_RP_SIZE   3

#define OCF_LE_SET_PERIODIC_SYNC_SUBEVENT 0x84
typedef struct {
    uint16_t    sync_handle;
    uint8_t     periodic_advertising_properties;
    uint8_t     num_subevents;
    uint8_t     subevent[1];
} __attribute__ ((packed)) le_set_periodic_sync_subevent_cp;
#define LE_SET_PERIODIC_SYNC_SUBEVENT_CP_SIZE   5

typedef struct {
    uint8_t     status;
    uint16_t    sync_handle;
} __attribute__ ((packed)) le_set_periodic_sync_subevent_rp;
#define LE_SET_PERIODIC_SYNC_SUBEVENT_RP_SIZE   3


/* Vendor specific commands */
#define OGF_VENDOR_CMD		0x3f

/* ---- HCI Events ---- */

#define EVT_INQUIRY_COMPLETE		0x01

#define EVT_INQUIRY_RESULT		0x02
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pscan_rep_mode;
	uint8_t		pscan_period_mode;
	uint8_t		pscan_mode;
	uint8_t		dev_class[3];
	uint16_t	clock_offset;
} __attribute__ ((packed)) inquiry_info;
#define INQUIRY_INFO_SIZE 14

#define EVT_CONN_COMPLETE		0x03
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	bdaddr_t	bdaddr;
	uint8_t		link_type;
	uint8_t		encr_mode;
} __attribute__ ((packed)) evt_conn_complete;
#define EVT_CONN_COMPLETE_SIZE 11

#define EVT_CONN_REQUEST		0x04
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		dev_class[3];
	uint8_t		link_type;
} __attribute__ ((packed)) evt_conn_request;
#define EVT_CONN_REQUEST_SIZE 10

#define EVT_DISCONN_COMPLETE		0x05
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		reason;
} __attribute__ ((packed)) evt_disconn_complete;
#define EVT_DISCONN_COMPLETE_SIZE 4

#define EVT_AUTH_COMPLETE		0x06
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) evt_auth_complete;
#define EVT_AUTH_COMPLETE_SIZE 3

#define EVT_REMOTE_NAME_REQ_COMPLETE	0x07
typedef struct {
	uint8_t		status;
	bdaddr_t	bdaddr;
	uint8_t		name[HCI_MAX_NAME_LENGTH];
} __attribute__ ((packed)) evt_remote_name_req_complete;
#define EVT_REMOTE_NAME_REQ_COMPLETE_SIZE 255

#define EVT_ENCRYPT_CHANGE		0x08
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		encrypt;
} __attribute__ ((packed)) evt_encrypt_change;
#define EVT_ENCRYPT_CHANGE_SIZE 4

#define EVT_CHANGE_CONN_LINK_KEY_COMPLETE	0x09
typedef struct {
	uint8_t		status;
	uint16_t	handle;
}  __attribute__ ((packed)) evt_change_conn_link_key_complete;
#define EVT_CHANGE_CONN_LINK_KEY_COMPLETE_SIZE 3

#define EVT_MASTER_LINK_KEY_COMPLETE		0x0A
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		key_flag;
} __attribute__ ((packed)) evt_master_link_key_complete;
#define EVT_MASTER_LINK_KEY_COMPLETE_SIZE 4

#define EVT_READ_REMOTE_FEATURES_COMPLETE	0x0B
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		features[8];
} __attribute__ ((packed)) evt_read_remote_features_complete;
#define EVT_READ_REMOTE_FEATURES_COMPLETE_SIZE 11

#define EVT_READ_REMOTE_VERSION_COMPLETE	0x0C
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		lmp_ver;
	uint16_t	manufacturer;
	uint16_t	lmp_subver;
} __attribute__ ((packed)) evt_read_remote_version_complete;
#define EVT_READ_REMOTE_VERSION_COMPLETE_SIZE 8

#define EVT_QOS_SETUP_COMPLETE		0x0D
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		flags;			/* Reserved */
	hci_qos		qos;
} __attribute__ ((packed)) evt_qos_setup_complete;
#define EVT_QOS_SETUP_COMPLETE_SIZE (4 + HCI_QOS_CP_SIZE)

#define EVT_CMD_COMPLETE		0x0E
typedef struct {
	uint8_t		ncmd;
	uint16_t	opcode;
} __attribute__ ((packed)) evt_cmd_complete;
#define EVT_CMD_COMPLETE_SIZE 3

#define EVT_CMD_STATUS			0x0F
typedef struct {
	uint8_t		status;
	uint8_t		ncmd;
	uint16_t	opcode;
} __attribute__ ((packed)) evt_cmd_status;
#define EVT_CMD_STATUS_SIZE 4

#define EVT_HARDWARE_ERROR		0x10
typedef struct {
	uint8_t		code;
} __attribute__ ((packed)) evt_hardware_error;
#define EVT_HARDWARE_ERROR_SIZE 1

#define EVT_FLUSH_OCCURRED		0x11
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) evt_flush_occured;
#define EVT_FLUSH_OCCURRED_SIZE 2

#define EVT_ROLE_CHANGE			0x12
typedef struct {
	uint8_t		status;
	bdaddr_t	bdaddr;
	uint8_t		role;
} __attribute__ ((packed)) evt_role_change;
#define EVT_ROLE_CHANGE_SIZE 8

#define EVT_NUM_COMP_PKTS		0x13
typedef struct {
	uint8_t		num_hndl;
	/* variable length part */
} __attribute__ ((packed)) evt_num_comp_pkts;
#define EVT_NUM_COMP_PKTS_SIZE 1

#define EVT_MODE_CHANGE			0x14
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		mode;
	uint16_t	interval;
} __attribute__ ((packed)) evt_mode_change;
#define EVT_MODE_CHANGE_SIZE 6

#define EVT_RETURN_LINK_KEYS		0x15
typedef struct {
	uint8_t		num_keys;
	/* variable length part */
} __attribute__ ((packed)) evt_return_link_keys;
#define EVT_RETURN_LINK_KEYS_SIZE 1

#define EVT_PIN_CODE_REQ		0x16
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) evt_pin_code_req;
#define EVT_PIN_CODE_REQ_SIZE 6

#define EVT_LINK_KEY_REQ		0x17
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) evt_link_key_req;
#define EVT_LINK_KEY_REQ_SIZE 6

#define EVT_LINK_KEY_NOTIFY		0x18
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		link_key[16];
	uint8_t		key_type;
} __attribute__ ((packed)) evt_link_key_notify;
#define EVT_LINK_KEY_NOTIFY_SIZE 23

#define EVT_LOOPBACK_COMMAND		0x19

#define EVT_DATA_BUFFER_OVERFLOW	0x1A
typedef struct {
	uint8_t		link_type;
} __attribute__ ((packed)) evt_data_buffer_overflow;
#define EVT_DATA_BUFFER_OVERFLOW_SIZE 1

#define EVT_MAX_SLOTS_CHANGE		0x1B
typedef struct {
	uint16_t	handle;
	uint8_t		max_slots;
} __attribute__ ((packed)) evt_max_slots_change;
#define EVT_MAX_SLOTS_CHANGE_SIZE 3

#define EVT_READ_CLOCK_OFFSET_COMPLETE	0x1C
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint16_t	clock_offset;
} __attribute__ ((packed)) evt_read_clock_offset_complete;
#define EVT_READ_CLOCK_OFFSET_COMPLETE_SIZE 5

#define EVT_CONN_PTYPE_CHANGED		0x1D
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint16_t	ptype;
} __attribute__ ((packed)) evt_conn_ptype_changed;
#define EVT_CONN_PTYPE_CHANGED_SIZE 5

#define EVT_QOS_VIOLATION		0x1E
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) evt_qos_violation;
#define EVT_QOS_VIOLATION_SIZE 2

#define EVT_PSCAN_REP_MODE_CHANGE	0x20
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pscan_rep_mode;
} __attribute__ ((packed)) evt_pscan_rep_mode_change;
#define EVT_PSCAN_REP_MODE_CHANGE_SIZE 7

#define EVT_FLOW_SPEC_COMPLETE		0x21
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		flags;
	uint8_t		direction;
	hci_qos		qos;
} __attribute__ ((packed)) evt_flow_spec_complete;
#define EVT_FLOW_SPEC_COMPLETE_SIZE (5 + HCI_QOS_CP_SIZE)

#define EVT_INQUIRY_RESULT_WITH_RSSI	0x22
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pscan_rep_mode;
	uint8_t		pscan_period_mode;
	uint8_t		dev_class[3];
	uint16_t	clock_offset;
	int8_t		rssi;
} __attribute__ ((packed)) inquiry_info_with_rssi;
#define INQUIRY_INFO_WITH_RSSI_SIZE 14
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pscan_rep_mode;
	uint8_t		pscan_period_mode;
	uint8_t		pscan_mode;
	uint8_t		dev_class[3];
	uint16_t	clock_offset;
	int8_t		rssi;
} __attribute__ ((packed)) inquiry_info_with_rssi_and_pscan_mode;
#define INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE 15

#define EVT_READ_REMOTE_EXT_FEATURES_COMPLETE	0x23
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		page_num;
	uint8_t		max_page_num;
	uint8_t		features[8];
} __attribute__ ((packed)) evt_read_remote_ext_features_complete;
#define EVT_READ_REMOTE_EXT_FEATURES_COMPLETE_SIZE 13

#define EVT_SYNC_CONN_COMPLETE		0x2C
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	bdaddr_t	bdaddr;
	uint8_t		link_type;
	uint8_t		trans_interval;
	uint8_t		retrans_window;
	uint16_t	rx_pkt_len;
	uint16_t	tx_pkt_len;
	uint8_t		air_mode;
} __attribute__ ((packed)) evt_sync_conn_complete;
#define EVT_SYNC_CONN_COMPLETE_SIZE 17

#define EVT_SYNC_CONN_CHANGED		0x2D
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		trans_interval;
	uint8_t		retrans_window;
	uint16_t	rx_pkt_len;
	uint16_t	tx_pkt_len;
} __attribute__ ((packed)) evt_sync_conn_changed;
#define EVT_SYNC_CONN_CHANGED_SIZE 9

#define EVT_SNIFF_SUBRATING		0x2E
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint16_t	max_tx_latency;
	uint16_t	max_rx_latency;
	uint16_t	min_remote_timeout;
	uint16_t	min_local_timeout;
} __attribute__ ((packed)) evt_sniff_subrating;
#define EVT_SNIFF_SUBRATING_SIZE 11

#define EVT_EXTENDED_INQUIRY_RESULT	0x2F
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pscan_rep_mode;
	uint8_t		pscan_period_mode;
	uint8_t		dev_class[3];
	uint16_t	clock_offset;
	int8_t		rssi;
	uint8_t		data[HCI_MAX_EIR_LENGTH];
} __attribute__ ((packed)) extended_inquiry_info;
#define EXTENDED_INQUIRY_INFO_SIZE 254

#define EVT_ENCRYPTION_KEY_REFRESH_COMPLETE	0x30
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) evt_encryption_key_refresh_complete;
#define EVT_ENCRYPTION_KEY_REFRESH_COMPLETE_SIZE 3

#define EVT_IO_CAPABILITY_REQUEST	0x31
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) evt_io_capability_request;
#define EVT_IO_CAPABILITY_REQUEST_SIZE 6

#define EVT_IO_CAPABILITY_RESPONSE	0x32
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		capability;
	uint8_t		oob_data;
	uint8_t		authentication;
} __attribute__ ((packed)) evt_io_capability_response;
#define EVT_IO_CAPABILITY_RESPONSE_SIZE 9

#define EVT_USER_CONFIRM_REQUEST	0x33
typedef struct {
	bdaddr_t	bdaddr;
	uint32_t	passkey;
} __attribute__ ((packed)) evt_user_confirm_request;
#define EVT_USER_CONFIRM_REQUEST_SIZE 10

#define EVT_USER_PASSKEY_REQUEST	0x34
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) evt_user_passkey_request;
#define EVT_USER_PASSKEY_REQUEST_SIZE 6

#define EVT_REMOTE_OOB_DATA_REQUEST	0x35
typedef struct {
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) evt_remote_oob_data_request;
#define EVT_REMOTE_OOB_DATA_REQUEST_SIZE 6

#define EVT_SIMPLE_PAIRING_COMPLETE	0x36
typedef struct {
	uint8_t		status;
	bdaddr_t	bdaddr;
} __attribute__ ((packed)) evt_simple_pairing_complete;
#define EVT_SIMPLE_PAIRING_COMPLETE_SIZE 7

#define EVT_LINK_SUPERVISION_TIMEOUT_CHANGED	0x38
typedef struct {
	uint16_t	handle;
	uint16_t	timeout;
} __attribute__ ((packed)) evt_link_supervision_timeout_changed;
#define EVT_LINK_SUPERVISION_TIMEOUT_CHANGED_SIZE 4

#define EVT_ENHANCED_FLUSH_COMPLETE	0x39
typedef struct {
	uint16_t	handle;
} __attribute__ ((packed)) evt_enhanced_flush_complete;
#define EVT_ENHANCED_FLUSH_COMPLETE_SIZE 2

#define EVT_USER_PASSKEY_NOTIFY		0x3B
typedef struct {
	bdaddr_t	bdaddr;
	uint32_t	passkey;
} __attribute__ ((packed)) evt_user_passkey_notify;
#define EVT_USER_PASSKEY_NOTIFY_SIZE 10

#define EVT_KEYPRESS_NOTIFY		0x3C
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		type;
} __attribute__ ((packed)) evt_keypress_notify;
#define EVT_KEYPRESS_NOTIFY_SIZE 7

#define EVT_REMOTE_HOST_FEATURES_NOTIFY	0x3D
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		features[8];
} __attribute__ ((packed)) evt_remote_host_features_notify;
#define EVT_REMOTE_HOST_FEATURES_NOTIFY_SIZE 14

#define EVT_LE_META_EVENT	0x3E
typedef struct {
	uint8_t		subevent;
	uint8_t		data[];
} __attribute__ ((packed)) evt_le_meta_event;
#define EVT_LE_META_EVENT_SIZE 1

#define EVT_LE_CONN_COMPLETE	0x01
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		role;
	uint8_t		peer_bdaddr_type;
	bdaddr_t	peer_bdaddr;
	uint16_t	interval;
	uint16_t	latency;
	uint16_t	supervision_timeout;
	uint8_t		master_clock_accuracy;
} __attribute__ ((packed)) evt_le_connection_complete;
#define EVT_LE_CONN_COMPLETE_SIZE 18

#define EVT_LE_ADVERTISING_REPORT	0x02
typedef struct {
	uint8_t		evt_type;
	uint8_t		bdaddr_type;
	bdaddr_t	bdaddr;
	uint8_t		length;
	uint8_t		data[];
} __attribute__ ((packed)) le_advertising_info;
#define LE_ADVERTISING_INFO_SIZE 9

#define EVT_LE_CONN_UPDATE_COMPLETE	0x03
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint16_t	interval;
	uint16_t	latency;
	uint16_t	supervision_timeout;
} __attribute__ ((packed)) evt_le_connection_update_complete;
#define EVT_LE_CONN_UPDATE_COMPLETE_SIZE 9

#define EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE	0x04
typedef struct {
	uint8_t		status;
	uint16_t	handle;
	uint8_t		features[8];
} __attribute__ ((packed)) evt_le_read_remote_used_features_complete;
#define EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE_SIZE 11

#define EVT_LE_LTK_REQUEST	0x05
typedef struct {
	uint16_t	handle;
	uint64_t	random;
	uint16_t	diversifier;
} __attribute__ ((packed)) evt_le_long_term_key_request;
#define EVT_LE_LTK_REQUEST_SIZE 12

#define EVT_LE_REMOTE_CONNECTION_PARAMETER_REQUEST 0x06
typedef struct {
	uint16_t    connection_handle;
	uint16_t    interval_min;
    uint16_t    interval_max;
    uint16_t    max_latency;
    uint16_t    timeout;
} __attribute__ ((packed)) evt_le_remote_connection_parameter_request;
#define EVT_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_SIZE 10

#define EVT_LE_DATA_LENGTH_CHANGE               0x07
typedef struct {
    uint16_t    connection_handle;
    uint16_t    max_tx_octets;
    uint16_t    max_tx_time;
    uint16_t    max_rx_octets;
    uint16_t	max_rx_time;
} __attribute__ ((packed)) evt_le_data_length_change;
#define EVT_LE_DATA_LENGTH_CHANGE_SIZE 10

#define EVT_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE 0x08
typedef struct {
	uint16_t	status;
	uint8_t		key_x_coordinate[32];
	uint8_t		key_y_coordinate[32];
} __attribute__ ((packed)) evt_le_read_local_p_256_public_key_complete;
#define EVT_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE_SIZE 65

#define EVT_LE_GENERATE_DHKEY_COMPLETE 0x09
typedef struct {
    uint16_t    status;
	uint8_t 	dh_key[32];
} __attribute__ ((packed)) evt_le_generate_dhkey_complete;
#define EVT_LE_GENERATE_DHKEY_COMPLETE_SIZE 33

#define EVT_LE_ENHANCED_CONNECTION_COMPLETE_V1 0x0A
typedef struct {
    uint8_t		status;
	uint16_t	connection_handle;
	uint8_t		role;
	uint8_t		peer_address_type;
	bdaddr_t	peer_address;
	bdaddr_t	local_resolvable_private_address;
	bdaddr_t	peer_resolvable_private_address;
	uint16_t	connection_interval;
	uint16_t	peripheral_latency;
	uint16_t	supervision_timeout;
	uint8_t		central_clock_accuracy;
} __attribute__ ((packed)) evt_le_enhanced_connection_complete_v1;
#define EVT_LE_ENHANCED_CONNECTION_COMPLETE_SIZE_V1 33

#define EVT_LE_ENHANCED_CONNECTION_COMPLETE_V2 0x29
typedef struct {
    uint8_t		status;
	uint16_t	connection_handle;
	uint8_t		role;
	uint8_t		peer_address_type;
	bdaddr_t	peer_address;
	bdaddr_t	local_resolvable_private_address;
	bdaddr_t	peer_resolvable_private_address;
	uint16_t	connection_interval;
	uint16_t	peripheral_latency;
	uint16_t	supervision_timeout;
	uint8_t		central_clock_accuracy;
	uint8_t		Advertising_Handle;
	uint16_t	Sync_Handle;
} __attribute__ ((packed)) evt_le_enhanced_connection_complete_v2;
#define EVT_LE_ENHANCED_CONNECTION_COMPLETE_SIZE_V2 33

#define EVT_LE_DIRECTED_ADVERTISING_REPORT 0x0B
typedef struct {
	uint8_t		num_reports;
	uint8_t		event_type[1];
	uint8_t		address_type[1];
	bdaddr_t	address[1];
	uint8_t		direct_address_type[1];
	bdaddr_t	direct_address[1];
	uint8_t		rssi[1];
} __attribute__ ((packed)) evt_le_directed_advertising_report;
#define EVT_LE_DIRECTED_ADVERTISING_REPORT_SIZE 17

#define EVT_LE_PHY_UPDATE_COMPLETE 0x0C
typedef struct {
	uint8_t		status;
	uint16_t	connection_handle;
	uint8_t		tx_phy;
	uint8_t		rx_phy;
} __attribute__ ((packed)) evt_le_phy_update_complete;
#define EVT_LE_PHY_UPDATE_COMPLETE_SIZE 5

#define EVT_LE_EXTENDED_ADVERTISING_REPORT 0x0D
typedef struct {
	uint8_t		num_reports;
	uint16_t	event_type[1];
	uint8_t		address_type[1];
	bdaddr_t	address[1];
	uint8_t		primary_phy[1];
	uint8_t		secondary_phy[1];
	uint8_t		advertising_sid[1];
	uint8_t		tx_power[1];
	uint8_t		rssi[1];
	uint16_t	periodic_advertising_interval[1];
	uint8_t		direct_address_type[1];
	bdaddr_t	direct_address[1];
	uint8_t		data_length[1];
	uint8_t		data[1];
} __attribute__ ((packed)) evt_le_extended_advertising_report;
#define EVT_LE_EXTENDED_ADVERTISING_REPORT_SIZE 26

#define EVT_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V1 0x0E
typedef struct {
	uint8_t		status;
	uint16_t	sync_handle;
	uint8_t		advertising_sid;
	uint8_t		advertiser_address_type;
	bdaddr_t	advertiser_address;
	uint8_t		advertiser_phy;
	uint16_t	periodic_advertising_interval;
	uint8_t		advertiser_clock_accuracy;
} __attribute__ ((packed)) evt_le_periodic_advertising_sync_established_v1;
#define EVT_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_SIZE_V1 15

#define EVT_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V2 0x24
typedef struct {
	uint8_t		status;
	uint16_t	sync_handle;
	uint8_t		advertising_sid;
	uint8_t		advertiser_address_type;
	bdaddr_t	advertiser_address;
	uint8_t		advertiser_phy;
	uint16_t	periodic_advertising_interval;
	uint8_t		advertiser_clock_accuracy;
	uint8_t		num_subevents;
	uint8_t		subevent_interval;
	uint8_t		response_slot_delay;
	uint8_t		response_slot_spacing;
} __attribute__ ((packed)) evt_le_periodic_advertising_sync_established_v2;
#define EVT_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_SIZE_V2 19

#define EVT_LE_PERIODIC_ADVERTISING_REPORT_V1 0x0F
typedef struct {
	uint16_t	sync_handle;
	uint8_t		tx_power;
	uint8_t		rssi;
	uint16_t	cte_type;
	uint8_t		data_status;
	uint8_t		data_length;
	uint8_t		data[1];
} __attribute__ ((packed)) evt_le_periodic_advertising_report_v1;
#define EVT_LE_PERIODIC_ADVERTISING_REPORT_SIZE_V1 9

#define EVT_LE_PERIODIC_ADVERTISING_REPORT_V2 0x25
typedef struct {
	uint16_t	sync_handle;
	uint8_t		tx_power;
	uint8_t		rssi;
	uint16_t	cte_type;
	uint16_t	periodic_event_counter;
	uint8_t		subevent;
	uint8_t		data_status;
	uint8_t		data_length;
	uint8_t		data[1];
} __attribute__ ((packed)) evt_le_periodic_advertising_report_v2;
#define EVT_LE_PERIODIC_ADVERTISING_REPORT_SIZE_V2 12

#define EVT_LE_PERIODIC_ADVERTISING_SYNC_LOST 0x10
typedef struct {
	uint16_t	sync_handle;
} __attribute__ ((packed)) evt_le_periodic_advertising_sync_lost;
#define EVT_LE_PERIODIC_ADVERTISING_SYNC_LOST_SIZE 2

#define EVT_LE_SCAN_TIMEOUT  0x11

#define EVT_LE_ADVERTISING_SET_TERMINATED 0x12
typedef struct {
	uint8_t		status;
	uint8_t		advertising_handle;
	uint16_t	connection_handle;
	uint8_t		num_completed_extended_advertising_events;
} __attribute__ ((packed)) evt_le_advertising_set_terminated;
#define EVT_LE_ADVERTISING_SET_TERMINATED_SIZE 5

#define EVT_LE_SCAN_REQUEST_RECEIVED 0x13
typedef struct {
	uint8_t		advertising_handle;
	uint8_t		scanner_address_type;
	bdaddr_t	scanner_address;
} __attribute__ ((packed)) evt_le_scan_request_received;
#define EVT_LE_SCAN_REQUEST_RECEIVED_SIZE 9

#define EVT_LE_CHANNEL_SELECTION_ALGORITHM 0x14
typedef struct {
	uint16_t	connection_handle;
	uint8_t		channel_selection_algorithm;
} __attribute__ ((packed)) evt_le_channel_selection_algorithm;
#define evt_le_channel_selection_algorithm_size 3

#define EVT_LE_CONNECTIONLESS_IQ_REPORT 0x15
typedef struct {
	uint16_t	sync_handle;
	uint8_t		channel_index;
	uint16_t	rssi;
	uint8_t		rssi_antenna_id;
	uint8_t		cte_type;
	uint8_t		slot_durations;
	uint8_t		packet_status;
	uint16_t	periodic_event_counter;
	uint8_t		sample_count;
	uint8_t		i_sample[1];
	uint8_t		q_sample[1];
} __attribute__ ((packed)) evt_le_connectionless_iq_report;
#define EVT_LE_CONNECTIONLESS_IQ_REPORT_SIZE

#define EVT_LE_CONNECTION_IQ_REPORT 0x16
typedef struct {
	uint16_t	connection_handle;
	uint8_t		rx_phy;
	uint8_t		data_channel_index;
	uint16_t	rssi;
	uint8_t		rssi_antenna_id;
	uint8_t		cte_type;
	uint8_t		slot_durations;
	uint8_t		packet_status;
	uint16_t	connection_event_counter;
	uint8_t		sample_count;
	uint8_t		i_sample[1];
	uint8_t		q_sample[1];
} __attribute__ ((packed)) evt_le_connection_iq_report;
#define EVT_LE_CONNECTION_IQ_REPORT_SIZE

#define EVT_LE_CTE_REQUEST_FAILED 0x17
typedef struct {
	uint8_t		status;
	uint16_t	connection_handle;
} __attribute__ ((packed)) evt_le_cte_request_failed;
#define EVT_LE_CTE_REQUEST_FAILED_SIZE 3

#define EVT_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_V1 0x18
typedef struct {
	uint8_t		status;
	uint16_t	connection_handle;
	uint16_t	service_data;
	uint16_t	sync_handle;
	uint8_t		advertising_sid;
	uint8_t		advertiser_address_type;
	bdaddr_t	advertiser_address;
	uint8_t		advertiser_phy;
	uint16_t	periodic_advertising_interval;
	uint8_t		advertiser_clock_accuracy;
} __attribute__ ((packed)) evt_le_periodic_advertising_sync_transfer_received_v1;
#define EVT_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_SIZE_V1 19

#define EVT_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_V2 0x26
typedef struct {
	uint8_t		status;
	uint16_t	connection_handle;
	uint16_t	service_data;
	uint16_t	sync_handle;
	uint8_t		advertising_sid;
	uint8_t		advertiser_address_type;
	bdaddr_t	advertiser_address;
	uint8_t		advertiser_phy;
	uint16_t	periodic_advertising_interval;
	uint8_t		advertiser_clock_accuracy;
	uint8_t		num_subevents;
	uint8_t		subevent_interval;
	uint8_t		response_slot_delay;
	uint8_t		response_slot_spacing;
} __attribute__ ((packed)) evt_le_periodic_advertising_sync_transfer_received_v2;
#define EVT_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_SIZE_V2 23

#define EVT_LE_CIS_ESTABLISHED 0x19
typedef struct {
	uint8_t		status;
	uint16_t	connection_handle;
	uint24_t	cig_sync_delay;
	uint24_t	cis_sync_delay;
	uint8_t		transport_latency_c_to_p;
	uint8_t		transport_latency_p_to_c;
	uint8_t		phy_c_to_p;
	uint8_t		phy_p_to_c;
	uint8_t		nse;
	uint8_t		bn_c_to_p;
	uint8_t		bn_p_to_c;
	uint8_t		ft_c_to_p;
	uint8_t		ft_p_to_c;
	uint16_t	max_pdu_c_to_p;
	uint16_t	max_pdu_p_to_c;
	uint16_t	iso_interval;
} __attribute__ ((packed)) evt_le_cis_established;
#define EVT_LE_CIS_ESTABLISHED_SIZE 24

#define EVT_LE_CIS_REQUEST 0x1A
typedef struct {
	uint16_t	acl_connection_handle;
	uint16_t	cis_connection_handle;
	uint8_t		cig_id;
	uint8_t		cis_id;
} __attribute__ ((packed)) evt_le_cis_request;
#define EVT_LE_CIS_REQUEST_SIZE 6

#define EVT_LE_CREATE_BIG_COMPLETE 0x1B
typedef struct {
	uint8_t		status;
	uint8_t		big_handle;
	uint24_t	big_sync_delay;
	uint24_t	transport_latency_big;
	uint8_t		phy;
	uint8_t		nse;
	uint8_t		bn;
	uint8_t		pto;
	uint8_t		irc;
	uint16_t	max_pdu;
	uint16_t	iso_interval;
	uint8_t		num_bis;
	uint8_t		connection_handle[1];
} __attribute__ ((packed)) evt_le_create_big_complete;
#define EVT_LE_CREATE_BIG_COMPLETE_SIZE

#define EVT_LE_TERMINATE_BIG_COMPLETE 0x1C
typedef struct {
	uint8_t		big_handle;
	uint8_t		reason;
} __attribute__ ((packed)) evt_le_terminate_big_complete;
#define EVT_LE_TERMINATE_BIG_COMPLETE_SIZE 2

#define EVT_LE_BIG_SYNC_ESTABLISHED 0x1D
typedef struct {
	uint8_t		status;
	uint8_t		big_handle;
	uint24_t	transport_latency_big;
	uint8_t		nse;
	uint8_t		bn;
	uint8_t		pto;
	uint8_t		irc;
	uint16_t	max_pdu;
	uint16_t	iso_interval;
	uint8_t		num_bis;
	uint16_t	connection_handle[1];
} __attribute__ ((packed)) evt_le_big_sync_established;
#define EVT_LE_BIG_SYNC_ESTABLISHED_SIZE

#define EVT_LE_BIG_SYNC_LOST 0x1E
typedef struct {
	uint8_t		big_handle;
	uint8_t		reason;
} __attribute__ ((packed)) evt_le_big_sync_lost;
#define EVT_LE_BIG_SYNC_LOST_SIZE 2

#define EVT_LE_REQUEST_PEER_SCA_COMPLETE 0x1F
typedef struct {
	uint8_t		Status;
	uint16_t	Connection_Handle;
	uint8_t		Peer_Clock_Accuracy;
} __attribute__ ((packed)) evt_le_request_peer_sca_complete;
#define EVT_LE_REQUEST_PEER_SCA_COMPLETE_SIZE 4

#define EVT_LE_PATH_LOSS_THRESHOLD 0x20
typedef struct {
	uint8_t		connection_handle;
	uint8_t		current_path_loss;
	uint8_t		zone_entered;
} __attribute__ ((packed)) evt_le_path_loss_threshold;
#define EVT_LE_PATH_LOSS_THRESHOLD_SIZE 3

#define EVT_LE_TRANSMIT_POWER_REPORTING 0x21
typedef struct {
	uint8_t		Status;
	uint16_t	Connection_Handle;
	uint8_t		Reason;
	uint8_t		PHY;
	uint8_t		TX_Power_Level;
	uint8_t		TX_Power_Level_Flag;
	uint8_t		Delta;
} __attribute__ ((packed)) evt_le_transmit_power_reporting;
#define EVT_LE_TRANSMIT_POWER_REPORTING_SIZE 8

#define EVT_LE_BIGINFO_ADVERTISING_REPORT 0x22
typedef struct {
	uint16_t	sync_handle;
	uint8_t		num_bis;
	uint8_t		nse;
	uint16_t	iso_interval;
	uint8_t		bn;
	uint8_t		pto;
	uint8_t		irc;
	uint16_t	max_pdu;
	uint24_t	sdu_interval;
	uint16_t	max_sdu;
	uint8_t		phy;
	uint8_t		framing;
	uint8_t		encryption;
} __attribute__ ((packed)) evt_le_biginfo_advertising_report;
#define EVT_LE_BIGINFO_ADVERTISING_REPORT_SIZE 19

#define EVT_LE_SUBRATE_CHANGE 0x23
typedef struct {
	uint8_t		status;
	uint16_t	connection_handle;
	uint16_t	subrate_factor;
	uint16_t	peripheral_latency;
	uint16_t	continuation_number;
	uint16_t	supervision_timeout;
} __attribute__ ((packed)) evt_le_subrate_change;
#define EVT_LE_SUBRATE_CHANGE_SIZE 11

#define EVT_LE_PERIODIC_ADVERTISING_SUBEVENT_DATA_REQUEST 0x27
typedef struct {
	uint8_t		advertising_handle;
	uint16_t	subevent_start;
	uint16_t	subevent_data_count;
} __attribute__ ((packed)) evt_le_periodic_advertising_subevent_data_request;
#define EVT_LE_PERIODIC_ADVERTISING_SUBEVENT_DATA_REQUEST_SIZE 5

#define EVT_LE_PERIODIC_ADVERTISING_RESPONSE_REPORT 0x28
typedef struct {
	uint8_t		advertising_handle;
	uint8_t		subevent;
	uint8_t		tx_status;
	uint8_t		num_responses;
	uint8_t		tx_power[1];
	uint8_t		rssi[1];
	uint8_t		cte_type[1];
	uint8_t		response_slot[1];
	uint8_t		data_status[1];
	uint8_t		data_length[1];
	uint8_t		data[1];
} __attribute__ ((packed)) evt_le_periodic_advertising_response_report;
#define EVT_LE_PERIODIC_ADVERTISING_RESPONSE_REPORT_SIZE 11

#define EVT_PHYSICAL_LINK_COMPLETE		0x40
typedef struct {
	uint8_t		status;
	uint8_t		handle;
} __attribute__ ((packed)) evt_physical_link_complete;
#define EVT_PHYSICAL_LINK_COMPLETE_SIZE 2

#define EVT_CHANNEL_SELECTED		0x41

#define EVT_DISCONNECT_PHYSICAL_LINK_COMPLETE	0x42
typedef struct {
	uint8_t		status;
	uint8_t		handle;
	uint8_t		reason;
} __attribute__ ((packed)) evt_disconn_physical_link_complete;
#define EVT_DISCONNECT_PHYSICAL_LINK_COMPLETE_SIZE 3

#define EVT_PHYSICAL_LINK_LOSS_EARLY_WARNING	0x43
typedef struct {
	uint8_t		handle;
	uint8_t		reason;
} __attribute__ ((packed)) evt_physical_link_loss_warning;
#define EVT_PHYSICAL_LINK_LOSS_WARNING_SIZE 2

#define EVT_PHYSICAL_LINK_RECOVERY		0x44
typedef struct {
	uint8_t		handle;
} __attribute__ ((packed)) evt_physical_link_recovery;
#define EVT_PHYSICAL_LINK_RECOVERY_SIZE 1

#define EVT_LOGICAL_LINK_COMPLETE		0x45
typedef struct {
	uint8_t		status;
	uint16_t	log_handle;
	uint8_t		handle;
	uint8_t		tx_flow_id;
} __attribute__ ((packed)) evt_logical_link_complete;
#define EVT_LOGICAL_LINK_COMPLETE_SIZE 5

#define EVT_DISCONNECT_LOGICAL_LINK_COMPLETE	0x46

#define EVT_FLOW_SPEC_MODIFY_COMPLETE		0x47
typedef struct {
	uint8_t		status;
	uint16_t	handle;
} __attribute__ ((packed)) evt_flow_spec_modify_complete;
#define EVT_FLOW_SPEC_MODIFY_COMPLETE_SIZE 3

#define EVT_NUMBER_COMPLETED_BLOCKS		0x48
typedef struct {
	uint16_t		handle;
	uint16_t		num_cmplt_pkts;
	uint16_t		num_cmplt_blks;
} __attribute__ ((packed)) cmplt_handle;
typedef struct {
	uint16_t		total_num_blocks;
	uint8_t			num_handles;
	cmplt_handle		handles[];
}  __attribute__ ((packed)) evt_num_completed_blocks;

#define EVT_AMP_STATUS_CHANGE			0x4D
typedef struct {
	uint8_t		status;
	uint8_t		amp_status;
} __attribute__ ((packed)) evt_amp_status_change;
#define EVT_AMP_STATUS_CHANGE_SIZE 2

#define EVT_TESTING			0xFE

#define EVT_VENDOR			0xFF

/* Internal events generated by BlueZ stack */
#define EVT_STACK_INTERNAL		0xFD
typedef struct {
	uint16_t	type;
	uint8_t		data[];
} __attribute__ ((packed)) evt_stack_internal;
#define EVT_STACK_INTERNAL_SIZE 2

#define EVT_SI_DEVICE	0x01
typedef struct {
	uint16_t	event;
	uint16_t	dev_id;
} __attribute__ ((packed)) evt_si_device;
#define EVT_SI_DEVICE_SIZE 4

/* --------  HCI Packet structures  -------- */
#define HCI_TYPE_LEN	1

typedef struct {
	uint16_t	opcode;		/* OCF & OGF */
	uint8_t		plen;
} __attribute__ ((packed))	hci_command_hdr;
#define HCI_COMMAND_HDR_SIZE	3

typedef struct {
	uint8_t		evt;
	uint8_t		plen;
} __attribute__ ((packed))	hci_event_hdr;
#define HCI_EVENT_HDR_SIZE	2

typedef struct {
	uint16_t	handle;		/* Handle & Flags(PB, BC) */
	uint16_t	dlen;
} __attribute__ ((packed))	hci_acl_hdr;
#define HCI_ACL_HDR_SIZE	4

typedef struct {
	uint16_t	handle;
	uint8_t		dlen;
} __attribute__ ((packed))	hci_sco_hdr;
#define HCI_SCO_HDR_SIZE	3

typedef struct {
	uint16_t	device;
	uint16_t	type;
	uint16_t	plen;
} __attribute__ ((packed))	hci_msg_hdr;
#define HCI_MSG_HDR_SIZE	6

/* Command opcode pack/unpack */
#define cmd_opcode_pack(ogf, ocf)	(uint16_t)((ocf & 0x03ff)|(ogf << 10))
#define cmd_opcode_ogf(op)		(op >> 10)
#define cmd_opcode_ocf(op)		(op & 0x03ff)

/* ACL handle and flags pack/unpack */
#define acl_handle_pack(h, f)	(uint16_t)((h & 0x0fff)|(f << 12))
#define acl_handle(h)		(h & 0x0fff)
#define acl_flags(h)		(h >> 12)

#endif /* _NO_HCI_DEFS */

/* HCI Socket options */
#define HCI_DATA_DIR	1
#define HCI_FILTER	2
#define HCI_TIME_STAMP	3

/* HCI CMSG flags */
#define HCI_CMSG_DIR	0x0001
#define HCI_CMSG_TSTAMP	0x0002

struct sockaddr_hci {
	sa_family_t	hci_family;
	unsigned short	hci_dev;
	unsigned short  hci_channel;
};
#define HCI_DEV_NONE	0xffff

#define HCI_CHANNEL_RAW		0
#define HCI_CHANNEL_USER	1
#define HCI_CHANNEL_MONITOR	2
#define HCI_CHANNEL_CONTROL	3
#define HCI_CHANNEL_LOGGING	4

struct hci_filter {
	uint32_t type_mask;
	uint32_t event_mask[2];
	uint16_t opcode;
};

#define HCI_FLT_TYPE_BITS	31
#define HCI_FLT_EVENT_BITS	63
#define HCI_FLT_OGF_BITS	63
#define HCI_FLT_OCF_BITS	127

/* Ioctl requests structures */
struct hci_dev_stats {
	uint32_t err_rx;
	uint32_t err_tx;
	uint32_t cmd_tx;
	uint32_t evt_rx;
	uint32_t acl_tx;
	uint32_t acl_rx;
	uint32_t sco_tx;
	uint32_t sco_rx;
	uint32_t byte_rx;
	uint32_t byte_tx;
};

struct hci_dev_info {
	uint16_t dev_id;
	char     name[8];

	bdaddr_t bdaddr;

	uint32_t flags;
	uint8_t  type;

	uint8_t  features[8];

	uint32_t pkt_type;
	uint32_t link_policy;
	uint32_t link_mode;

	uint16_t acl_mtu;
	uint16_t acl_pkts;
	uint16_t sco_mtu;
	uint16_t sco_pkts;

	struct   hci_dev_stats stat;
};

struct hci_conn_info {
	uint16_t handle;
	bdaddr_t bdaddr;
	uint8_t  type;
	uint8_t	 out;
	uint16_t state;
	uint32_t link_mode;
};

struct hci_dev_req {
	uint16_t dev_id;
	uint32_t dev_opt;
};

struct hci_dev_list_req {
	uint16_t dev_num;
	struct hci_dev_req dev_req[];	/* hci_dev_req structures */
};

struct hci_conn_list_req {
	uint16_t dev_id;
	uint16_t conn_num;
	struct hci_conn_info conn_info[];
};

struct hci_conn_info_req {
	bdaddr_t bdaddr;
	uint8_t  type;
	struct hci_conn_info conn_info[];
};

struct hci_auth_info_req {
	bdaddr_t bdaddr;
	uint8_t  type;
};

struct hci_inquiry_req {
	uint16_t dev_id;
	uint16_t flags;
	uint8_t  lap[3];
	uint8_t  length;
	uint8_t  num_rsp;
};
#define IREQ_CACHE_FLUSH 0x0001

#ifdef __cplusplus
}
#endif

#endif /* __HCI_H */