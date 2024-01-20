// SPDX-License-Identifier: GPL-2.0-or-later
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "bluetooth.h"
#include "hci.h"
#include "hci_lib.h"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

typedef struct {
	char *str;
	unsigned int val;
} hci_map;

static char *hci_bit2str(hci_map *m, unsigned int val)
{
	char *str = malloc(120);
	char *ptr = str;

	if (!str)
		return NULL;

	*ptr = 0;
	while (m->str) {
		if ((unsigned int) m->val & val)
			ptr += sprintf(ptr, "%s ", m->str);
		m++;
	}
	return str;
}

static int hci_str2bit(hci_map *map, char *str, unsigned int *val)
{
	char *t, *ptr;
	hci_map *m;
	int set;

	if (!str || !(str = ptr = strdup(str)))
		return 0;

	*val = set = 0;

	while ((t = strsep(&ptr, ","))) {
		for (m = map; m->str; m++) {
			if (!strcasecmp(m->str, t)) {
				*val |= (unsigned int) m->val;
				set = 1;
			}
		}
	}
	free(str);

	return set;
}

static char *hci_uint2str(hci_map *m, unsigned int val)
{
	char *str = malloc(50);
	char *ptr = str;

	if (!str)
		return NULL;

	*ptr = 0;
	while (m->str) {
		if ((unsigned int) m->val == val) {
			ptr += sprintf(ptr, "%s", m->str);
			break;
		}
		m++;
	}
	return str;
}

static int hci_str2uint(hci_map *map, char *str, unsigned int *val)
{
	char *t, *ptr;
	hci_map *m;
	int set = 0;

	if (!str)
		return 0;

	str = ptr = strdup(str);

	while ((t = strsep(&ptr, ","))) {
		for (m = map; m->str; m++) {
			if (!strcasecmp(m->str,t)) {
				*val = (unsigned int) m->val;
				set = 1;
				break;
			}
		}
	}
	free(str);

	return set;
}

char *hci_bustostr(int bus)
{
	switch (bus) {
	case HCI_VIRTUAL:
		return "Virtual";
	case HCI_USB:
		return "USB";
	case HCI_PCCARD:
		return "PCCARD";
	case HCI_UART:
		return "UART";
	case HCI_RS232:
		return "RS232";
	case HCI_PCI:
		return "PCI";
	case HCI_SDIO:
		return "SDIO";
	case HCI_SPI:
		return "SPI";
	case HCI_I2C:
		return "I2C";
	case HCI_SMD:
		return "SMD";
	case HCI_VIRTIO:
		return "VIRTIO";
	default:
		return "Unknown";
	}
}

char *hci_dtypetostr(int type)
{
	return hci_bustostr(type & 0x0f);
}

char *hci_typetostr(int type)
{
	switch (type) {
	case HCI_PRIMARY:
		return "Primary";
	case HCI_AMP:
		return "AMP";
	default:
		return "Unknown";
	}
}

/* HCI dev flags mapping */
static hci_map dev_flags_map[] = {
	{ "UP",      HCI_UP      },
	{ "INIT",    HCI_INIT    },
	{ "RUNNING", HCI_RUNNING },
	{ "RAW",     HCI_RAW     },
	{ "PSCAN",   HCI_PSCAN   },
	{ "ISCAN",   HCI_ISCAN   },
	{ "INQUIRY", HCI_INQUIRY },
	{ "AUTH",    HCI_AUTH    },
	{ "ENCRYPT", HCI_ENCRYPT },
	{ NULL }
};

char *hci_dflagstostr(uint32_t flags)
{
	char *str = bt_malloc(50);
	char *ptr = str;
	hci_map *m = dev_flags_map;

	if (!str)
		return NULL;

	*ptr = 0;

	if (!hci_test_bit(HCI_UP, &flags))
		ptr += sprintf(ptr, "DOWN ");

	while (m->str) {
		if (hci_test_bit(m->val, &flags))
			ptr += sprintf(ptr, "%s ", m->str);
		m++;
	}
	return str;
}

/* HCI packet type mapping */
static hci_map pkt_type_map[] = {
	{ "DM1",   HCI_DM1  },
	{ "DM3",   HCI_DM3  },
	{ "DM5",   HCI_DM5  },
	{ "DH1",   HCI_DH1  },
	{ "DH3",   HCI_DH3  },
	{ "DH5",   HCI_DH5  },
	{ "HV1",   HCI_HV1  },
	{ "HV2",   HCI_HV2  },
	{ "HV3",   HCI_HV3  },
	{ "2-DH1", HCI_2DH1 },
	{ "2-DH3", HCI_2DH3 },
	{ "2-DH5", HCI_2DH5 },
	{ "3-DH1", HCI_3DH1 },
	{ "3-DH3", HCI_3DH3 },
	{ "3-DH5", HCI_3DH5 },
	{ NULL }
};

static hci_map sco_ptype_map[] = {
	{ "HV1",   0x0001   },
	{ "HV2",   0x0002   },
	{ "HV3",   0x0004   },
	{ "EV3",   HCI_EV3  },
	{ "EV4",   HCI_EV4  },
	{ "EV5",   HCI_EV5  },
	{ "2-EV3", HCI_2EV3 },
	{ "2-EV5", HCI_2EV5 },
	{ "3-EV3", HCI_3EV3 },
	{ "3-EV5", HCI_3EV5 },
	{ NULL }
};

char *hci_ptypetostr(unsigned int ptype)
{
	return hci_bit2str(pkt_type_map, ptype);
}

int hci_strtoptype(char *str, unsigned int *val)
{
	return hci_str2bit(pkt_type_map, str, val);
}

char *hci_scoptypetostr(unsigned int ptype)
{
	return hci_bit2str(sco_ptype_map, ptype);
}

int hci_strtoscoptype(char *str, unsigned int *val)
{
	return hci_str2bit(sco_ptype_map, str, val);
}

/* Link policy mapping */
static hci_map link_policy_map[] = {
	{ "NONE",	0		},
	{ "RSWITCH",	HCI_LP_RSWITCH	},
	{ "HOLD",	HCI_LP_HOLD	},
	{ "SNIFF",	HCI_LP_SNIFF	},
	{ "PARK",	HCI_LP_PARK	},
	{ NULL }
};

char *hci_lptostr(unsigned int lp)
{
	return hci_bit2str(link_policy_map, lp);
}

int hci_strtolp(char *str, unsigned int *val)
{
	return hci_str2bit(link_policy_map, str, val);
}

/* Link mode mapping */
static hci_map link_mode_map[] = {
	{ "NONE",	0		},
	{ "ACCEPT",	HCI_LM_ACCEPT	},
	{ "CENTRAL",	HCI_LM_MASTER	},
	{ "AUTH",	HCI_LM_AUTH	},
	{ "ENCRYPT",	HCI_LM_ENCRYPT	},
	{ "TRUSTED",	HCI_LM_TRUSTED	},
	{ "RELIABLE",	HCI_LM_RELIABLE	},
	{ "SECURE",	HCI_LM_SECURE	},
	{ NULL }
};

char *hci_lmtostr(unsigned int lm)
{
	char *s, *str = bt_malloc(50);
	if (!str)
		return NULL;

	*str = 0;
	if (!(lm & HCI_LM_MASTER))
		strcpy(str, "PERIPHERAL ");

	s = hci_bit2str(link_mode_map, lm);
	if (!s) {
		bt_free(str);
		return NULL;
	}

	strcat(str, s);
	free(s);
	return str;
}

int hci_strtolm(char *str, unsigned int *val)
{
	int ret = hci_str2bit(link_mode_map, str, val);

	/* Deprecated name. Kept for compatibility. */
	if (!!str && strcasestr(str, "MASTER")) {
		ret = 1;
		*val |= HCI_LM_MASTER;
	}

	return ret;
}

/* Command mapping */
static hci_map commands_map[] = {
	{ "Inquiry",					0   },
	{ "Inquiry Cancel",				1   },
	{ "Periodic Inquiry Mode",			2   },
	{ "Exit Periodic Inquiry Mode",			3   },
	{ "Create Connection",				4   },
	{ "Disconnect",					5   },
	{ "Add SCO Connection",				6   },
	{ "Cancel Create Connection",			7   },

	{ "Accept Connection Request",			8   },
	{ "Reject Connection Request",			9   },
	{ "Link Key Request Reply",			10  },
	{ "Link Key Request Negative Reply",		11  },
	{ "PIN Code Request Reply",			12  },
	{ "PIN Code Request Negative Reply",		13  },
	{ "Change Connection Packet Type",		14  },
	{ "Authentication Requested",			15  },

	{ "Set Connection Encryption",			16  },
	{ "Change Connection Link Key",			17  },
	{ "Temporary Link Key",				18  },
	{ "Remote Name Request",			19  },
	{ "Cancel Remote Name Request",			20  },
	{ "Read Remote Supported Features",		21  },
	{ "Read Remote Extended Features",		22  },
	{ "Read Remote Version Information",		23  },

	{ "Read Clock Offset",				24  },
	{ "Read LMP Handle",				25  },
	{ "Reserved",					26  },
	{ "Reserved",					27  },
	{ "Reserved",					28  },
	{ "Reserved",					29  },
	{ "Reserved",					30  },
	{ "Reserved",					31  },

	{ "Reserved",					32  },
	{ "Hold Mode",					33  },
	{ "Sniff Mode",					34  },
	{ "Exit Sniff Mode",				35  },
	{ "Park State",					36  },
	{ "Exit Park State",				37  },
	{ "QoS Setup",					38  },
	{ "Role Discovery",				39  },

	{ "Switch Role",				40  },
	{ "Read Link Policy Settings",			41  },
	{ "Write Link Policy Settings",			42  },
	{ "Read Default Link Policy Settings",		43  },
	{ "Write Default Link Policy Settings",		44  },
	{ "Flow Specification",				45  },
	{ "Set Event Mask",				46  },
	{ "Reset",					47  },

	{ "Set Event Filter",				48  },
	{ "Flush",					49  },
	{ "Read PIN Type",				50  },
	{ "Write PIN Type",				51  },
	{ "Create New Unit Key",			52  },
	{ "Read Stored Link Key",			53  },
	{ "Write Stored Link Key",			54  },
	{ "Delete Stored Link Key",			55  },

	{ "Write Local Name",				56  },
	{ "Read Local Name",				57  },
	{ "Read Connection Accept Timeout",		58  },
	{ "Write Connection Accept Timeout",		59  },
	{ "Read Page Timeout",				60  },
	{ "Write Page Timeout",				61  },
	{ "Read Scan Enable",				62  },
	{ "Write Scan Enable",				63  },

	{ "Read Page Scan Activity",			64  },
	{ "Write Page Scan Activity",			65  },
	{ "Read Inquiry Scan Activity",			66  },
	{ "Write Inquiry Scan Activity",		67  },
	{ "Read Authentication Enable",			68  },
	{ "Write Authentication Enable",		69  },
	{ "Read Encryption Mode",			70  },
	{ "Write Encryption Mode",			71  },

	{ "Read Class Of Device",			72  },
	{ "Write Class Of Device",			73  },
	{ "Read Voice Setting",				74  },
	{ "Write Voice Setting",			75  },
	{ "Read Automatic Flush Timeout",		76  },
	{ "Write Automatic Flush Timeout",		77  },
	{ "Read Num Broadcast Retransmissions",		78  },
	{ "Write Num Broadcast Retransmissions",	79  },

	{ "Read Hold Mode Activity",			80  },
	{ "Write Hold Mode Activity",			81  },
	{ "Read Transmit Power Level",			82  },
	{ "Read Synchronous Flow Control Enable",	83  },
	{ "Write Synchronous Flow Control Enable",	84  },
	{ "Set Host Controller To Host Flow Control",	85  },
	{ "Host Buffer Size",				86  },
	{ "Host Number Of Completed Packets",		87  },

	{ "Read Link Supervision Timeout",		88  },
	{ "Write Link Supervision Timeout",		89  },
	{ "Read Number of Supported IAC",		90  },
	{ "Read Current IAC LAP",			91  },
	{ "Write Current IAC LAP",			92  },
	{ "Read Page Scan Period Mode",			93  },
	{ "Write Page Scan Period Mode",		94  },
	{ "Read Page Scan Mode",			95  },

	{ "Write Page Scan Mode",			96  },
	{ "Set AFH Channel Classification",		97  },
	{ "Reserved",					98  },
	{ "Reserved",					99  },
	{ "Read Inquiry Scan Type",			100 },
	{ "Write Inquiry Scan Type",			101 },
	{ "Read Inquiry Mode",				102 },
	{ "Write Inquiry Mode",				103 },

	{ "Read Page Scan Type",			104 },
	{ "Write Page Scan Type",			105 },
	{ "Read AFH Channel Assessment Mode",		106 },
	{ "Write AFH Channel Assessment Mode",		107 },
	{ "Reserved",					108 },
	{ "Reserved",					109 },
	{ "Reserved",					110 },
	{ "Reserved",					111 },

	{ "Reserved",					112 },
	{ "Reserved",					113 },
	{ "Reserved",					114 },
	{ "Read Local Version Information",		115 },
	{ "Read Local Supported Commands",		116 },
	{ "Read Local Supported Features",		117 },
	{ "Read Local Extended Features",		118 },
	{ "Read Buffer Size",				119 },

	{ "Read Country Code",				120 },
	{ "Read BD ADDR",				121 },
	{ "Read Failed Contact Counter",		122 },
	{ "Reset Failed Contact Counter",		123 },
	{ "Get Link Quality",				124 },
	{ "Read RSSI",					125 },
	{ "Read AFH Channel Map",			126 },
	{ "Read BD Clock",				127 },

	{ "Read Loopback Mode",				128 },
	{ "Write Loopback Mode",			129 },
	{ "Enable Device Under Test Mode",		130 },
	{ "Setup Synchronous Connection",		131 },
	{ "Accept Synchronous Connection",		132 },
	{ "Reject Synchronous Connection",		133 },
	{ "Reserved",					134 },
	{ "Reserved",					135 },

	{ "Read Extended Inquiry Response",		136 },
	{ "Write Extended Inquiry Response",		137 },
	{ "Refresh Encryption Key",			138 },
	{ "Reserved",					139 },
	{ "Sniff Subrating",				140 },
	{ "Read Simple Pairing Mode",			141 },
	{ "Write Simple Pairing Mode",			142 },
	{ "Read Local OOB Data",			143 },

	{ "Read Inquiry Response Transmit Power Level",	144 },
	{ "Write Inquiry Transmit Power Level",		145 },
	{ "Read Default Erroneous Data Reporting",	146 },
	{ "Write Default Erroneous Data Reporting",	147 },
	{ "Reserved",					148 },
	{ "Reserved",					149 },
	{ "Reserved",					150 },
	{ "IO Capability Request Reply",		151 },

	{ "User Confirmation Request Reply",		152 },
	{ "User Confirmation Request Negative Reply",	153 },
	{ "User Passkey Request Reply",			154 },
	{ "User Passkey Request Negative Reply",	155 },
	{ "Remote OOB Data Request Reply",		156 },
	{ "Write Simple Pairing Debug Mode",		157 },
	{ "Enhanced Flush",				158 },
	{ "Remote OOB Data Request Negative Reply",	159 },

	{ "Reserved",					160 },
	{ "Reserved",					161 },
	{ "Send Keypress Notification",			162 },
	{ "IO Capability Request Negative Reply",	163 },
	{ "Read Encryption Key Size",			164 },
	{ "Reserved",					165 },
	{ "Reserved",					166 },
	{ "Reserved",					167 },

	{ "Create Physical Link",			168 },
	{ "Accept Physical Link",			169 },
	{ "Disconnect Physical Link",			170 },
	{ "Create Logical Link",			171 },
	{ "Accept Logical Link",			172 },
	{ "Disconnect Logical Link",			173 },
	{ "Logical Link Cancel",			174 },
	{ "Flow Specification Modify",			175 },

	{ "Read Logical Link Accept Timeout",		176 },
	{ "Write Logical Link Accept Timeout",		177 },
	{ "Set Event Mask Page 2",			178 },
	{ "Read Location Data",				179 },
	{ "Write Location Data",			180 },
	{ "Read Local AMP Info",			181 },
	{ "Read Local AMP_ASSOC",			182 },
	{ "Write Remote AMP_ASSOC",			183 },

	{ "Read Flow Control Mode",			184 },
	{ "Write Flow Control Mode",			185 },
	{ "Read Data Block Size",			186 },
	{ "Reserved",					187 },
	{ "Reserved",					188 },
	{ "Enable AMP Receiver Reports",		189 },
	{ "AMP Test End",				190 },
	{ "AMP Test Command",				191 },

	{ "Read Enhanced Transmit Power Level",		192 },
	{ "Reserved",					193 },
	{ "Read Best Effort Flush Timeout",		194 },
	{ "Write Best Effort Flush Timeout",		195 },
	{ "Short Range Mode",				196 },
	{ "Read LE Host Support",			197 },
	{ "Write LE Host Support",			198 },
	{ "Reserved",					199 },

	{ "LE Set Event Mask",				200 },
	{ "LE Read Buffer Size",			201 },
	{ "LE Read Local Supported Features",		202 },
	{ "Reserved",					203 },
	{ "LE Set Random Address",			204 },
	{ "LE Set Advertising Parameters",		205 },
	{ "LE Read Advertising Channel TX Power",	206 },
	{ "LE Set Advertising Data",			207 },

	{ "LE Set Scan Response Data",			208 },
	{ "LE Set Advertise Enable",			209 },
	{ "LE Set Scan Parameters",			210 },
	{ "LE Set Scan Enable",				211 },
	{ "LE Create Connection",			212 },
	{ "LE Create Connection Cancel",		213 },
	{ "LE Read Accept List Size",			214 },
	{ "LE Clear Accept List",			215 },

	{ "LE Add Device To Accept List",		216 },
	{ "LE Remove Device From Accept List",		217 },
	{ "LE Connection Update",			218 },
	{ "LE Set Host Channel Classification",		219 },
	{ "LE Read Channel Map",			220 },
	{ "LE Read Remote Used Features",		221 },
	{ "LE Encrypt",					222 },
	{ "LE Rand",					223 },

	{ "LE Start Encryption",			224 },
	{ "LE Long Term Key Request Reply",		225 },
	{ "LE Long Term Key Request Negative Reply",	226 },
	{ "LE Read Supported States",			227 },
	{ "LE Receiver Test",				228 },
	{ "LE Transmitter Test",			229 },
	{ "LE Test End",				230 },
	{ "Reserved",					231 },

	{ NULL }
};

char *hci_cmdtostr(unsigned int cmd)
{
	return hci_uint2str(commands_map, cmd);
}

char *hci_commandstostr(uint8_t *commands, char *pref, int width)
{
	unsigned int maxwidth = width - 3;
	hci_map *m;
	char *off, *ptr, *str;
	int size = 10;

	m = commands_map;

	while (m->str) {
		if (commands[m->val / 8] & (1 << (m->val % 8)))
			size += strlen(m->str) + (pref ? strlen(pref) : 0) + 3;
		m++;
	}

	str = bt_malloc(size);
	if (!str)
		return NULL;

	ptr = str; *ptr = '\0';

	if (pref)
		ptr += sprintf(ptr, "%s", pref);

	off = ptr;

	m = commands_map;

	while (m->str) {
		if (commands[m->val / 8] & (1 << (m->val % 8))) {
			if (strlen(off) + strlen(m->str) > maxwidth) {
				ptr += sprintf(ptr, "\n%s", pref ? pref : "");
				off = ptr;
			}
			ptr += sprintf(ptr, "'%s' ", m->str);
		}
		m++;
	}

	return str;
}

/* Version mapping */
static hci_map ver_map[] = {
	{ "1.0b",	0x00 },
	{ "1.1",	0x01 },
	{ "1.2",	0x02 },
	{ "2.0",	0x03 },
	{ "2.1",	0x04 },
	{ "3.0",	0x05 },
	{ "4.0",	0x06 },
	{ "4.1",	0x07 },
	{ "4.2",	0x08 },
	{ "5.0",	0x09 },
	{ "5.1",	0x0a },
	{ "5.2",	0x0b },
	{ NULL }
};

char *hci_vertostr(unsigned int ver)
{
	return hci_uint2str(ver_map, ver);
}

int hci_strtover(char *str, unsigned int *ver)
{
	return hci_str2uint(ver_map, str, ver);
}

char *lmp_vertostr(unsigned int ver)
{
	return hci_uint2str(ver_map, ver);
}

int lmp_strtover(char *str, unsigned int *ver)
{
	return hci_str2uint(ver_map, str, ver);
}

static hci_map pal_map[] = {
	{ "3.0",	0x01 },
	{ NULL }
};

char *pal_vertostr(unsigned int ver)
{
	return hci_uint2str(pal_map, ver);
}

int pal_strtover(char *str, unsigned int *ver)
{
	return hci_str2uint(pal_map, str, ver);
}

/* LMP features mapping */
static hci_map lmp_features_map[8][9] = {
	{	/* Byte 0 */
		{ "<3-slot packets>",	LMP_3SLOT	},	/* Bit 0 */
		{ "<5-slot packets>",	LMP_5SLOT	},	/* Bit 1 */
		{ "<encryption>",	LMP_ENCRYPT	},	/* Bit 2 */
		{ "<slot offset>",	LMP_SOFFSET	},	/* Bit 3 */
		{ "<timing accuracy>",	LMP_TACCURACY	},	/* Bit 4 */
		{ "<role switch>",	LMP_RSWITCH	},	/* Bit 5 */
		{ "<hold mode>",	LMP_HOLD	},	/* Bit 6 */
		{ "<sniff mode>",	LMP_SNIFF	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 1 */
		{ "<park state>",	LMP_PARK	},	/* Bit 0 */
		{ "<RSSI>",		LMP_RSSI	},	/* Bit 1 */
		{ "<channel quality>",	LMP_QUALITY	},	/* Bit 2 */
		{ "<SCO link>",		LMP_SCO		},	/* Bit 3 */
		{ "<HV2 packets>",	LMP_HV2		},	/* Bit 4 */
		{ "<HV3 packets>",	LMP_HV3		},	/* Bit 5 */
		{ "<u-law log>",	LMP_ULAW	},	/* Bit 6 */
		{ "<A-law log>",	LMP_ALAW	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 2 */
		{ "<CVSD>",		LMP_CVSD	},	/* Bit 0 */
		{ "<paging scheme>",	LMP_PSCHEME	},	/* Bit 1 */
		{ "<power control>",	LMP_PCONTROL	},	/* Bit 2 */
		{ "<transparent SCO>",	LMP_TRSP_SCO	},	/* Bit 3 */
		{ "<broadcast encrypt>",LMP_BCAST_ENC	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 3 */
		{ "<no. 24>",		0x01		},	/* Bit 0 */
		{ "<EDR ACL 2 Mbps>",	LMP_EDR_ACL_2M	},	/* Bit 1 */
		{ "<EDR ACL 3 Mbps>",	LMP_EDR_ACL_3M	},	/* Bit 2 */
		{ "<enhanced iscan>",	LMP_ENH_ISCAN	},	/* Bit 3 */
		{ "<interlaced iscan>",	LMP_ILACE_ISCAN	},	/* Bit 4 */
		{ "<interlaced pscan>",	LMP_ILACE_PSCAN	},	/* Bit 5 */
		{ "<inquiry with RSSI>",LMP_RSSI_INQ	},	/* Bit 6 */
		{ "<extended SCO>",	LMP_ESCO	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 4 */
		{ "<EV4 packets>",	LMP_EV4		},	/* Bit 0 */
		{ "<EV5 packets>",	LMP_EV5		},	/* Bit 1 */
		{ "<no. 34>",		0x04		},	/* Bit 2 */
		{ "<AFH cap. perip.>",	LMP_AFH_CAP_SLV	},	/* Bit 3 */
		{ "<AFH cls. perip.>",	LMP_AFH_CLS_SLV	},	/* Bit 4 */
		{ "<BR/EDR not supp.>",	LMP_NO_BREDR	},	/* Bit 5 */
		{ "<LE support>",	LMP_LE		},	/* Bit 6 */
		{ "<3-slot EDR ACL>",	LMP_EDR_3SLOT	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 5 */
		{ "<5-slot EDR ACL>",	LMP_EDR_5SLOT	},	/* Bit 0 */
		{ "<sniff subrating>",	LMP_SNIFF_SUBR	},	/* Bit 1 */
		{ "<pause encryption>",	LMP_PAUSE_ENC	},	/* Bit 2 */
		{ "<AFH cap. central>",	LMP_AFH_CAP_MST	},	/* Bit 3 */
		{ "<AFH cls. central>", LMP_AFH_CLS_MST	},	/* Bit 4 */
		{ "<EDR eSCO 2 Mbps>",	LMP_EDR_ESCO_2M	},	/* Bit 5 */
		{ "<EDR eSCO 3 Mbps>",	LMP_EDR_ESCO_3M	},	/* Bit 6 */
		{ "<3-slot EDR eSCO>",	LMP_EDR_3S_ESCO	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 6 */
		{ "<extended inquiry>",	LMP_EXT_INQ	},	/* Bit 0 */
		{ "<LE and BR/EDR>",	LMP_LE_BREDR	},	/* Bit 1 */
		{ "<no. 50>",		0x04		},	/* Bit 2 */
		{ "<simple pairing>",	LMP_SIMPLE_PAIR	},	/* Bit 3 */
		{ "<encapsulated PDU>",	LMP_ENCAPS_PDU	},	/* Bit 4 */
		{ "<err. data report>",	LMP_ERR_DAT_REP	},	/* Bit 5 */
		{ "<non-flush flag>",	LMP_NFLUSH_PKTS	},	/* Bit 6 */
		{ "<no. 55>",		0x80		},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 7 */
		{ "<LSTO>",		LMP_LSTO	},	/* Bit 1 */
		{ "<inquiry TX power>",	LMP_INQ_TX_PWR	},	/* Bit 1 */
		{ "<EPC>",		LMP_EPC		},	/* Bit 2 */
		{ "<no. 59>",		0x08		},	/* Bit 3 */
		{ "<no. 60>",		0x10		},	/* Bit 4 */
		{ "<no. 61>",		0x20		},	/* Bit 5 */
		{ "<no. 62>",		0x40		},	/* Bit 6 */
		{ "<extended features>",LMP_EXT_FEAT	},	/* Bit 7 */
		{ NULL }
	},
};

char *lmp_featurestostr(uint8_t *features, char *pref, int width)
{
	unsigned int maxwidth = width - 1;
	char *off, *ptr, *str;
	int i, size = 10;

	for (i = 0; i < 8; i++) {
		hci_map *m = lmp_features_map[i];

		while (m->str) {
			if (m->val & features[i])
				size += strlen(m->str) +
						(pref ? strlen(pref) : 0) + 1;
			m++;
		}
	}

	str = bt_malloc(size);
	if (!str)
		return NULL;

	ptr = str; *ptr = '\0';

	if (pref)
		ptr += sprintf(ptr, "%s", pref);

	off = ptr;

	for (i = 0; i < 8; i++) {
		hci_map *m = lmp_features_map[i];

		while (m->str) {
			if (m->val & features[i]) {
				if (strlen(off) + strlen(m->str) > maxwidth) {
					ptr += sprintf(ptr, "\n%s",
							pref ? pref : "");
					off = ptr;
				}
				ptr += sprintf(ptr, "%s ", m->str);
			}
			m++;
		}
	}

	return str;
}

/* HCI functions that do not require open device */
int hci_for_each_dev(int flag, int (*func)(int dd, int dev_id, long arg),
			long arg)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int dev_id = -1;
	int i, sk, err = 0;

	sk = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (sk < 0)
		return -1;

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		err = errno;
		goto done;
	}

	memset(dl, 0, HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, (void *) dl) < 0) {
		err = errno;
		goto free;
	}

	for (i = 0; i < dl->dev_num; i++, dr++) {
		if (hci_test_bit(flag, &dr->dev_opt))
			if (!func || func(sk, dr->dev_id, arg)) {
				dev_id = dr->dev_id;
				break;
			}
	}

	if (dev_id < 0)
		err = ENODEV;

free:
	free(dl);

done:
	close(sk);
	errno = err;

	return dev_id;
}

static int __other_bdaddr(int dd, int dev_id, long arg)
{
	struct hci_dev_info di = { .dev_id = dev_id };

	if (ioctl(dd, HCIGETDEVINFO, (void *) &di))
		return 0;

	if (hci_test_bit(HCI_RAW, &di.flags))
		return 0;

	return bacmp((bdaddr_t *) arg, &di.bdaddr);
}

static int __same_bdaddr(int dd, int dev_id, long arg)
{
	struct hci_dev_info di = { .dev_id = dev_id };

	if (ioctl(dd, HCIGETDEVINFO, (void *) &di))
		return 0;

	return !bacmp((bdaddr_t *) arg, &di.bdaddr);
}

int hci_get_route(bdaddr_t *bdaddr)
{
	int dev_id;

	dev_id = hci_for_each_dev(HCI_UP, __other_bdaddr,
				(long) (bdaddr ? bdaddr : BDADDR_ANY));
	if (dev_id < 0)
		dev_id = hci_for_each_dev(HCI_UP, __same_bdaddr,
				(long) (bdaddr ? bdaddr : BDADDR_ANY));

	return dev_id;
}

int hci_devid(const char *str)
{
	bdaddr_t ba;
	int id = -1;

	if (!strncmp(str, "hci", 3) && strlen(str) >= 4) {
		id = atoi(str + 3);
		if (hci_devba(id, &ba) < 0)
			return -1;
	} else {
		errno = ENODEV;
		str2ba(str, &ba);
		id = hci_for_each_dev(HCI_UP, __same_bdaddr, (long) &ba);
	}

	return id;
}

int hci_devinfo(int dev_id, struct hci_dev_info *di)
{
	int dd, err, ret;

	dd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (dd < 0)
		return dd;

	memset(di, 0, sizeof(struct hci_dev_info));

	di->dev_id = dev_id;
	ret = ioctl(dd, HCIGETDEVINFO, (void *) di);

	err = errno;
	close(dd);
	errno = err;

	return ret;
}

int hci_devba(int dev_id, bdaddr_t *bdaddr)
{
	struct hci_dev_info di;

	memset(&di, 0, sizeof(di));

	if (hci_devinfo(dev_id, &di))
		return -1;

	if (!hci_test_bit(HCI_UP, &di.flags)) {
		errno = ENETDOWN;
		return -1;
	}

	bacpy(bdaddr, &di.bdaddr);

	return 0;
}

int hci_inquiry(int dev_id, int len, int nrsp, const uint8_t *lap,
		inquiry_info **ii, long flags)
{
	struct hci_inquiry_req *ir;
	uint8_t num_rsp = nrsp;
	void *buf;
	int dd, size, err, ret = -1;

	if (nrsp <= 0) {
		num_rsp = 0;
		nrsp = 255;
	}

	if (dev_id < 0) {
		dev_id = hci_get_route(NULL);
		if (dev_id < 0) {
			errno = ENODEV;
			return -1;
		}
	}

	dd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (dd < 0)
		return dd;

	buf = malloc(sizeof(*ir) + (sizeof(inquiry_info) * (nrsp)));
	if (!buf)
		goto done;

	ir = buf;
	ir->dev_id  = dev_id;
	ir->num_rsp = num_rsp;
	ir->length  = len;
	ir->flags   = flags;

	if (lap) {
		memcpy(ir->lap, lap, 3);
	} else {
		ir->lap[0] = 0x33;
		ir->lap[1] = 0x8b;
		ir->lap[2] = 0x9e;
	}

	ret = ioctl(dd, HCIINQUIRY, (unsigned long) buf);
	if (ret < 0)
		goto free;

	size = sizeof(inquiry_info) * ir->num_rsp;

	if (!*ii)
		*ii = malloc(size);

	if (*ii) {
		memcpy((void *) *ii, buf + sizeof(*ir), size);
		ret = ir->num_rsp;
	} else
		ret = -1;

free:
	free(buf);

done:
	err = errno;
	close(dd);
	errno = err;

	return ret;
}

/* Open HCI device.
 * Returns device descriptor (dd). */
int hci_open_dev(int dev_id)
{
	struct sockaddr_hci a;
	int dd, err;

	/* Check for valid device id */
	if (dev_id < 0) {
		errno = ENODEV;
		return -1;
	}

	/* Create HCI socket */
	dd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (dd < 0)
		return dd;

	/* Bind socket to the HCI device */
	memset(&a, 0, sizeof(a));
	a.hci_family = AF_BLUETOOTH;
	a.hci_dev = dev_id;
	if (bind(dd, (struct sockaddr *) &a, sizeof(a)) < 0)
		goto failed;

	return dd;

failed:
	err = errno;
	close(dd);
	errno = err;

	return -1;
}

int hci_close_dev(int dd)
{
	return close(dd);
}

/* HCI functions that require open device
 * dd - Device descriptor returned by hci_open_dev. */

int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, uint8_t plen, void *param)
{
	uint8_t type = HCI_COMMAND_PKT;
	hci_command_hdr hc;
	struct iovec iv[3];
	int ivn;

	hc.opcode = htobs(cmd_opcode_pack(ogf, ocf));
	hc.plen= plen;

	iv[0].iov_base = &type;
	iv[0].iov_len  = 1;
	iv[1].iov_base = &hc;
	iv[1].iov_len  = HCI_COMMAND_HDR_SIZE;
	ivn = 2;

	if (plen) {
		iv[2].iov_base = param;
		iv[2].iov_len  = plen;
		ivn = 3;
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int hci_send_req(int dd, struct hci_request *r, int to)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	uint16_t opcode = htobs(cmd_opcode_pack(r->ogf, r->ocf));
	struct hci_filter nf, of;
	socklen_t olen;
	hci_event_hdr *hdr;
	int err, try;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
		return -1;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
	hci_filter_set_event(EVT_CMD_STATUS, &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	hci_filter_set_event(r->event, &nf);
	hci_filter_set_opcode(opcode, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
		return -1;

	if (hci_send_cmd(dd, r->ogf, r->ocf, r->clen, r->cparam) < 0)
		goto failed;

	try = 10;
	while (try--) {
		evt_cmd_complete *cc;
		evt_cmd_status *cs;
		evt_remote_name_req_complete *rn;
		evt_le_meta_event *me;
		remote_name_req_cp *cp;
		int len;

		if (to) {
			struct pollfd p;
			int n;

			p.fd = dd; p.events = POLLIN;
			while ((n = poll(&p, 1, to)) < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;
				goto failed;
			}

			if (!n) {
				errno = ETIMEDOUT;
				goto failed;
			}

			to -= 10;
			if (to < 0)
				to = 0;

		}

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto failed;
		}

		hdr = (void *) (buf + 1);
		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		switch (hdr->evt) {
		case EVT_CMD_STATUS:
			cs = (void *) ptr;

			if (cs->opcode != opcode)
				continue;

			if (r->event != EVT_CMD_STATUS) {
				if (cs->status) {
					errno = EIO;
					goto failed;
				}
				break;
			}

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;

		case EVT_CMD_COMPLETE:
			cc = (void *) ptr;

			if (cc->opcode != opcode)
				continue;

			ptr += EVT_CMD_COMPLETE_SIZE;
			len -= EVT_CMD_COMPLETE_SIZE;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;

		case EVT_REMOTE_NAME_REQ_COMPLETE:
			if (hdr->evt != r->event)
				break;

			rn = (void *) ptr;
			cp = r->cparam;

			if (bacmp(&rn->bdaddr, &cp->bdaddr))
				continue;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;

		case EVT_LE_META_EVENT:
			me = (void *) ptr;

			if (me->subevent != r->event)
				continue;

			len -= 1;
			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, me->data, r->rlen);
			goto done;

		default:
			if (hdr->evt != r->event)
				break;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;
		}
	}
	errno = ETIMEDOUT;

failed:
	err = errno;
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of)) < 0)
		err = errno;
	errno = err;
	return -1;

done:
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of)) < 0)
		return -1;
	return 0;
}

int hci_reset_dev(int dd)
{
	struct hci_request rq;
    uint8_t status;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_RESET;
	rq.rparam = &status;
	rq.rlen   = 1;

	if (hci_send_req(dd, &rq, 1000) < 0)  // default timeout is 1000
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;

}
int hci_create_connection(int dd, const bdaddr_t *bdaddr, uint16_t ptype,
				uint16_t clkoffset, uint8_t rswitch,
				uint16_t *handle, int to)
{
	evt_conn_complete rp;
	create_conn_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.pkt_type       = ptype;
	cp.pscan_rep_mode = 0x02;
	cp.clock_offset   = clkoffset;
	cp.role_switch    = rswitch;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_CREATE_CONN;
	rq.event  = EVT_CONN_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = CREATE_CONN_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CONN_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*handle = rp.handle;
	return 0;
}

int hci_disconnect(int dd, uint16_t handle, uint8_t reason, int to)
{
	evt_disconn_complete rp;
	disconnect_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;
	cp.reason = reason;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_DISCONNECT;
	rq.event  = EVT_DISCONN_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = DISCONNECT_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_DISCONN_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}
	return 0;
}

int hci_le_add_white_list(int dd, const bdaddr_t *bdaddr, uint8_t type, int to)
{
	struct hci_request rq;
	le_add_device_to_white_list_cp cp;
	uint8_t status;

	memset(&cp, 0, sizeof(cp));
	cp.bdaddr_type = type;
	bacpy(&cp.bdaddr, bdaddr);

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_ADD_DEVICE_TO_WHITE_LIST;
	rq.cparam = &cp;
	rq.clen = LE_ADD_DEVICE_TO_WHITE_LIST_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_rm_white_list(int dd, const bdaddr_t *bdaddr, uint8_t type, int to)
{
	struct hci_request rq;
	le_remove_device_from_white_list_cp cp;
	uint8_t status;

	memset(&cp, 0, sizeof(cp));
	cp.bdaddr_type = type;
	bacpy(&cp.bdaddr, bdaddr);

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST;
	rq.cparam = &cp;
	rq.clen = LE_REMOVE_DEVICE_FROM_WHITE_LIST_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_read_white_list_size(int dd, uint8_t *size, int to)
{
	struct hci_request rq;
	le_read_white_list_size_rp rp;

	memset(&rp, 0, sizeof(rp));
	memset(&rq, 0, sizeof(rq));

	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_READ_WHITE_LIST_SIZE;
	rq.rparam = &rp;
	rq.rlen = LE_READ_WHITE_LIST_SIZE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (size)
		*size = rp.size;

	return 0;
}

int hci_le_clear_white_list(int dd, int to)
{
	struct hci_request rq;
	uint8_t status;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_CLEAR_WHITE_LIST;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_add_resolving_list(int dd, const bdaddr_t *bdaddr, uint8_t type,
				uint8_t *peer_irk, uint8_t *local_irk, int to)
{
	struct hci_request rq;
	le_add_device_to_resolv_list_cp cp;
	uint8_t status;

	memset(&cp, 0, sizeof(cp));
	cp.bdaddr_type = type;
	bacpy(&cp.bdaddr, bdaddr);
	if (peer_irk)
		memcpy(cp.peer_irk, peer_irk, 16);
	if (local_irk)
		memcpy(cp.local_irk, local_irk, 16);

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_ADD_DEVICE_TO_RESOLV_LIST;
	rq.cparam = &cp;
	rq.clen = LE_ADD_DEVICE_TO_RESOLV_LIST_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_rm_resolving_list(int dd, const bdaddr_t *bdaddr, uint8_t type, int to)
{
	struct hci_request rq;
	le_remove_device_from_resolv_list_cp cp;
	uint8_t status;

	memset(&cp, 0, sizeof(cp));
	cp.bdaddr_type = type;
	bacpy(&cp.bdaddr, bdaddr);

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST;
	rq.cparam = &cp;
	rq.clen = LE_REMOVE_DEVICE_FROM_RESOLV_LIST_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_clear_resolving_list(int dd, int to)
{
	struct hci_request rq;
	uint8_t status;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_CLEAR_RESOLV_LIST;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_read_resolving_list_size(int dd, uint8_t *size, int to)
{
	struct hci_request rq;
	le_read_resolv_list_size_rp rp;

	memset(&rp, 0, sizeof(rp));
	memset(&rq, 0, sizeof(rq));

	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_READ_RESOLV_LIST_SIZE;
	rq.rparam = &rp;
	rq.rlen = LE_READ_RESOLV_LIST_SIZE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (size)
		*size = rp.size;

	return 0;
}

int hci_le_set_address_resolution_enable(int dd, uint8_t enable, int to)
{
	struct hci_request rq;
	le_set_address_resolution_enable_cp cp;
	uint8_t status;

	memset(&cp, 0, sizeof(cp));
	cp.enable = enable;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_ADDRESS_RESOLUTION_ENABLE;
	rq.cparam = &cp;
	rq.clen = LE_SET_ADDRESS_RESOLUTION_ENABLE_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_local_name(int dd, int len, char *name, int to)
{
	read_local_name_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_LOCAL_NAME;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_NAME_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	rp.name[247] = '\0';
	strncpy(name, (char *) rp.name, len);
	return 0;
}

int hci_write_local_name(int dd, const char *name, int to)
{
	change_local_name_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	strncpy((char *) cp.name, name, sizeof(cp.name) - 1);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_CHANGE_LOCAL_NAME;
	rq.cparam = &cp;
	rq.clen   = CHANGE_LOCAL_NAME_CP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	return 0;
}

int hci_read_remote_name_with_clock_offset(int dd, const bdaddr_t *bdaddr,
						uint8_t pscan_rep_mode,
						uint16_t clkoffset,
						int len, char *name, int to)
{
	evt_remote_name_req_complete rn;
	remote_name_req_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.pscan_rep_mode = pscan_rep_mode;
	cp.clock_offset   = clkoffset;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_REMOTE_NAME_REQ;
	rq.cparam = &cp;
	rq.clen   = REMOTE_NAME_REQ_CP_SIZE;
	rq.event  = EVT_REMOTE_NAME_REQ_COMPLETE;
	rq.rparam = &rn;
	rq.rlen   = EVT_REMOTE_NAME_REQ_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rn.status) {
		errno = EIO;
		return -1;
	}

	rn.name[247] = '\0';
	strncpy(name, (char *) rn.name, len);
	return 0;
}

int hci_read_remote_name(int dd, const bdaddr_t *bdaddr, int len, char *name,
				int to)
{
	return hci_read_remote_name_with_clock_offset(dd, bdaddr, 0x02, 0x0000,
							len, name, to);
}

int hci_read_remote_name_cancel(int dd, const bdaddr_t *bdaddr, int to)
{
	remote_name_req_cancel_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_REMOTE_NAME_REQ_CANCEL;
	rq.cparam = &cp;
	rq.clen   = REMOTE_NAME_REQ_CANCEL_CP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	return 0;
}

int hci_read_remote_version(int dd, uint16_t handle, struct hci_version *ver,
				int to)
{
	evt_read_remote_version_complete rp;
	read_remote_version_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_READ_REMOTE_VERSION;
	rq.event  = EVT_READ_REMOTE_VERSION_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = READ_REMOTE_VERSION_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_READ_REMOTE_VERSION_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	ver->manufacturer = btohs(rp.manufacturer);
	ver->lmp_ver      = rp.lmp_ver;
	ver->lmp_subver   = btohs(rp.lmp_subver);
	return 0;
}

int hci_read_remote_features(int dd, uint16_t handle, uint8_t *features, int to)
{
	evt_read_remote_features_complete rp;
	read_remote_features_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_READ_REMOTE_FEATURES;
	rq.event  = EVT_READ_REMOTE_FEATURES_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = READ_REMOTE_FEATURES_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_READ_REMOTE_FEATURES_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (features)
		memcpy(features, rp.features, 8);

	return 0;
}

int hci_read_remote_ext_features(int dd, uint16_t handle, uint8_t page,
					uint8_t *max_page, uint8_t *features,
					int to)
{
	evt_read_remote_ext_features_complete rp;
	read_remote_ext_features_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle   = handle;
	cp.page_num = page;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_READ_REMOTE_EXT_FEATURES;
	rq.event  = EVT_READ_REMOTE_EXT_FEATURES_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = READ_REMOTE_EXT_FEATURES_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_READ_REMOTE_EXT_FEATURES_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (max_page)
		*max_page = rp.max_page_num;

	if (features)
		memcpy(features, rp.features, 8);

	return 0;
}

int hci_read_clock_offset(int dd, uint16_t handle, uint16_t *clkoffset, int to)
{
	evt_read_clock_offset_complete rp;
	read_clock_offset_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_READ_CLOCK_OFFSET;
	rq.event  = EVT_READ_CLOCK_OFFSET_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = READ_CLOCK_OFFSET_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_READ_CLOCK_OFFSET_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*clkoffset = rp.clock_offset;
	return 0;
}

int hci_read_local_version(int dd, struct hci_version *ver, int to)
{
	read_local_version_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_INFO_PARAM;
	rq.ocf    = OCF_READ_LOCAL_VERSION;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_VERSION_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	ver->manufacturer = btohs(rp.manufacturer);
	ver->hci_ver      = rp.hci_ver;
	ver->hci_rev      = btohs(rp.hci_rev);
	ver->lmp_ver      = rp.lmp_ver;
	ver->lmp_subver   = btohs(rp.lmp_subver);
	return 0;
}

int hci_read_local_commands(int dd, uint8_t *commands, int to)
{
	read_local_commands_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_INFO_PARAM;
	rq.ocf    = OCF_READ_LOCAL_COMMANDS;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_COMMANDS_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (commands)
		memcpy(commands, rp.commands, 64);

	return 0;
}

int hci_read_local_features(int dd, uint8_t *features, int to)
{
	read_local_features_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_INFO_PARAM;
	rq.ocf    = OCF_READ_LOCAL_FEATURES;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_FEATURES_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (features)
		memcpy(features, rp.features, 8);

	return 0;
}

int hci_read_local_ext_features(int dd, uint8_t page, uint8_t *max_page,
				uint8_t *features, int to)
{
	read_local_ext_features_cp cp;
	read_local_ext_features_rp rp;
	struct hci_request rq;

	cp.page_num = page;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_INFO_PARAM;
	rq.ocf    = OCF_READ_LOCAL_EXT_FEATURES;
	rq.cparam = &cp;
	rq.clen   = READ_LOCAL_EXT_FEATURES_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_EXT_FEATURES_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (max_page)
		*max_page = rp.max_page_num;

	if (features)
		memcpy(features, rp.features, 8);

	return 0;
}

int hci_read_bd_addr(int dd, bdaddr_t *bdaddr, int to)
{
	read_bd_addr_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_INFO_PARAM;
	rq.ocf    = OCF_READ_BD_ADDR;
	rq.rparam = &rp;
	rq.rlen   = READ_BD_ADDR_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (bdaddr)
		bacpy(bdaddr, &rp.bdaddr);

	return 0;
}

int hci_read_class_of_dev(int dd, uint8_t *cls, int to)
{
	read_class_of_dev_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_CLASS_OF_DEV;
	rq.rparam = &rp;
	rq.rlen   = READ_CLASS_OF_DEV_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	memcpy(cls, rp.dev_class, 3);
	return 0;
}

int hci_write_class_of_dev(int dd, uint32_t cls, int to)
{
	write_class_of_dev_cp cp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	cp.dev_class[0] = cls & 0xff;
	cp.dev_class[1] = (cls >> 8) & 0xff;
	cp.dev_class[2] = (cls >> 16) & 0xff;
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_CLASS_OF_DEV;
	rq.cparam = &cp;
	rq.clen   = WRITE_CLASS_OF_DEV_CP_SIZE;
	return hci_send_req(dd, &rq, to);
}

int hci_read_voice_setting(int dd, uint16_t *vs, int to)
{
	read_voice_setting_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_VOICE_SETTING;
	rq.rparam = &rp;
	rq.rlen   = READ_VOICE_SETTING_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*vs = rp.voice_setting;
	return 0;
}

int hci_write_voice_setting(int dd, uint16_t vs, int to)
{
	write_voice_setting_cp cp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	cp.voice_setting = vs;
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_VOICE_SETTING;
	rq.cparam = &cp;
	rq.clen   = WRITE_VOICE_SETTING_CP_SIZE;

	return hci_send_req(dd, &rq, to);
}

int hci_read_current_iac_lap(int dd, uint8_t *num_iac, uint8_t *lap, int to)
{
	read_current_iac_lap_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_CURRENT_IAC_LAP;
	rq.rparam = &rp;
	rq.rlen   = READ_CURRENT_IAC_LAP_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*num_iac = rp.num_current_iac;
	memcpy(lap, rp.lap, rp.num_current_iac * 3);
	return 0;
}

int hci_write_current_iac_lap(int dd, uint8_t num_iac, uint8_t *lap, int to)
{
	write_current_iac_lap_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.num_current_iac = num_iac;
	memcpy(&cp.lap, lap, num_iac * 3);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_CURRENT_IAC_LAP;
	rq.cparam = &cp;
	rq.clen   = num_iac * 3 + 1;

	return hci_send_req(dd, &rq, to);
}

int hci_read_stored_link_key(int dd, bdaddr_t *bdaddr, uint8_t all, int to)
{
	read_stored_link_key_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.read_all = all;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_STORED_LINK_KEY;
	rq.cparam = &cp;
	rq.clen   = READ_STORED_LINK_KEY_CP_SIZE;

	return hci_send_req(dd, &rq, to);
}

int hci_write_stored_link_key(int dd, bdaddr_t *bdaddr, uint8_t *key, int to)
{
	unsigned char cp[WRITE_STORED_LINK_KEY_CP_SIZE + 6 + 16];
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp[0] = 1;
	bacpy((bdaddr_t *) (cp + 1), bdaddr);
	memcpy(cp + 7, key, 16);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_STORED_LINK_KEY;
	rq.cparam = &cp;
	rq.clen   = WRITE_STORED_LINK_KEY_CP_SIZE + 6 + 16;

	return hci_send_req(dd, &rq, to);
}

int hci_delete_stored_link_key(int dd, bdaddr_t *bdaddr, uint8_t all, int to)
{
	delete_stored_link_key_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.delete_all = all;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_DELETE_STORED_LINK_KEY;
	rq.cparam = &cp;
	rq.clen   = DELETE_STORED_LINK_KEY_CP_SIZE;

	return hci_send_req(dd, &rq, to);
}

int hci_authenticate_link(int dd, uint16_t handle, int to)
{
	auth_requested_cp cp;
	evt_auth_complete rp;
	struct hci_request rq;

	cp.handle = handle;

	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.event  = EVT_AUTH_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_AUTH_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_encrypt_link(int dd, uint16_t handle, uint8_t encrypt, int to)
{
	set_conn_encrypt_cp cp;
	evt_encrypt_change rp;
	struct hci_request rq;

	cp.handle  = handle;
	cp.encrypt = encrypt;

	rq.ogf     = OGF_LINK_CTL;
	rq.ocf     = OCF_SET_CONN_ENCRYPT;
	rq.event   = EVT_ENCRYPT_CHANGE;
	rq.cparam  = &cp;
	rq.clen    = SET_CONN_ENCRYPT_CP_SIZE;
	rq.rparam  = &rp;
	rq.rlen    = EVT_ENCRYPT_CHANGE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_change_link_key(int dd, uint16_t handle, int to)
{
	change_conn_link_key_cp cp;
	evt_change_conn_link_key_complete rp;
	struct hci_request rq;

	cp.handle = handle;

	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_CHANGE_CONN_LINK_KEY;
	rq.event  = EVT_CHANGE_CONN_LINK_KEY_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = CHANGE_CONN_LINK_KEY_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CHANGE_CONN_LINK_KEY_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_switch_role(int dd, bdaddr_t *bdaddr, uint8_t role, int to)
{
	switch_role_cp cp;
	evt_role_change rp;
	struct hci_request rq;

	bacpy(&cp.bdaddr, bdaddr);
	cp.role   = role;
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_SWITCH_ROLE;
	rq.cparam = &cp;
	rq.clen   = SWITCH_ROLE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_ROLE_CHANGE_SIZE;
	rq.event  = EVT_ROLE_CHANGE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_park_mode(int dd, uint16_t handle, uint16_t max_interval,
			uint16_t min_interval, int to)
{
	park_mode_cp cp;
	evt_mode_change rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof (cp));
	cp.handle       = handle;
	cp.max_interval = max_interval;
	cp.min_interval = min_interval;

	memset(&rq, 0, sizeof (rq));
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_PARK_MODE;
	rq.event  = EVT_MODE_CHANGE;
	rq.cparam = &cp;
	rq.clen   = PARK_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_MODE_CHANGE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_exit_park_mode(int dd, uint16_t handle, int to)
{
	exit_park_mode_cp cp;
	evt_mode_change rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof (cp));
	cp.handle = handle;

	memset (&rq, 0, sizeof (rq));
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_EXIT_PARK_MODE;
	rq.event  = EVT_MODE_CHANGE;
	rq.cparam = &cp;
	rq.clen   = EXIT_PARK_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_MODE_CHANGE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_inquiry_scan_type(int dd, uint8_t *type, int to)
{
	read_inquiry_scan_type_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_INQUIRY_SCAN_TYPE;
	rq.rparam = &rp;
	rq.rlen   = READ_INQUIRY_SCAN_TYPE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*type = rp.type;
	return 0;
}

int hci_write_inquiry_scan_type(int dd, uint8_t type, int to)
{
	write_inquiry_scan_type_cp cp;
	write_inquiry_scan_type_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.type = type;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_INQUIRY_SCAN_TYPE;
	rq.cparam = &cp;
	rq.clen   = WRITE_INQUIRY_SCAN_TYPE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_INQUIRY_SCAN_TYPE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_inquiry_mode(int dd, uint8_t *mode, int to)
{
	read_inquiry_mode_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_INQUIRY_MODE;
	rq.rparam = &rp;
	rq.rlen   = READ_INQUIRY_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*mode = rp.mode;
	return 0;
}

int hci_write_inquiry_mode(int dd, uint8_t mode, int to)
{
	write_inquiry_mode_cp cp;
	write_inquiry_mode_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_INQUIRY_MODE;
	rq.cparam = &cp;
	rq.clen   = WRITE_INQUIRY_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_INQUIRY_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_afh_mode(int dd, uint8_t *mode, int to)
{
	read_afh_mode_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_AFH_MODE;
	rq.rparam = &rp;
	rq.rlen   = READ_AFH_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*mode = rp.mode;
	return 0;
}

int hci_write_afh_mode(int dd, uint8_t mode, int to)
{
	write_afh_mode_cp cp;
	write_afh_mode_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_AFH_MODE;
	rq.cparam = &cp;
	rq.clen   = WRITE_AFH_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_AFH_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_ext_inquiry_response(int dd, uint8_t *fec, uint8_t *data, int to)
{
	read_ext_inquiry_response_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_EXT_INQUIRY_RESPONSE;
	rq.rparam = &rp;
	rq.rlen   = READ_EXT_INQUIRY_RESPONSE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*fec = rp.fec;
	memcpy(data, rp.data, HCI_MAX_EIR_LENGTH);

	return 0;
}

int hci_write_ext_inquiry_response(int dd, uint8_t fec, uint8_t *data, int to)
{
	write_ext_inquiry_response_cp cp;
	write_ext_inquiry_response_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.fec = fec;
	memcpy(cp.data, data, HCI_MAX_EIR_LENGTH);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_EXT_INQUIRY_RESPONSE;
	rq.cparam = &cp;
	rq.clen   = WRITE_EXT_INQUIRY_RESPONSE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_EXT_INQUIRY_RESPONSE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_simple_pairing_mode(int dd, uint8_t *mode, int to)
{
	read_simple_pairing_mode_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_SIMPLE_PAIRING_MODE;
	rq.rparam = &rp;
	rq.rlen   = READ_SIMPLE_PAIRING_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*mode = rp.mode;
	return 0;
}

int hci_write_simple_pairing_mode(int dd, uint8_t mode, int to)
{
	write_simple_pairing_mode_cp cp;
	write_simple_pairing_mode_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_SIMPLE_PAIRING_MODE;
	rq.cparam = &cp;
	rq.clen   = WRITE_SIMPLE_PAIRING_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_SIMPLE_PAIRING_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_local_oob_data(int dd, uint8_t *hash, uint8_t *randomizer, int to)
{
	read_local_oob_data_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_LOCAL_OOB_DATA;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_OOB_DATA_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	memcpy(hash, rp.hash, 16);
	memcpy(randomizer, rp.randomizer, 16);
	return 0;
}

int hci_read_inq_response_tx_power_level(int dd, int8_t *level, int to)
{
	read_inq_response_tx_power_level_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL;
	rq.rparam = &rp;
	rq.rlen   = READ_INQ_RESPONSE_TX_POWER_LEVEL_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*level = rp.level;
	return 0;
}

int hci_read_inquiry_transmit_power_level(int dd, int8_t *level, int to)
{
	return hci_read_inq_response_tx_power_level(dd, level, to);
}

int hci_write_inquiry_transmit_power_level(int dd, int8_t level, int to)
{
	write_inquiry_transmit_power_level_cp cp;
	write_inquiry_transmit_power_level_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.level = level;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_INQUIRY_TRANSMIT_POWER_LEVEL;
	rq.cparam = &cp;
	rq.clen   = WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_transmit_power_level(int dd, uint16_t handle, uint8_t type,
					int8_t *level, int to)
{
	read_transmit_power_level_cp cp;
	read_transmit_power_level_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;
	cp.type   = type;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_TRANSMIT_POWER_LEVEL;
	rq.cparam = &cp;
	rq.clen   = READ_TRANSMIT_POWER_LEVEL_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = READ_TRANSMIT_POWER_LEVEL_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*level = rp.level;
	return 0;
}

int hci_read_link_policy(int dd, uint16_t handle, uint16_t *policy, int to)
{
	read_link_policy_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_READ_LINK_POLICY;
	rq.cparam = &handle;
	rq.clen   = 2;
	rq.rparam = &rp;
	rq.rlen   = READ_LINK_POLICY_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*policy = rp.policy;
	return 0;
}

int hci_write_link_policy(int dd, uint16_t handle, uint16_t policy, int to)
{
	write_link_policy_cp cp;
	write_link_policy_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;
	cp.policy = policy;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_WRITE_LINK_POLICY;
	rq.cparam = &cp;
	rq.clen   = WRITE_LINK_POLICY_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_LINK_POLICY_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_link_supervision_timeout(int dd, uint16_t handle,
					uint16_t *timeout, int to)
{
	read_link_supervision_timeout_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_LINK_SUPERVISION_TIMEOUT;
	rq.cparam = &handle;
	rq.clen   = 2;
	rq.rparam = &rp;
	rq.rlen   = READ_LINK_SUPERVISION_TIMEOUT_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*timeout = rp.timeout;
	return 0;
}

int hci_write_link_supervision_timeout(int dd, uint16_t handle,
					uint16_t timeout, int to)
{
	write_link_supervision_timeout_cp cp;
	write_link_supervision_timeout_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle  = handle;
	cp.timeout = timeout;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_LINK_SUPERVISION_TIMEOUT;
    rq.event  = EVT_CMD_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = WRITE_LINK_SUPERVISION_TIMEOUT_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_LINK_SUPERVISION_TIMEOUT_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_set_afh_classification(int dd, uint8_t *map, int to)
{
	set_afh_classification_cp cp;
	set_afh_classification_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	memcpy(cp.map, map, 10);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_SET_AFH_CLASSIFICATION;
	rq.cparam = &cp;
	rq.clen   = SET_AFH_CLASSIFICATION_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = SET_AFH_CLASSIFICATION_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_link_quality(int dd, uint16_t handle, uint8_t *link_quality,
				int to)
{
	read_link_quality_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_STATUS_PARAM;
	rq.ocf    = OCF_READ_LINK_QUALITY;
	rq.cparam = &handle;
	rq.clen   = 2;
	rq.rparam = &rp;
	rq.rlen   = READ_LINK_QUALITY_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*link_quality = rp.link_quality;
	return 0;
}

int hci_read_rssi(int dd, uint16_t handle, int8_t *rssi, int to)
{
	read_rssi_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_STATUS_PARAM;
	rq.ocf    = OCF_READ_RSSI;
	rq.cparam = &handle;
	rq.clen   = 2;
	rq.rparam = &rp;
	rq.rlen   = READ_RSSI_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*rssi = rp.rssi;
	return 0;
}

int hci_read_afh_map(int dd, uint16_t handle, uint8_t *mode, uint8_t *map,
			int to)
{
	read_afh_map_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_STATUS_PARAM;
	rq.ocf    = OCF_READ_AFH_MAP;
	rq.cparam = &handle;
	rq.clen   = 2;
	rq.rparam = &rp;
	rq.rlen   = READ_AFH_MAP_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*mode = rp.mode;
	memcpy(map, rp.map, 10);
	return 0;
}

int hci_read_clock(int dd, uint16_t handle, uint8_t which, uint32_t *clock,
			uint16_t *accuracy, int to)
{
	read_clock_cp cp;
	read_clock_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle      = handle;
	cp.which_clock = which;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_STATUS_PARAM;
	rq.ocf    = OCF_READ_CLOCK;
	rq.cparam = &cp;
	rq.clen   = READ_CLOCK_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = READ_CLOCK_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*clock    = rp.clock;
	*accuracy = rp.accuracy;
	return 0;
}

int hci_le_set_scan_enable(int dd, uint8_t enable, uint8_t filter_dup, int to)
{
	struct hci_request rq;
	le_set_scan_enable_cp scan_cp;
	uint8_t status;

	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = enable;
	scan_cp.filter_dup = filter_dup;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_SCAN_ENABLE;
	rq.cparam = &scan_cp;
	rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_set_scan_parameters(int dd, uint8_t type,
					uint16_t interval, uint16_t window,
					uint8_t own_type, uint8_t filter, int to)
{
	struct hci_request rq;
	le_set_scan_parameters_cp param_cp;
	uint8_t status;

	memset(&param_cp, 0, sizeof(param_cp));
	param_cp.type = type;
	param_cp.interval = interval;
	param_cp.window = window;
	param_cp.own_bdaddr_type = own_type;
	param_cp.filter = filter;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_SCAN_PARAMETERS;
	rq.cparam = &param_cp;
	rq.clen = LE_SET_SCAN_PARAMETERS_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_set_advertise_enable(int dd, uint8_t enable, int to)
{
	struct hci_request rq;
	le_set_advertise_enable_cp adv_cp;
	uint8_t status;

	memset(&adv_cp, 0, sizeof(adv_cp));
	adv_cp.enable = enable;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
	rq.cparam = &adv_cp;
	rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_create_conn(int dd, uint16_t interval, uint16_t window,
		uint8_t initiator_filter, uint8_t peer_bdaddr_type,
		bdaddr_t peer_bdaddr, uint8_t own_bdaddr_type,
		uint16_t min_interval, uint16_t max_interval,
		uint16_t latency, uint16_t supervision_timeout,
		uint16_t min_ce_length, uint16_t max_ce_length,
		uint16_t *handle, int to)
{
	struct hci_request rq;
	le_create_connection_cp create_conn_cp;
	evt_le_connection_complete conn_complete_rp;

	memset(&create_conn_cp, 0, sizeof(create_conn_cp));
	create_conn_cp.interval = interval;
	create_conn_cp.window = window;
	create_conn_cp.initiator_filter = initiator_filter;
	create_conn_cp.peer_bdaddr_type = peer_bdaddr_type;
	create_conn_cp.peer_bdaddr = peer_bdaddr;
	create_conn_cp.own_bdaddr_type = own_bdaddr_type;
	create_conn_cp.min_interval = min_interval;
	create_conn_cp.max_interval = max_interval;
	create_conn_cp.latency = latency;
	create_conn_cp.supervision_timeout = supervision_timeout;
	create_conn_cp.min_ce_length = min_ce_length;
	create_conn_cp.max_ce_length = max_ce_length;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_CREATE_CONN;
	rq.event = EVT_LE_CONN_COMPLETE;
	rq.cparam = &create_conn_cp;
	rq.clen = LE_CREATE_CONN_CP_SIZE;
	rq.rparam = &conn_complete_rp;
	rq.rlen = EVT_CONN_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (conn_complete_rp.status) {
		errno = EIO;
		return -1;
	}

	if (handle)
		*handle = conn_complete_rp.handle;

	return 0;
}

int hci_le_conn_update(int dd, uint16_t handle, uint16_t min_interval,
			uint16_t max_interval, uint16_t latency,
			uint16_t supervision_timeout, int to)
{
	evt_le_connection_update_complete evt;
	le_connection_update_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;
	cp.min_interval = min_interval;
	cp.max_interval = max_interval;
	cp.latency = latency;
	cp.supervision_timeout = supervision_timeout;
	cp.min_ce_length = htobs(0x0001);
	cp.max_ce_length = htobs(0x0001);

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_CONN_UPDATE;
	rq.cparam = &cp;
	rq.clen = LE_CONN_UPDATE_CP_SIZE;
	rq.event = EVT_LE_CONN_UPDATE_COMPLETE;
	rq.rparam = &evt;
	rq.rlen = sizeof(evt);

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (evt.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_read_remote_features(int dd, uint16_t handle, uint8_t *features, int to)
{
	evt_le_read_remote_used_features_complete rp;
	le_read_remote_used_features_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_REMOTE_USED_FEATURES;
	rq.event  = EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = LE_READ_REMOTE_USED_FEATURES_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	if (features)
		memcpy(features, rp.features, 8);

	return 0;
}

/* HCI LE cmd api start
 * 1. the input args is in command list,
 * 2  if the input include array, the array shoule memory valid, api will not check the array size.
 * 2  If the reply only reply status, it will use struct le_common_rp to store
 * 3. If the reply include more data, use special data structure to handle and return
  */
static int devfd, timeout = 1000;

void hci_set_device_fd(int dd)
{
    devfd = dd;
}

void hci_clear_device_fd(int dd)
{
    devfd = 0;
}

int hci_le_cmd_set_event_mask(uint8_t * mask, le_common_rp * common_rp)
{
	le_set_event_mask_cp cp;
	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EVENT_MASK;

    memcpy(cp.mask, mask, LE_SET_EVENT_MASK_CP_SIZE);
	rq.event  = 0;
    rq.cparam = &cp;
	rq.clen   = sizeof(cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_read_buffer_size(le_read_buffer_size_rp* reply)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_BUFFER_SIZE;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_buffer_size_rp);

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_read_buffer_size_v2(le_read_buffer_size_v2_rp* reply)
{
	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_BUFFER_SIZE_V2;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_buffer_size_v2_rp);

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_read_local_supported_features(le_read_local_supported_features_rp * reply)
{
	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_LOCAL_SUPPORTED_FEATURES;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen = sizeof(le_read_local_supported_features_rp);

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_random_address(bdaddr_t * p_bdaddr, le_common_rp * common_rp)
{
    le_set_random_address_cp cmd_param;
	struct hci_request rq;

    memcpy(&cmd_param.bdaddr, p_bdaddr, sizeof(bdaddr_t));
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_RANDOM_ADDRESS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_advertising_parameters(uint16_t min_interval, uint16_t max_interval,
            uint8_t advtype, uint8_t own_bdaddr_type, uint8_t direct_bdaddr_type,
            bdaddr_t * direct_bdaddr, uint8_t chan_map, uint8_t filter, le_common_rp * common_rp)
{
    le_set_advertising_parameters_cp cmd_param;
	struct hci_request rq;

    cmd_param.min_interval = min_interval;
    cmd_param.max_interval = max_interval;
    cmd_param.advtype = advtype;
    cmd_param.own_bdaddr_type = own_bdaddr_type;
    cmd_param.direct_bdaddr_type = direct_bdaddr_type;
    memcpy(&cmd_param.direct_bdaddr, direct_bdaddr, sizeof(bdaddr_t));
    cmd_param.chan_map = chan_map;
    cmd_param.filter = filter;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_ADVERTISING_PARAMETERS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_read_advertising_physical_channel_tx_power(le_read_advertising_channel_tx_power_rp * reply)
{
	struct hci_request rq;


	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_ADVERTISING_PARAMETERS;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_advertising_channel_tx_power_rp);

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_advertising_data(uint8_t length, uint8_t	* data, le_common_rp * common_rp)
{
    le_set_advertising_data_cp cmd_param;
	struct hci_request rq;
    cmd_param.length = length;
    memcpy(&cmd_param.data, data, length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_SCAN_RESPONSE_DATA;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = length + 1;  //length and data
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_scan_response_data(uint8_t length, uint8_t * data, le_common_rp * common_rp)
{
    le_set_scan_response_data_cp cmd_param;
	struct hci_request rq;

    cmd_param.length = length;
    memcpy(&cmd_param.data, data, length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_SCAN_RESPONSE_DATA;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = length + 1;  //length and data
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_advertising_enable(uint8_t enable, le_common_rp * common_rp)
{
    le_set_advertise_enable_cp cmd_param;
	struct hci_request rq;

    cmd_param.enable = enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_ADVERTISE_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_scan_parameters(uint8_t type, uint16_t interval, uint16_t window,
        uint8_t own_bdaddr_type, uint8_t filter, le_common_rp * common_rp)
{
    le_set_scan_parameters_cp cmd_param;
	struct hci_request rq;

    cmd_param.type = type;
    cmd_param.interval = interval;
    cmd_param.window = window;
    cmd_param.own_bdaddr_type = own_bdaddr_type;
    cmd_param.filter = filter;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_SCAN_PARAMETERS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_scan_enable(uint8_t enable, uint8_t filter_dup, le_common_rp * common_rp)
{
    le_set_scan_enable_cp cmd_param;
	struct hci_request rq;

    cmd_param.enable = enable;
    cmd_param.filter_dup = filter_dup;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_SCAN_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_create_connection(uint16_t interval, uint16_t window, uint8_t initiator_filter,
        uint8_t peer_bdaddr_type, bdaddr_t * peer_bdaddr, uint8_t own_bdaddr_type,
        uint16_t min_interval, uint16_t max_interval, uint16_t latency, uint16_t supervision_timeout,
        uint16_t min_ce_length, uint16_t max_ce_length, le_common_rp * common_rp)
{
    le_create_connection_cp cmd_param;

	struct hci_request rq;

    cmd_param.interval = interval;
    cmd_param.window = window;
    cmd_param.initiator_filter = initiator_filter;
    cmd_param.peer_bdaddr_type = peer_bdaddr_type;
    memcpy(&cmd_param.peer_bdaddr, peer_bdaddr, sizeof(bdaddr_t));
    cmd_param.own_bdaddr_type = own_bdaddr_type;
    cmd_param.min_interval = min_interval;
    cmd_param.max_interval = max_interval;
    cmd_param.latency = latency;
    cmd_param.supervision_timeout = supervision_timeout;
    cmd_param.min_ce_length = min_ce_length;
    cmd_param.max_ce_length = max_ce_length;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CREATE_CONN;

	//An HCI_LE_Connection_Complete or HCI_LE_Enhanced_Connection_Complete event
    rq.event  = EVT_LE_CONN_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_create_connection_cancel(le_common_rp * common_rp)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CREATE_CONN_CANCEL;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_filter_accept_list_size(le_read_white_list_size_rp * reply)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_FILTER_ACCEPT_SIZE;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_white_list_size_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_clear_filter_accept_list(le_common_rp * common_rp)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CLEAR_FILTER_ACCEPT_LIST;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_add_device_to_filter_accept_list(uint8_t bdaddr_type, bdaddr_t * bdaddr,
        le_common_rp * common_rp)
{
    le_add_device_to_white_list_cp cmd_param;

	struct hci_request rq;

	cmd_param.bdaddr_type= bdaddr_type;
	memcpy(&cmd_param.bdaddr, bdaddr, sizeof(bdaddr_t));
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remove_device_from_filter_accept_list(uint8_t bdaddr_type, bdaddr_t * bdaddr,
        le_common_rp * common_rp)
{
    le_remove_device_from_white_list_cp cmd_param;

	struct hci_request rq;

	cmd_param.bdaddr_type= bdaddr_type;
	memcpy(&cmd_param.bdaddr, bdaddr, sizeof(bdaddr_t));	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = LE_REMOVE_DEVICE_FROM_WHITE_LIST_CP_SIZE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_connection_update(uint16_t handle, uint16_t min_interval, uint16_t max_interval,
            uint16_t latency, uint16_t supervision_timeout, uint16_t min_ce_length,
            uint16_t max_ce_length, le_common_rp * common_rp)
{
    le_connection_update_cp cmd_param;

	struct hci_request rq;

	cmd_param.handle = handle;
	cmd_param.min_interval = min_interval;
	cmd_param.max_interval = max_interval;
	cmd_param.latency = latency;
	cmd_param.supervision_timeout =	supervision_timeout;
	cmd_param.min_ce_length = min_ce_length;
	cmd_param.max_ce_length = max_ce_length;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CONN_UPDATE;

	rq.event  = EVT_LE_CONN_UPDATE_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_host_channel_classification(uint8_t * map, le_common_rp * common_rp)
{
    le_set_host_channel_classification_cp cmd_param;

	struct hci_request rq;

	memcpy(&cmd_param.map, map, 5);
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_HOST_CHANNEL_CLASSIFICATION;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_channel_map(uint16_t handle, le_read_channel_map_rp * reply)
{
    le_read_channel_map_cp cmd_param;

	struct hci_request rq;

	cmd_param.handle = handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_CHANNEL_MAP;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_channel_map_rp);

    return hci_send_req(devfd, &rq, timeout);

}

/* When the Controller receives the HCI_LE_Read_Remote_Features command,
the Controller shall send the HCI_Command_Status event to the Host. When
the Controller has completed the procedure to determine the remote features
or has determined that it will be using a cached copy, the Controller shall send
an HCI_LE_Read_Remote_Features_Complete event to the Host.
The HCI_LE_Read_Remote_Features_Complete event contains the status of
this command and the parameter describing the features used on the
connection and the features supported by the remote device.
*/
int hci_le_cmd_read_remote_features(uint16_t handle, evt_read_remote_features_complete * event,
        le_common_rp * common_rp)
{
    le_read_remote_used_features_cp cmd_param;

	struct hci_request rq;

	cmd_param.handle = handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_REMOTE_USED_FEATURES;

	rq.event  = EVT_READ_REMOTE_FEATURES_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = event;
	rq.rlen   = sizeof(evt_read_remote_features_complete);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_encrypt(	uint8_t * key, uint8_t * plaintext, le_encrypt_rp * reply)
{
    le_encrypt_cp cmd_param;

	struct hci_request rq;

	memcpy(cmd_param.key, key, 16);
	memcpy(cmd_param.plaintext, plaintext, 16);
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ENCRYPT;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(cmd_param);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_encrypt_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_rand(le_rand_rp * reply)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_RAND;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_rand_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_enable_encryption(uint16_t handle, uint64_t random, uint16_t diversifier, uint8_t * key,
        le_common_rp * common_rp)
{
    le_start_encryption_cp cmd_param;

	struct hci_request rq;

	cmd_param.handle = handle;
	cmd_param.random = random,
	cmd_param.diversifier = diversifier;
	memcpy(cmd_param.key, key, 16);  //key is long term key
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_START_ENCRYPTION;

	rq.event  = EVT_ENCRYPTION_KEY_REFRESH_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

/*When the Controller receives the HCI_LE_Enable_Encryption command it
shall send the HCI_Command_Status event to the Host. If the connection is not
encrypted when this command is issued, an HCI_Encryption_Change event
shall occur when encryption has been started for the connection. If the connec-
tion is encrypted when this command is issued, an HCI_Encryption_Key_-
Refresh_Complete event shall occur when encryption has been resumed.
*/
//base the description, need investigate.
int hci_le_cmd_long_term_key_request_reply(uint16_t handle, uint8_t * key, le_ltk_reply_rp * reply)
{
    le_ltk_reply_cp cmd_param;

	struct hci_request rq;

	cmd_param.handle = handle;
	memcpy(cmd_param.key, key ,16);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_LTK_REPLY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_ltk_reply_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_ltk_reply_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_long_term_key_request_negative_reply(uint16_t handle, le_ltk_neg_reply_rp * reply)
{
    le_ltk_neg_reply_cp cmd_param;

	struct hci_request rq;

	cmd_param.handle = handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_LTK_NEG_REPLY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_ltk_neg_reply_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_ltk_neg_reply_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_supported_states(le_read_supported_states_rp * reply)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_SUPPORTED_STATES;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_supported_states_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_receiver_test_v1(uint8_t frequency, le_common_rp * common_rp)
{
    le_receiver_test_cp cmd_param;

	struct hci_request rq;

	cmd_param.frequency = frequency;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_RECEIVER_TEST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_receiver_test_v2(uint8_t frequency, uint8_t phy, uint8_t modulation_index, le_common_rp * common_rp)
{
    le_receiver_test_v2_cp cmd_param;

	struct hci_request rq;
	cmd_param.frequency = frequency;
	cmd_param.phy = phy;
	cmd_param.modulation_index = modulation_index;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_RECEIVER_TEST_V2;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_receiver_test_v2_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_receiver_test_v3(uint8_t frequency, uint8_t phy, uint8_t modulation_index,
        uint8_t expected_cte_length, uint8_t expected_cte_type, uint8_t slot_durations,
        uint8_t switching_pattern_length, uint8_t *antenna_ids, le_common_rp * common_rp)
{
    le_receiver_test_v3_cp * p_cmd_param;

	struct hci_request rq;

	p_cmd_param = (le_receiver_test_v3_cp*)malloc(sizeof(le_receiver_test_v3_cp) + switching_pattern_length);
	p_cmd_param->frequency =frequency;
	p_cmd_param->phy = phy;
	p_cmd_param->modulation_index = modulation_index;
	p_cmd_param->expected_cte_length = expected_cte_length;
	p_cmd_param->expected_cte_type = expected_cte_length;
	p_cmd_param->slot_durations = slot_durations;
	p_cmd_param->switching_pattern_length = switching_pattern_length;
	memcpy(p_cmd_param->antenna_ids, antenna_ids, switching_pattern_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_RECEIVER_TEST_V3;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_receiver_test_v3_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_transmitter_test_v1(uint8_t frequency, uint8_t length, uint8_t payload,
        le_common_rp * common_rp)
{
    le_transmitter_test_cp cmd_param;

	struct hci_request rq;
	cmd_param.frequency = frequency;
	cmd_param.length = length;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_TRANSMITTER_TEST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_transmitter_test_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_transmitter_test_v2(uint8_t frequency, uint8_t length, uint8_t payload, uint8_t phy,
        le_common_rp * common_rp)
{
    le_transmitter_test_v2_cp cmd_param;

	struct hci_request rq;
	cmd_param.frequency = frequency;
	cmd_param.length = length;
	cmd_param.payload = payload;
	cmd_param.phy = phy;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_TRANSMITTER_TEST_V2;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_transmitter_test_v2_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_transmitter_test_v3(uint8_t frequency, uint8_t length, uint8_t payload, uint8_t phy,
            uint8_t cte_length, uint8_t cte_type, uint8_t switching_pattern_length, uint8_t * antenna_ids,
            le_common_rp * common_rp)
{
    le_transmitter_test_v3_cp * p_cmd_param;

	struct hci_request rq;
	p_cmd_param->frequency = frequency;
	p_cmd_param->length = length;
	p_cmd_param->payload = payload;
	p_cmd_param->phy = phy;
	p_cmd_param->cte_length = cte_length;
	p_cmd_param->cte_type = cte_type;
	p_cmd_param->switching_pattern_length = switching_pattern_length;
	memcpy(p_cmd_param->antenna_ids, antenna_ids, switching_pattern_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_TRANSMITTER_TEST_V3;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_transmitter_test_v3_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_transmitter_test_v4(uint8_t frequency, uint8_t length, uint8_t payload, uint8_t phy,
             uint8_t cte_length, uint8_t cte_type, uint8_t switching_pattern_length,
             uint8_t * antenna_ids, uint8_t tx_power_level, le_common_rp * common_rp)
{
    le_transmitter_test_v4_cp * p_cmd_param;

	struct hci_request rq;
	p_cmd_param->frequency = frequency;
	p_cmd_param->length = length;
	p_cmd_param->payload = payload;
	p_cmd_param->phy = phy;
	p_cmd_param->cte_length = cte_length;
	p_cmd_param->cte_type = cte_type;
	p_cmd_param->switching_pattern_length = switching_pattern_length;
	memcpy(p_cmd_param->antenna_ids, antenna_ids, switching_pattern_length);
	p_cmd_param->tx_power_level = tx_power_level;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_TRANSMITTER_TEST_V4;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_transmitter_test_v4_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_test_end(le_test_end_rp * reply)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_TEST_END;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_test_end_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remote_connection_parameter_request_replycommand(uint16_t connection_handle,
            uint16_t interval_min, uint16_t interval_max, uint16_t max_latency, uint16_t timeout,
            uint16_t min_ce_length, uint16_t max_ce_length, le_common_rp * common_rp)
{
    le_remote_connection_parameter_request_reply_cp cmd_param;

	struct hci_request rq;
	cmd_param.connection_handle = connection_handle;
	cmd_param.interval_min = interval_min;
	cmd_param.interval_max = interval_max;
	cmd_param.max_latency = max_latency;
	cmd_param.timeout = timeout;
	cmd_param.min_ce_length = min_ce_length;
	cmd_param.max_ce_length = max_ce_length;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_remote_connection_parameter_request_reply_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remote_connection_parameter_request_negativereply(uint16_t connection_handle, uint8_t reason,
            le_remote_connection_parameter_request_negative_reply_rp * reply)
{
    le_remote_connection_parameter_request_negative_reply_cp cmd_param;

	struct hci_request rq;
	cmd_param.connection_handle = connection_handle;
	cmd_param.reason = reason;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_remote_connection_parameter_request_negative_reply_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_remote_connection_parameter_request_negative_reply_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_data_length(uint16_t conn_handle, uint16_t tx_octets, uint16_t tx_time,
    le_set_data_length_rp * reply)
{
    le_set_data_length_cp cmd_param;

	struct hci_request rq;
	cmd_param.conn_handle = conn_handle;
	cmd_param.tx_octets = tx_octets;
	cmd_param.tx_time = tx_time;
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_DATA_LENGTH;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_data_length_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_data_length_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_suggested_default_data_length(le_read_suggested_default_data_length_rp * reply)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_suggested_default_data_length_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_write_suggested_default_data_length(uint16_t suggest_max_tx_octets,
        uint16_t suggest_max_tx_time, le_common_rp * common_rp)
{
    le_write_suggest_default_data_length_cp cmd_param;

	struct hci_request rq;
	cmd_param.suggest_max_tx_octets = suggest_max_tx_octets;
	cmd_param.suggest_max_tx_time = suggest_max_tx_time;
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_write_suggest_default_data_length_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

/* When the Controller receives the HCI_LE_Read_Local_P-256_Public_Key
command, the Controller shall send the HCI_Command_Status event to the
Host. When the local P-256 public key generation finishes, an HCI_LE_Read_-
Local_P-256_Public_Key_Complete event shall be generated.
*/
int hci_le_cmd_read_local_p256_public_key(le_common_rp * common_rp)
{
    le_generate_dhkey_v1_cp cmd_param;

	struct hci_request rq;
	evt_le_read_local_p_256_public_key_complete event;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_LOCAL_P_256_PUBLIC_KEY;

	rq.event  = EVT_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = NULL;
	rq.rlen   = 0;

	return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_generate_dhkey_v1(uint8_t * key_x_coordinate, uint8_t * key_y_coordinate,
        le_common_rp * common_rp)
{
    le_generate_dhkey_v1_cp cmd_param;

	struct hci_request rq;

	memcpy(cmd_param.key_x_coordinate, key_x_coordinate, 32);
	memcpy(cmd_param.key_y_coordinate, key_y_coordinate, 32);
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_GENERATE_DHKEY;

	rq.event  = EVT_LE_GENERATE_DHKEY_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_generate_dhkey_v1_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_generate_dhkey_v2(uint8_t * key_x_coordinate, uint8_t * key_y_coordinate,
        uint8_t key_type, le_common_rp * common_rp)
{
    le_generate_dhkey_v2_cp cmd_param;

	struct hci_request rq;

	memcpy(cmd_param.key_x_coordinate, key_x_coordinate, 32);
	memcpy(cmd_param.key_y_coordinate, key_y_coordinate, 32);
	cmd_param.key_type = key_type;
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_GENERATE_DHKEY_V2;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_generate_dhkey_v2_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_add_device_to_resolving_list(uint8_t bdaddr_type, bdaddr_t * bdaddr,
        uint8_t * peer_irk, uint8_t * local_irk, le_common_rp * common_rp)
{
    le_add_device_to_resolv_list_cp cmd_param;

	struct hci_request rq;
	cmd_param.bdaddr_type = bdaddr_type;
	memcpy(&cmd_param.bdaddr, bdaddr, sizeof(bdaddr_t));
	memcpy(cmd_param.peer_irk, peer_irk, 16);
	memcpy(cmd_param.local_irk, local_irk, 16);
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ADD_DEVICE_TO_RESOLV_LIST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_add_device_to_resolv_list_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remove_device_from_resolving_list(uint8_t bdaddr_type, bdaddr_t * bdaddr,
        le_common_rp * common_rp)
{
    le_remove_device_from_resolv_list_cp cmd_param;

	struct hci_request rq;
	cmd_param.bdaddr_type = bdaddr_type;
	memcpy(&cmd_param.bdaddr, bdaddr, sizeof(bdaddr_t));

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REMOVE_DEVICE_FROM_RESOLV_LIST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_remove_device_from_resolv_list_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_clear_resolving_list(le_common_rp * common_rp)
{
	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CLEAR_RESOLV_LIST;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_resolving_list_size(le_read_resolv_list_size_rp * reply, le_common_rp * common_rp)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_RESOLV_LIST_SIZE;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_resolv_list_size_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_peer_resolvable_address(uint8_t peer_identity_address_type,
             bdaddr_t * peer_identity_address, le_read_local_resolvable_address_rp * reply)
{
    le_read_local_resolvable_address_cp cmd_param;

	struct hci_request rq;
	cmd_param.peer_identity_address_type = peer_identity_address_type;
	memcpy(&cmd_param.peer_identity_address, peer_identity_address, sizeof(bdaddr_t));
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_PEER_RESOLVABLE_ADDRESS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_local_resolvable_address_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_local_resolvable_address(uint8_t peer_identity_address_type,
             bdaddr_t * peer_identity_address, le_read_local_resolvable_address_rp * reply)
{
    le_read_local_resolvable_address_cp cmd_param;

	struct hci_request rq;
	cmd_param.peer_identity_address_type = peer_identity_address_type;
	memcpy(&cmd_param.peer_identity_address, peer_identity_address, sizeof(bdaddr_t));
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_LOCAL_RESOLVABLE_ADDRESS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_read_local_resolvable_address_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_local_resolvable_address_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_address_resolution_enable(uint8_t enable, le_common_rp * common_rp)
{
    le_set_address_resolution_enable_cp cmd_param;

	struct hci_request rq;
	cmd_param.enable = enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_ADDRESS_RESOLUTION_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_address_resolution_enable_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_resolvable_private_address_timeout(uint8_t rpa_timeout, le_common_rp * common_rp)
{
    le_set_resolvable_private_address_timeout_cp cmd_param;

	struct hci_request rq;
	cmd_param.rpa_timeout = rpa_timeout;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_resolvable_private_address_timeout_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_maximum_data_length(le_read_maximum_data_length_rp * reply)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_MAXIMUM_DATA_LENGTH;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_maximum_data_length_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_phy(uint16_t connection_handle, le_read_phy_rp * reply)
{
    le_read_phy_cp cmd_param;

	struct hci_request rq;
	cmd_param.connection_handle = connection_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_PHY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_read_phy_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_phy_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_default_phy(uint8_t status, uint8_t tx_phy, uint8_t rx_phy, le_common_rp * common_rp)
{
	//uint8_t status = -1;
    le_set_default_phy_cp cmd_param;

	struct hci_request rq;
	cmd_param.status = status;
	cmd_param.tx_phy = tx_phy;
	cmd_param.rx_phy = rx_phy;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_DEFAULT_PHY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_default_phy_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}
/*When the Controller receives the HCI_LE_Set_PHY command, the Controller
shall send the HCI_Command_Status event to the Host. The HCI_LE_PHY_-
Update_Complete event shall be generated either when one or both PHY
changes or when the Controller determines that neither PHY will change
immediately.*/
int hci_le_cmd_set_phy(uint16_t connection_handle, uint8_t all_phys, uint8_t tx_phys,
        uint8_t rx_phys, uint16_t phy_options, le_common_rp * common_rp)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PHY;

	rq.event  = EVT_LE_PHY_UPDATE_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_advertising_set_random_address(uint8_t advertising_handle,
        bdaddr_t * random_address, le_common_rp * common_rp)
{
    le_set_advertising_set_random_address_cp cmd_param;

	struct hci_request rq;
	cmd_param.advertising_handle = advertising_handle;
	memcpy(&cmd_param.random_address, random_address, sizeof(bdaddr_t));

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_advertising_set_random_address_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_extended_advertising_parameters_v1(uint8_t advertising_handle,
            uint16_t advertising_event_properties, uint24_t primary_advertising_interval_min,
            uint24_t primary_advertising_interval_max, uint8_t primary_advertising_channel_map,
            uint8_t own_address_type, uint8_t peer_address_type, bdaddr_t * peer_address,
            uint8_t advertising_filter_policy, uint8_t advertising_tx_power,
            uint8_t primary_advertising_phy, uint8_t secondary_advertising_max_skip,
            uint8_t secondary_advertising_phy, uint8_t advertising_sid,
            uint8_t scan_request_notification_enable, le_set_extended_advertising_parameters_rp * reply)
{
    le_set_extended_advertising_parameters_v1_cp cmd_param;

	struct hci_request rq;

	cmd_param.advertising_handle = advertising_handle;
	cmd_param.advertising_event_properties = advertising_event_properties;
	cmd_param.primary_advertising_interval_min = primary_advertising_interval_min;
	cmd_param.primary_advertising_interval_max = primary_advertising_interval_max;
	cmd_param.primary_advertising_channel_map = primary_advertising_channel_map;
	cmd_param.own_address_type = own_address_type;
	cmd_param.peer_address_type = peer_address_type;
	memcpy(&cmd_param.peer_address, peer_address, sizeof(bdaddr_t));
	cmd_param.advertising_filter_policy = advertising_filter_policy;
	cmd_param.advertising_tx_power = advertising_tx_power;
	cmd_param.primary_advertising_phy = primary_advertising_phy;
	cmd_param.secondary_advertising_max_skip = secondary_advertising_max_skip;
	cmd_param.secondary_advertising_phy = secondary_advertising_phy;
	cmd_param.advertising_sid = advertising_sid;
	cmd_param.scan_request_notification_enable = scan_request_notification_enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V1;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_extended_advertising_parameters_v1_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_extended_advertising_parameters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_extended_advertising_parameters_v2(uint8_t advertising_handle,
            uint16_t advertising_event_properties, uint24_t primary_advertising_interval_min,
            uint24_t primary_advertising_interval_max, uint8_t primary_advertising_channel_map,
            uint8_t own_address_type, uint8_t peer_address_type, bdaddr_t * peer_address,
            uint8_t advertising_filter_policy, uint8_t advertising_tx_power,
            uint8_t primary_advertising_phy, uint8_t secondary_advertising_max_skip,
            uint8_t secondary_advertising_phy, uint8_t advertising_sid,
            uint8_t scan_request_notification_enable, uint8_t primary_advertising_phy_options,
            uint8_t secondary_advertising_phy_options, le_set_extended_advertising_parameters_rp * reply)
{
    le_set_extended_advertising_parameters_v2_cp cmd_param;

	struct hci_request rq;

	cmd_param.advertising_handle = advertising_handle;
	cmd_param.advertising_event_properties = advertising_event_properties;
	cmd_param.primary_advertising_interval_min = primary_advertising_interval_min;
	cmd_param.primary_advertising_interval_max = primary_advertising_interval_max;
	cmd_param.primary_advertising_channel_map = primary_advertising_channel_map;
	cmd_param.own_address_type = own_address_type;
	cmd_param.peer_address_type = peer_address_type;
	memcpy(&cmd_param.peer_address, peer_address, sizeof(bdaddr_t));
	cmd_param.advertising_filter_policy = advertising_filter_policy;
	cmd_param.advertising_tx_power = advertising_tx_power;
	cmd_param.primary_advertising_phy = primary_advertising_phy;
	cmd_param.secondary_advertising_max_skip = secondary_advertising_max_skip;
	cmd_param.secondary_advertising_phy = secondary_advertising_phy;
	cmd_param.advertising_sid = advertising_sid;
	cmd_param.scan_request_notification_enable = scan_request_notification_enable;
	cmd_param.primary_advertising_phy_options = primary_advertising_phy_options;
	cmd_param.secondary_advertising_phy_options = secondary_advertising_phy_options;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_extended_advertising_parameters_v2_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_extended_advertising_parameters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_extended_advertising_data(uint8_t advertising_handle, uint8_t operation,
            uint8_t fragment_preference, uint8_t advertising_data_length,
            uint8_t * advertising_data, le_common_rp * common_rp)
{
    le_set_extended_advertising_data_cp *p_cmd_param;

	struct hci_request rq;

	p_cmd_param = (le_set_extended_advertising_data_cp*)malloc(
	        sizeof(le_set_extended_advertising_data_cp) + advertising_data_length);
	p_cmd_param->advertising_handle = advertising_handle;
	p_cmd_param->operation = operation;
	p_cmd_param->fragment_preference = fragment_preference;
	p_cmd_param->advertising_data_length = advertising_data_length;
	memcpy(p_cmd_param->advertising_data, advertising_data, advertising_data_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EXTENDED_ADVERTISING_DATA;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_extended_advertising_data_cp) + advertising_data_length;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_extended_scan_response_data(uint8_t advertising_handle, uint8_t operation,
            uint8_t fragment_preference, uint8_t scan_response_data_length,
            uint8_t * scan_response_data, le_common_rp * common_rp)
{
    le_set_extended_scan_response_data_cp *p_cmd_param;

	struct hci_request rq;
	p_cmd_param = (le_set_extended_scan_response_data_cp *)malloc(
	        sizeof(le_set_extended_scan_response_data_cp) + scan_response_data_length);
	p_cmd_param->advertising_handle = advertising_handle;
	p_cmd_param->operation = operation;
	p_cmd_param->fragment_preference = fragment_preference;
	p_cmd_param->scan_response_data_length = scan_response_data_length;
	memcpy(p_cmd_param->scan_response_data, scan_response_data, scan_response_data_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EXTENDED_SCAN_RESPONSE_DATA;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_extended_scan_response_data_cp) + scan_response_data_length;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_extended_advertising_enable(uint8_t enable, uint8_t num_sets,
         uint8_t * advertising_handle, uint16_t * duration,
         uint8_t * max_extended_advertising_events, le_common_rp * common_rp)
{
    le_set_extended_advertising_enable_cp * p_cmd_param;

	struct hci_request rq;
	uint8_t * ptr;
	p_cmd_param = (le_set_extended_advertising_enable_cp *)malloc(
	        sizeof(le_set_extended_advertising_enable_cp) + (num_sets -1) * 4);  //4 is sizeof one set.
	p_cmd_param->enable = enable;
	p_cmd_param->num_sets = num_sets;
	ptr = p_cmd_param->advertising_handle;
	memcpy(ptr, advertising_handle, num_sets * sizeof(uint8_t));
	ptr += num_sets * sizeof(uint8_t);
	memcpy(ptr, duration, num_sets * sizeof(uint16_t));
	ptr += num_sets * sizeof(uint8_t);
	memcpy(ptr, max_extended_advertising_events, num_sets * sizeof(uint16_t));
	num_sets * sizeof(uint8_t);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EXTENDED_ADVERTISING_ENABLE;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_extended_advertising_enable_cp) + (num_sets-1) * 4;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_maximum_advertising_data_length(le_read_maximum_advertising_data_length_rp * reply)
{

	struct hci_request rq;


	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_maximum_advertising_data_length_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_number_of_supported_advertising_sets(le_read_number_of_supported_advertising_sets_rp * reply)
{


	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_number_of_supported_advertising_sets_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remove_advertising_set(uint8_t advertising_handle, le_common_rp * common_rp)
{
    le_remove_advertising_set_cp cmd_param;

	struct hci_request rq;

	cmd_param.advertising_handle = advertising_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REMOVE_ADVERTISING_SET;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_remove_advertising_set_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_clear_advertising_sets(le_common_rp * common_rp)
{


	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CLEAR_ADVERTISING_SETS;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_periodic_advertising_parameters_v1(uint8_t advertising_handle,
            uint16_t periodic_advertising_interval_min, uint16_t periodic_advertising_interval_max,
            uint16_t periodic_advertising_properties, le_common_rp * common_rp)
{
    le_set_periodic_advertising_parameters_v1_cp cmd_param;

	struct hci_request rq;

	cmd_param.advertising_handle = advertising_handle;
	cmd_param.periodic_advertising_interval_min = periodic_advertising_interval_min;
	cmd_param.periodic_advertising_interval_max = periodic_advertising_interval_max;
	cmd_param.periodic_advertising_properties = periodic_advertising_properties;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PERIODIC_ADVERTISING_PARAMETERS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_periodic_advertising_parameters_v1_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_periodic_advertising_parameters_v2(uint8_t advertising_handle,
            uint16_t periodic_advertising_interval_min, uint16_t periodic_advertising_interval_max,
            uint16_t periodic_advertising_properties, uint8_t num_subevents,
            uint8_t subevent_interval, uint8_t response_slot_delay,
            uint8_t response_slot_spacing, uint8_t num_response_slots, le_common_rp * common_rp)
{
    le_set_periodic_advertising_parameters_v2_cp cmd_param;

	struct hci_request rq;

	cmd_param.advertising_handle = advertising_handle;
	cmd_param.periodic_advertising_interval_min = periodic_advertising_interval_min;
	cmd_param.periodic_advertising_interval_max = periodic_advertising_interval_max;
	cmd_param.periodic_advertising_properties = periodic_advertising_properties;
	cmd_param.num_subevents = num_subevents;
	cmd_param.subevent_interval = subevent_interval;
	cmd_param.response_slot_delay = response_slot_delay;
	cmd_param.response_slot_spacing, response_slot_spacing;
	cmd_param.num_response_slots = num_response_slots;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_periodic_advertising_parameters_v2_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_set_periodic_advertising_data(uint8_t advertising_handle, uint8_t operation,
            uint8_t advertising_data_length, uint8_t * advertising_data, le_common_rp * common_rp)
{
    le_set_periodic_advertising_data_cp *p_cmd_param;

	struct hci_request rq;

	p_cmd_param = (le_set_periodic_advertising_data_cp *)malloc(
	        sizeof(le_set_periodic_advertising_data_cp) + advertising_data_length);

	p_cmd_param->advertising_handle = advertising_handle;
	p_cmd_param->operation = operation;
	p_cmd_param->advertising_data_length = advertising_data_length;
	memcpy(p_cmd_param->advertising_data, advertising_data, advertising_data_length);
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PERIODIC_ADVERTISING_DATA;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_periodic_advertising_data_cp) + advertising_data_length;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_periodic_advertising_enable(uint8_t enable, uint8_t advertising_handle,
        le_common_rp * common_rp)
{
    le_set_periodic_advertising_enable_cp cmd_param;

	struct hci_request rq;
	cmd_param.enable = enable;
	cmd_param.advertising_handle = advertising_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PERIODIC_ADVERTISING_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_periodic_advertising_enable_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_extended_scan_parameters(uint8_t own_address_type, uint8_t scanning_filter_policy,
             uint8_t scanning_phys, uint8_t * scan_type, uint16_t* scan_interval,
             uint16_t * scan_window, le_common_rp * common_rp)
{
    le_set_extended_scan_parameters_cp * p_cmd_param;
	uint8_t * ptr;

	struct hci_request rq;
	p_cmd_param = (le_set_extended_scan_parameters_cp*)
			malloc(sizeof(le_set_extended_scan_parameters_cp) + (scanning_phys - 1) * 5); //5 is in protocol
	p_cmd_param->own_address_type = own_address_type;
	p_cmd_param->scanning_filter_policy = scanning_filter_policy;
	ptr = p_cmd_param->scan_type;

	memcpy(p_cmd_param->scan_type, scan_type, scanning_phys * 1);
	ptr += scanning_phys * 1;
	memcpy(p_cmd_param->scan_interval, scan_interval, scanning_phys * 2);
	ptr += scanning_phys * 2;
	memcpy(p_cmd_param->scan_window, scan_window, scanning_phys * 2);
	ptr += scanning_phys * 2;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EXTENDED_SCAN_PARAMETERS;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_extended_scan_parameters_cp) + (scanning_phys - 1) * 5;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_extended_scan_enable(uint8_t enable, uint8_t filter_duplicates,
        uint16_t duration, uint16_t period, le_common_rp * common_rp)
{
    le_set_extended_scan_enable_cp cmd_param;

	struct hci_request rq;

	cmd_param.enable = enable;
	cmd_param.filter_duplicates = filter_duplicates;
	cmd_param.duration = duration;
	cmd_param.period = period;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_EXTENDED_SCAN_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_extended_scan_enable_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

/* When the Controller receives the HCI_LE_Extended_Create_Connection
command, the Controller sends the HCI_Command_Status event to the Host.
An HCI_LE_Enhanced_Connection_Complete event shall be generated when
a connection is created because of this command or the connection creation
procedure is cancelled;
*/
int hci_le_cmd_extended_create_connection_v1(uint8_t initiator_filter_policy,
        uint8_t own_address_type, uint8_t peer_address_type, bdaddr_t * peer_address,
        uint8_t initiating_phys, uint16_t * scan_interval, uint16_t * scan_window,
        uint16_t * connection_interval_min, uint16_t * connection_interval_max, uint16_t * max_latency,
        uint16_t * supervision_timeout, uint16_t * min_ce_length, uint16_t * max_ce_length,
        le_common_rp * common_rp)
{
    le_extended_create_connection_v1_cp * p_cmd_param;
	uint8_t * ptr;
	//define rp if needed.
	struct hci_request rq;
	p_cmd_param = (le_extended_create_connection_v1_cp*)
			malloc(sizeof(le_extended_create_connection_v1_cp) + (initiating_phys - 1) * 16); //5 is in protocol
	p_cmd_param->initiator_filter_policy = initiator_filter_policy;
	p_cmd_param->own_address_type = own_address_type;
	p_cmd_param->peer_address_type = peer_address_type;
	memcpy(&p_cmd_param->peer_address, peer_address, sizeof(bdaddr_t));
	p_cmd_param->initiating_phys = initiating_phys;

	ptr = (uint8_t *)&p_cmd_param->scan_interval;

	memcpy(p_cmd_param->scan_interval, scan_interval, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->scan_window, scan_window, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->connection_interval_min, connection_interval_min, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->connection_interval_max, connection_interval_max, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->max_latency, max_latency, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->supervision_timeout, supervision_timeout, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->min_ce_length, min_ce_length, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->max_ce_length, max_ce_length, initiating_phys * 2);
	ptr += initiating_phys * 2;


	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_EXTENDED_CREATE_CONNECTION_V1;

	rq.event  = EVT_LE_ENHANCED_CONNECTION_COMPLETE_V1;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_extended_create_connection_v1_cp) + (initiating_phys - 1) * 16;
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);
}

int hci_le_cmd_extended_create_connection_v2(uint8_t advertising_handle, uint8_t subevent,
        uint8_t initiator_filter_policy, uint8_t own_address_type, uint8_t peer_address_type,
        bdaddr_t * peer_address, uint8_t initiating_phys, uint16_t * scan_interval,
        uint16_t * scan_window, uint16_t * connection_interval_min, uint16_t * connection_interval_max,
        uint16_t * max_latency, uint16_t * supervision_timeout, uint16_t * min_ce_length,
        uint16_t * max_ce_length, le_common_rp * common_rp)
{
    ocf_le_extended_create_connection_v2_cp * p_cmd_param;
	uint8_t * ptr;
	//define rp if needed.
	struct hci_request rq;
	p_cmd_param = (ocf_le_extended_create_connection_v2_cp*)
			malloc(sizeof(ocf_le_extended_create_connection_v2_cp) + (initiating_phys - 1) * 16); //5 is in protocol
	p_cmd_param->advertising_handle = advertising_handle;
	p_cmd_param->subevent = subevent;
	p_cmd_param->initiator_filter_policy = initiator_filter_policy;
	p_cmd_param->own_address_type = own_address_type;
	p_cmd_param->peer_address_type = peer_address_type;
	memcpy(&p_cmd_param->peer_address, peer_address, sizeof(bdaddr_t));
	p_cmd_param->initiating_phys = initiating_phys;

	ptr = (uint8_t *)&p_cmd_param->scan_interval;

	memcpy(p_cmd_param->scan_interval, scan_interval, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->scan_window, scan_window, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->connection_interval_min, connection_interval_min, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->connection_interval_max, connection_interval_max, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->max_latency, max_latency, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->supervision_timeout, supervision_timeout, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->min_ce_length, min_ce_length, initiating_phys * 2);
	ptr += initiating_phys * 2;
	memcpy(p_cmd_param->max_ce_length, max_ce_length, initiating_phys * 2);
	ptr += initiating_phys * 2;


	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_EXTENDED_CREATE_CONNECTION_V2;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(ocf_le_extended_create_connection_v2_cp) + (initiating_phys - 1) * 16;
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);
}

/* When the HCI_LE_Periodic_Advertising_Create_Sync command has been
received, the Controller sends the HCI_Command_Status event to the Host.
An HCI_LE_Periodic_Advertising_Sync_Established event shall be generated
when the Controller starts receiving periodic advertising packets.*/
int hci_le_cmd_periodic_advertising_create_sync(uint8_t options, uint8_t advertising_sid,
            uint8_t advertiser_address_type, bdaddr_t * advertiser_address, uint16_t skip,
            uint16_t sync_timeout, uint8_t sync_cte_type, le_common_rp * common_rp)
{
    le_periodic_advertising_create_sync_cp cmd_param;

	struct hci_request rq;

	cmd_param.options = options;
	cmd_param.advertising_sid = advertising_sid;
	cmd_param.advertiser_address_type = advertiser_address_type;
	memcpy(&cmd_param.advertiser_address, advertiser_address, sizeof(bdaddr_t));
	cmd_param.skip = skip;
	cmd_param.sync_timeout = sync_timeout;
	cmd_param.sync_cte_type = sync_cte_type;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_PERIODIC_ADVERTISING_CREATE_SYNC;

	rq.event  = EVT_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V1;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_periodic_advertising_create_sync_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_periodic_advertising_create_sync_cancel(le_common_rp * common_rp)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_periodic_advertising_terminate_sync(uint16_t sync_handle, le_common_rp * common_rp)
{
    le_periodic_advertising_terminate_sync_cp cmd_param;

	struct hci_request rq;

	cmd_param.sync_handle = sync_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_periodic_advertising_terminate_sync_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_add_device_to_periodic_advertiser_list(uint8_t advertiser_address_type,
        bdaddr_t * advertiser_address, uint8_t advertising_sid, le_common_rp * common_rp)
{
    le_add_device_to_periodic_advertiser_list_cp cmd_param;

	struct hci_request rq;

	cmd_param.advertiser_address_type = advertiser_address_type;
	memcpy(&cmd_param.advertiser_address, advertiser_address, sizeof(bdaddr_t));
	cmd_param.advertising_sid = advertising_sid;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_add_device_to_periodic_advertiser_list_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remove_device_from_periodic_advertiser_list(uint8_t advertiser_address_type,
        bdaddr_t * advertiser_address, uint8_t advertising_sid, le_common_rp * common_rp)
{
    le_remove_device_from_periodic_advertiser_list_cp cmd_param;
	cmd_param.advertiser_address_type = advertiser_address_type;
	memcpy(&cmd_param.advertiser_address, advertiser_address, sizeof(bdaddr_t));
	cmd_param.advertising_sid = advertising_sid;


	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_remove_device_from_periodic_advertiser_list_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_clear_periodic_advertiser_list(le_common_rp * common_rp)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CLEAR_PERIODIC_ADVERTISER_LIST;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_periodic_advertiser_list_size(le_read_periodic_advertiser_list_size_rp * reply)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_periodic_advertiser_list_size_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_transmit_power(le_read_transmit_power_rp * reply)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_TRANSMIT_POWER;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_transmit_power_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_rf_path_compensation(le_read_rf_path_compensation_rp * reply)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_RF_PATH_COMPENSATION;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_rf_path_compensation_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_write_rf_path_compensation(uint16_t rf_tx_path_compensation_value,
        uint16_t rf_rx_path_compensation_value, le_common_rp * common_rp)
{
    le_write_rf_path_compensation_cp cmd_param;

	struct hci_request rq;
	cmd_param.rf_tx_path_compensation_value = rf_tx_path_compensation_value;
	cmd_param.rf_rx_path_compensation_value = rf_rx_path_compensation_value;
	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_WRITE_RF_PATH_COMPENSATION;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_write_rf_path_compensation_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_privacy_mode(uint8_t peer_identity_address_type, bdaddr_t * peer_identity_address,
        uint8_t privacy_mode, le_common_rp * common_rp)
{
    le_set_privacy_mode_cp cmd_param;

	struct hci_request rq;

	cmd_param.peer_identity_address_type = peer_identity_address_type;
	memcpy(&cmd_param.peer_identity_address, peer_identity_address, sizeof(bdaddr_t));
	cmd_param.privacy_mode = privacy_mode;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PRIVACY_MODE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_privacy_mode_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_connectionless_cte_transmit_parameters(uint8_t advertising_handle,
        uint8_t cte_length, uint8_t cte_type, uint8_t cte_count, uint8_t switching_pattern_length,
        uint8_t * antenna_ids, le_common_rp * common_rp)
{
    set_connectionless_cte_transmit_parameters_cp * p_cmd_param;

	struct hci_request rq;

	p_cmd_param = (set_connectionless_cte_transmit_parameters_cp *)
			malloc(sizeof(set_connectionless_cte_transmit_parameters_cp) + switching_pattern_length * 1);
	p_cmd_param->advertising_handle = advertising_handle;
	p_cmd_param->cte_length = cte_length;
	p_cmd_param->cte_type = cte_type;
	p_cmd_param->cte_count = cte_count;
	p_cmd_param->switching_pattern_length = switching_pattern_length;
	memcpy(p_cmd_param->antenna_ids, antenna_ids, switching_pattern_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(set_connectionless_cte_transmit_parameters_cp) + switching_pattern_length * 1;
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_connectionless_cte_transmit_enable(uint8_t advertising_handle,
        uint8_t cte_enable, le_common_rp * common_rp)
{
    le_set_connectionless_cte_transmit_enable_cp cmd_param;

	struct hci_request rq;

	cmd_param.advertising_handle = advertising_handle;
	cmd_param.cte_enable = cte_enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_connectionless_cte_transmit_enable_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_connectionless_iq_sampling_enable(uint16_t sync_handle, uint8_t sampling_enable,
            uint8_t slot_durations, uint8_t max_sampled_ctes, uint8_t switching_pattern_length,
            uint8_t * antenna_ids, le_set_connectionless_iq_sampling_enable_rp * reply)
{
    le_set_connectionless_iq_sampling_enable_cp * p_cmd_param;

	struct hci_request rq;

	p_cmd_param =(le_set_connectionless_iq_sampling_enable_cp *)
			malloc(sizeof(le_set_connectionless_iq_sampling_enable_cp) + (switching_pattern_length -1) * 1);
	p_cmd_param->sync_handle = sync_handle;
	p_cmd_param->sampling_enable = sampling_enable;
	p_cmd_param->slot_durations = slot_durations;
	p_cmd_param->max_sampled_ctes = max_sampled_ctes;
	p_cmd_param->switching_pattern_length =  switching_pattern_length;
	memcpy(p_cmd_param->antenna_ids, antenna_ids, switching_pattern_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_connectionless_iq_sampling_enable_cp) + (switching_pattern_length -1) * 1;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_connectionless_iq_sampling_enable_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_connection_cte_receive_parameters(uint16_t connection_handle,
        uint8_t sampling_enable, uint8_t slot_durations, uint8_t switching_pattern_length,
        uint8_t * antenna_ids, le_set_connection_cte_receive_parameters_rp * reply)
{
    le_set_connection_cte_receive_parameters_cp * p_cmd_param;

	struct hci_request rq;

	p_cmd_param = (le_set_connection_cte_receive_parameters_cp*)
			malloc(sizeof(le_set_connection_cte_receive_parameters_cp) + (switching_pattern_length -1) * 1);

	p_cmd_param->connection_handle = connection_handle;
	p_cmd_param->sampling_enable = sampling_enable;
	p_cmd_param->slot_durations = slot_durations;
	p_cmd_param->switching_pattern_length = switching_pattern_length;
	memcpy(p_cmd_param->antenna_ids, antenna_ids, switching_pattern_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_connection_cte_receive_parameters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_connection_cte_transmit_parameters(uint16_t connection_handle,
            uint8_t cte_types, uint8_t switching_pattern_length, uint8_t antenna_ids,
            le_set_connection_cte_transmit_parameters_rp * reply)
{
    le_set_scan_enable_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_connection_cte_transmit_parameters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_connection_cte_request_enable(uint16_t connection_handle, uint8_t enable,
         uint16_t cte_request_interval, uint8_t requested_cte_length,
         uint8_t requested_cte_type, le_connection_cte_request_enable_rp * reply)
{
    le_connection_cte_request_enable_cp cmd_param;

	struct hci_request rq;
	cmd_param.connection_handle = connection_handle;
	cmd_param.enable = enable;
	cmd_param.cte_request_interval = cte_request_interval;
	cmd_param.requested_cte_length = requested_cte_length;
	cmd_param.requested_cte_type = requested_cte_type;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CONNECTION_CTE_REQUEST_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_connection_cte_request_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_connection_cte_request_enable_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_connection_cte_response_enable(uint16_t connection_handle, uint8_t enable,
        le_connection_cte_response_enable_rp * reply)
{
    le_connection_cte_response_enable_cp cmd_param;

	struct hci_request rq;

	cmd_param.connection_handle = connection_handle;
	cmd_param.enable = enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CONNECTION_CTE_RESPONSE_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_connection_cte_response_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_connection_cte_response_enable_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_antenna_information(le_connection_cte_response_enable_rp * reply)
{

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_ANTENNA_INFORMATION;

	rq.event  = 0;
    rq.cparam = NULL;
	rq.clen   = 0;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_connection_cte_response_enable_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_periodic_advertising_receive_enable(uint16_t sync_handle, uint8_t enable,
        le_common_rp * common_rp)
{
    le_set_periodic_advertising_receive_enable_cp cmd_param;

	struct hci_request rq;

	cmd_param.sync_handle = sync_handle;
	cmd_param.enable = enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_periodic_advertising_receive_enable_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_periodic_advertising_sync_transfer(uint16_t connection_handle, uint16_t service_data,
         uint16_t sync_handle, le_periodic_advertising_sync_transfer_rp * reply)
{
    le_periodic_advertising_sync_transfer_cp cmd_param;

	struct hci_request rq;

	cmd_param.connection_handle = connection_handle;
	cmd_param.service_data = service_data;
	cmd_param.sync_handle = sync_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_periodic_advertising_sync_transfer_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_periodic_advertising_sync_transfer_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_periodic_advertising_set_info_transfer(uint16_t connection_handle,
        uint16_t service_data, uint16_t advertising_handle,
        le_periodic_advertising_set_info_transfer_rp * reply)
{
    le_periodic_advertising_set_info_transfer_cp cmd_param;

	struct hci_request rq;

	cmd_param.connection_handle = connection_handle;
	cmd_param.service_data = service_data,
	cmd_param.advertising_handle = advertising_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_periodic_advertising_set_info_transfer_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_periodic_advertising_set_info_transfer_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_periodic_advertising_sync_transfer_parameters(uint16_t connection_handle,
        uint8_t mode, uint16_t skip, uint16_t sync_timeout, uint8_t cte_type,
        le_set_periodic_advertising_sync_transfer_parameters_rp * reply)
{
    le_set_periodic_advertising_sync_transfer_parameters_cp cmd_param;

	struct hci_request rq;

	cmd_param.connection_handle = connection_handle;
	cmd_param.mode = mode;
	cmd_param.skip = skip;
	cmd_param.sync_timeout = sync_timeout;
	cmd_param.cte_type = cte_type;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_periodic_advertising_sync_transfer_parameters_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_periodic_advertising_sync_transfer_parameters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_default_periodic_advertising_sync_transfer_parameters(uint8_t mode,
    uint16_t skip, uint16_t sync_timeout, uint8_t cte_type, le_common_rp * common_rp)
{
    le_set_default_periodic_advertising_sync_transfer_parameters_cp cmd_param;

	struct hci_request rq;

	cmd_param.mode = mode;
	cmd_param.skip = skip;
	cmd_param.sync_timeout = sync_timeout;
	cmd_param.cte_type = cte_type;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_default_periodic_advertising_sync_transfer_parameters_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_modify_sleep_clock_accuracy(uint8_t action, le_common_rp * common_rp)
{
    le_modify_sleep_clock_accuracy_cp cmd_param;

	struct hci_request rq;

	cmd_param.action = action;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_MODIFY_SLEEP_CLOCK_ACCURACY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_modify_sleep_clock_accuracy_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_iso_tx_sync(uint16_t connection_handle, le_read_iso_tx_sync_rp * reply)
{
    le_read_iso_tx_sync_cp cmd_param;

	struct hci_request rq;

	cmd_param.connection_handle = connection_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_ISO_TX_SYNC;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_read_iso_tx_sync_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_iso_tx_sync_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_cig_parameters(uint8_t cig_id, uint24_t sdu_interval_c_to_p,
        uint24_t sdu_interval_p_to_c, uint8_t worst_case_sca, uint8_t packing, uint8_t framing,
        uint16_t max_transport_latency_c_to_p, uint16_t max_transport_latency_p_to_c,
        uint8_t cis_count, uint8_t * cis_id, uint8_t * max_sdu_c_to_p, uint8_t * max_sdu_p_to_c,
        uint8_t *  phy_c_to_p, uint8_t * phy_p_to_c, uint8_t * rtn_c_to_p, uint8_t * rtn_p_to_c,
        le_set_cig_parameters_rp * reply)
{
    le_set_cig_parameters_cp * p_cmd_param;
	uint8_t * ptr;
	struct hci_request rq;

	p_cmd_param = (le_set_cig_parameters_cp*)malloc(sizeof(le_set_cig_parameters_cp) + (cis_count -1) * 7);
	p_cmd_param->cig_id = cig_id;
	p_cmd_param->sdu_interval_c_to_p = sdu_interval_c_to_p;
	p_cmd_param->sdu_interval_p_to_c = sdu_interval_p_to_c;
	p_cmd_param->worst_case_sca = worst_case_sca;
	p_cmd_param->packing = packing;
	p_cmd_param->framing = framing;
	p_cmd_param->max_transport_latency_c_to_p = max_transport_latency_c_to_p;
	p_cmd_param->max_transport_latency_p_to_c = max_transport_latency_p_to_c;
	p_cmd_param->cis_count = cis_count;
	ptr = (uint8_t *)&p_cmd_param->cis_id;
	memcpy(p_cmd_param->cis_id, cis_id, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->max_sdu_c_to_p, max_sdu_c_to_p, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->max_sdu_p_to_c, max_sdu_p_to_c, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->phy_c_to_p, phy_c_to_p, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->phy_p_to_c, phy_p_to_c, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->rtn_c_to_p, rtn_c_to_p, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->rtn_p_to_c, rtn_p_to_c, cis_count * 1);
	ptr += cis_count * 1;


	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_CIG_PARAMETERS;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_cig_parameters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_cig_parameters_test(uint8_t cig_id, uint24_t sdu_interval_c_to_p,
        uint24_t sdu_interval_p_to_c, uint8_t ft_c_to_p, uint8_t ft_p_to_c, uint16_t iso_interval,
        uint8_t worst_case_sca, uint8_t packing, uint8_t framing, uint8_t cis_count,
        uint8_t * cis_id, uint8_t * nse, uint16_t *  max_sdu_c_to_p, uint16_t * max_sdu_p_to_c,
        uint16_t * max_pdu_c_to_p, uint16_t * max_pdu_p_to_c, uint8_t * phy_c_to_p,
        uint8_t * phy_p_to_c, uint8_t * bn_c_to_p, uint8_t * bn_p_to_c,
        le_set_cig_parameters_test_rp * reply)
{
    le_set_cig_parameters_test_cp * p_cmd_param;
	uint8_t * ptr;
	struct hci_request rq;

	p_cmd_param = (le_set_cig_parameters_test_cp*)malloc(sizeof(le_set_cig_parameters_test_cp) + (cis_count -1) * 14);
	p_cmd_param->cig_id = cig_id;
	p_cmd_param->sdu_interval_c_to_p = sdu_interval_c_to_p;
	p_cmd_param->sdu_interval_p_to_c = sdu_interval_p_to_c;
	p_cmd_param->ft_c_to_p = ft_c_to_p;
	p_cmd_param->ft_p_to_c = ft_p_to_c;
	p_cmd_param->iso_interval = iso_interval;
	p_cmd_param->worst_case_sca = worst_case_sca;
	p_cmd_param->packing = packing;
	p_cmd_param->framing = framing;
	p_cmd_param->cis_count = cis_count;
	ptr = (uint8_t *)&p_cmd_param->cis_id;
	memcpy(p_cmd_param->cis_id, cis_id, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->nse, nse, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->max_sdu_c_to_p, max_sdu_c_to_p, cis_count * 2);
	ptr += cis_count * 2;
	memcpy(p_cmd_param->max_sdu_p_to_c, max_sdu_p_to_c, cis_count * 2);
	ptr += cis_count * 2;
	memcpy(p_cmd_param->max_sdu_c_to_p, max_pdu_c_to_p, cis_count * 2);
	ptr += cis_count * 2;
	memcpy(p_cmd_param->max_sdu_p_to_c, max_pdu_p_to_c, cis_count * 2);
	ptr += cis_count * 2;
	memcpy(p_cmd_param->phy_c_to_p, phy_c_to_p, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->phy_p_to_c, phy_p_to_c, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->bn_c_to_p, bn_c_to_p, cis_count * 1);
	ptr += cis_count * 1;
	memcpy(p_cmd_param->bn_p_to_c, bn_p_to_c, cis_count * 1);
	ptr += cis_count * 1;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_CIG_PARAMETERS_TEST;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_cig_parameters_test_cp)+ (cis_count -1) * 14;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_cig_parameters_test_rp);

    return hci_send_req(devfd, &rq, timeout);

}
/*When the Controller receives the HCI_LE_Create_CIS command, the
Controller sends the HCI_Command_Status event to the Host. An
HCI_LE_CIS_Established event will be generated for each CIS when it is
established or if it is disconnected or considered lost before being established;
until all the events are generated, the command remains pending.*/
int hci_le_cmd_create_cis(uint8_t cis_count, uint16_t * cis_connection_handle,
        uint16_t * acl_connection_handle, le_common_rp * common_rp)
{
    le_create_cis_cp * p_cmd_param;
	uint8_t * ptr;

	struct hci_request rq;
	p_cmd_param = (le_create_cis_cp*)malloc(sizeof(le_create_cis_cp) + (cis_count -1)*4);
	p_cmd_param->cis_count = cis_count;
	ptr = (uint8_t *)&p_cmd_param->cis_connection_handle;
	memcpy(p_cmd_param->cis_connection_handle, cis_connection_handle, cis_count);
	memcpy(p_cmd_param->acl_connection_handle, acl_connection_handle, cis_count);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CREATE_CIS;

	rq.event  = EVT_LE_CIS_ESTABLISHED;
    rq.cparam = p_cmd_param;
	rq.clen   = (sizeof(le_create_cis_cp) + (cis_count -1)*4);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remove_cig(uint8_t cig_id, le_remove_cig_rp * reply)
{
	//uint8_t status = -1;
    le_remove_cig_cp cmd_param;

	struct hci_request rq;

    cmd_param.cig_id = cig_id;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REMOVE_CIG;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_remove_cig_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_remove_cig_rp);

    return hci_send_req(devfd, &rq, timeout);

}

/* When the Controller receives the HCI_LE_Accept_CIS_Request command,
the Controller sends the HCI_Command_Status event to the Host. An
HCI_LE_CIS_Established event will be generated when the CIS is established
or is considered lost before being established */
int hci_le_cmd_accept_cis_request(uint16_t connection_handle, le_common_rp * common_rp)
{
    le_accept_cis_request_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ACCEPT_CIS_REQUEST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_accept_cis_request_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_reject_cis_request(uint16_t connection_handle, uint8_t reason,
        le_reject_cis_request_rp * reply)
{
    le_reject_cis_request_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;;
    cmd_param.reason = reason;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REJECT_CIS_REQUEST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_reject_cis_request_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_reject_cis_request_rp);

    return hci_send_req(devfd, &rq, timeout);

}
/*When the Controller receives the HCI_LE_Create_BIG command, the Control-
ler sends the HCI_Command_Status event to the Host. When the HCI_LE_-
Create_BIG command has completed, the HCI_LE_Create_BIG_Complete
event is generated.*/
int hci_le_cmd_create_big(uint8_t big_handle, uint8_t advertising_handle, uint8_t num_bis,
        uint24_t sdu_interval, uint16_t max_sdu, uint16_t max_transport_latency, uint8_t rtn,
        uint8_t phy, uint8_t packing, uint8_t framing, uint8_t encryption,
        uint8_t * broadcast_code, le_common_rp * common_rp)
{
    le_create_big_cp cmd_param;

	struct hci_request rq;

    cmd_param.big_handle = big_handle;
    cmd_param.advertising_handle = advertising_handle;
    cmd_param.num_bis = num_bis;
    cmd_param.sdu_interval = sdu_interval;
    cmd_param.max_sdu = max_sdu;
    cmd_param.max_transport_latency = max_transport_latency;
    cmd_param.rtn = rtn;
    cmd_param.packing = packing;
    cmd_param.framing = framing;
    cmd_param.encryption = encryption;
    memcpy(&cmd_param.broadcast_code, broadcast_code, 16);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CREATE_BIG;

	rq.event  = EVT_LE_CREATE_BIG_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_create_big_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_create_big_test(uint8_t big_handle, uint8_t advertising_handle, uint8_t num_bis,
        uint24_t sdu_interval, uint16_t iso_interval, uint8_t nse, uint16_t max_sdu,
        uint16_t max_pdu, uint8_t phy, uint8_t packing, uint8_t framing, uint8_t bn, uint8_t irc,
        uint8_t pto, uint8_t encryption, uint8_t * broadcast_code, le_common_rp * common_rp)
{
    le_create_big_test_cp cmd_param;

	struct hci_request rq;

    cmd_param.big_handle = big_handle;
    cmd_param.advertising_handle = advertising_handle;
    cmd_param.num_bis = num_bis;
    cmd_param.sdu_interval = sdu_interval;
    cmd_param.iso_interval = iso_interval;
    cmd_param.nse = nse;
    cmd_param.max_sdu = max_sdu;
    cmd_param.max_pdu = max_pdu;
    cmd_param.phy = phy;
    cmd_param.packing = packing;
    cmd_param.framing = framing;
    cmd_param.bn = bn;
    cmd_param.irc = irc;
    cmd_param.pto = pto;
    cmd_param.encryption = encryption;
    memcpy(&cmd_param.broadcast_code, broadcast_code, 16);


	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_CREATE_BIG_TEST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_create_big_test_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_terminate_big(uint8_t big_handle, uint8_t reason, le_common_rp * common_rp)
{
    le_terminate_big_cp cmd_param;

	struct hci_request rq;

    cmd_param.big_handle = big_handle;
    cmd_param.reason = reason;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_TERMINATE_BIG;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_terminate_big_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}
/*When the Controller receives the HCI_LE_BIG_Create_Sync command, the
Controller sends the HCI_Command_Status event to the Host. When the
HCI_LE_BIG_Create_Sync command has completed, the HCI_LE_BIG_-
Sync_Established event will be generated.*/
int hci_le_cmd_big_create_sync(uint8_t big_handle, uint16_t sync_handle, uint8_t encryption,
    uint8_t * broadcast_code, uint8_t mse, uint16_t big_sync_timeout, uint8_t num_bis,
    uint8_t * bis, le_common_rp * common_rp)
{
    le_big_create_sync_cp * p_cmd_param;

	struct hci_request rq;
    p_cmd_param = (le_big_create_sync_cp*)malloc(sizeof(le_big_create_sync_cp) + (num_bis -1) *1);
    p_cmd_param->big_handle = big_handle;
    p_cmd_param->sync_handle = sync_handle;
    p_cmd_param->encryption = encryption;
    memcpy(p_cmd_param->broadcast_code, broadcast_code, 16);
    p_cmd_param->mse = mse;
    p_cmd_param->big_sync_timeout = big_sync_timeout;
    p_cmd_param->num_bis = num_bis;
    memcpy(p_cmd_param->bis, bis, num_bis * 1);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_BIG_CREATE_SYNC;

	rq.event  = EVT_LE_BIG_SYNC_ESTABLISHED;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_big_create_sync_cp) + (num_bis -1) *1;
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_big_terminate_sync(uint8_t big_handle, le_big_terminate_sync_rp * reply)
{
    le_big_terminate_sync_cp cmd_param;
	struct hci_request rq;

    cmd_param.big_handle = big_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_BIG_TERMINATE_SYNC;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_big_terminate_sync_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_big_terminate_sync_rp);

    return hci_send_req(devfd, &rq, timeout);

}

/* When the Controller receives the HCI_LE_Request_Peer_SCA command, the
Controller sends the HCI_Command_Status event to the Host. When the
HCI_LE_Request_Peer_SCA command has completed, the HCI_LE_-
Request_Peer_SCA_Complete event shall be generated.*/
int hci_le_cmd_request_peer_sca(uint16_t connection_handle, le_common_rp * common_rp)
{
    le_request_peer_sca_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REQUEST_PEER_SCA;

	rq.event  = EVT_LE_REQUEST_PEER_SCA_COMPLETE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_request_peer_sca_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_setup_iso_data_path(uint16_t connection_handle, uint8_t data_path_direction,
        uint8_t data_path_id, uint8_t * codec_id, uint24_t controller_delay,
        uint8_t codec_configuration_length, uint8_t * codec_configuration,
        le_setup_iso_data_path_rp * reply)
{
    le_setup_iso_data_path_cp * p_cmd_param;

	struct hci_request rq;

    p_cmd_param = (le_setup_iso_data_path_cp*)malloc(
            sizeof(le_accept_cis_request_cp) + (codec_configuration_length -1)* 1);
    p_cmd_param->connection_handle = connection_handle;
    p_cmd_param->data_path_direction = data_path_direction;
    p_cmd_param->data_path_id = data_path_id;
    memcpy(p_cmd_param->codec_id, codec_id, 5);
    p_cmd_param->controller_delay = controller_delay;
    p_cmd_param->codec_configuration_length = codec_configuration_length;
    memcpy(p_cmd_param->codec_configuration, codec_configuration, codec_configuration_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SETUP_ISO_DATA_PATH;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_accept_cis_request_cp) + (codec_configuration_length -1)* 1;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_setup_iso_data_path_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_remove_iso_data_path(uint8_t connection_handle, uint16_t data_path_direction,
        le_remove_iso_data_path_rp * reply)
{
	//uint8_t status = -1;
    le_remove_iso_data_path_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;
    cmd_param.data_path_direction = data_path_direction;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_REMOVE_ISO_DATA_PATH;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_remove_iso_data_path_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_remove_iso_data_path_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_iso_transmit_test(uint16_t connection_handle, uint8_t payload_type,
        le_iso_transmit_test_rp * reply)
{
    le_iso_transmit_test_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;
    cmd_param.payload_type = payload_type;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ISO_TRANSMIT_TEST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_iso_transmit_test_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_iso_transmit_test_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_iso_receive_test(uint16_t connection_handle, uint8_t payload_type,
        le_iso_receive_test_rp * reply)
{
    le_iso_receive_test_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;
    cmd_param.payload_type = payload_type;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ISO_RECEIVE_TEST;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_iso_receive_test_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_iso_receive_test_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_iso_read_test_counters(uint16_t connection_handle, le_iso_read_test_counters_rp * reply)
{
    le_iso_read_test_counters_cp cmd_param;

	struct hci_request rq;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ISO_READ_TEST_COUNTERS;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_iso_read_test_counters_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_iso_read_test_counters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_iso_test_end(uint16_t connection_handle, le_iso_test_end_rp * reply)
{
    le_iso_test_end_cp cmd_param;

	struct hci_request rq;
    cmd_param.connection_handle = connection_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ISO_TEST_END;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_iso_test_end_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_iso_test_end_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_host_feature(uint8_t bit_number, uint8_t bit_value, le_common_rp * common_rp)
{
    le_set_host_feature_cp cmd_param;

	struct hci_request rq;

    cmd_param.bit_number = bit_number;
    cmd_param.bit_value = bit_value;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_HOST_FEATURE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_host_feature_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_iso_link_quality(uint16_t connection_handle, le_read_iso_link_quality_rp * reply)
{
    le_read_iso_link_quality_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_ISO_LINK_QUALITY;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_read_iso_link_quality_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_read_iso_link_quality_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_enhanced_read_transmit_power_level(uint16_t connection_handle, uint8_t phy,
        le_enhanced_read_transmit_power_level_rp * reply)
{
    le_enhanced_read_transmit_power_level_cp cmd_param;

	struct hci_request rq;
    cmd_param.connection_handle = connection_handle;
    cmd_param.phy = phy;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_enhanced_read_transmit_power_level_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_enhanced_read_transmit_power_level_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_read_remote_transmit_power_level(uint16_t connection_handle, uint8_t phy,
        le_common_rp * common_rp)
{
    le_read_remote_transmit_power_level_cp cmd_param;

	struct hci_request rq;
    cmd_param.connection_handle = connection_handle;
    cmd_param.phy = phy;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_READ_REMOTE_TRANSMIT_POWER_LEVEL;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_read_remote_transmit_power_level_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_path_loss_reporting_parameters(uint16_t connection_handle,
        uint8_t high_threshold, uint8_t high_hysteresis, uint8_t low_threshold, uint8_t low_hysteresis,
        uint16_t min_time_spent, le_set_path_loss_reporting_parameters_rp * reply)
{
    le_set_path_loss_reporting_parameters_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;
    cmd_param.high_threshold = high_threshold;
    cmd_param.high_hysteresis = high_hysteresis;
    cmd_param.low_threshold = low_threshold;
    cmd_param.low_hysteresis = low_hysteresis;
    cmd_param.min_time_spent = min_time_spent;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_SCAN_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_path_loss_reporting_parameters_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_path_loss_reporting_enable(uint8_t connection_handle, uint8_t enable,
        le_set_path_loss_reporting_enable_rp * reply)
{
    le_set_path_loss_reporting_enable_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;
    cmd_param.enable = enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PATH_LOSS_REPORTING_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_path_loss_reporting_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_path_loss_reporting_enable_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_transmit_power_reporting_enable(uint8_t connection_handle, uint8_t local_enable,
        uint8_t remote_enable, le_set_transmit_power_reporting_enable_rp * reply)
{
    le_set_transmit_power_reporting_enable_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;
    cmd_param.local_enable = local_enable;
    cmd_param.remote_enable = remote_enable;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_TRANSMIT_POWER_REPORTING_ENABLE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_transmit_power_reporting_enable_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_data_related_address_changes(uint8_t advertising_handle, uint8_t change_reasons,
        le_common_rp * common_rp)
{
    le_set_data_related_address_changes_cp cmd_param;

	struct hci_request rq;

    cmd_param.advertising_handle = advertising_handle;
    cmd_param.change_reasons = change_reasons;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_DATA_RELATED_ADDRESS_CHANGES;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_data_related_address_changes_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_default_subrate(uint16_t subrate_min, uint16_t subrate_max, uint16_t max_latency,
            uint16_t continuation_number, uint16_t supervision_timeout, le_common_rp * common_rp)
{
    le_set_default_subrate_cp cmd_param;

	struct hci_request rq;

    cmd_param.subrate_min = subrate_min;
    cmd_param.subrate_max = subrate_max;
    cmd_param.max_latency =  max_latency;
    cmd_param.continuation_number = continuation_number;
    cmd_param.supervision_timeout = supervision_timeout;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_DEFAULT_SUBRATE;

	rq.event  = 0;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_set_default_subrate_cp);
	rq.rparam = common_rp;
	rq.rlen   = LE_COMMON_RP_SIZE;

    return hci_send_req(devfd, &rq, timeout);

}
/*When the Controller receives the HCI_LE_Subrate_Request command, the
Controller sends the HCI_Command_Status event to the Host. An HCI_LE_-
Subrate_Change event shall be generated when the Connection Subrate
Update procedure has completed.
*/
int hci_le_cmd_subrate_request(uint16_t connection_handle, uint16_t subrate_min, uint16_t subrate_max,
        uint16_t max_latency, uint16_t continuation_number, uint16_t supervision_timeout,
        le_common_rp * common_rp)
{
    le_subrate_request_cp cmd_param;

	struct hci_request rq;

    cmd_param.connection_handle = connection_handle;
    cmd_param.subrate_min = subrate_min;
    cmd_param.subrate_max = subrate_max;
    cmd_param.max_latency = max_latency;
    cmd_param.continuation_number = continuation_number;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SUBRATE_REQUEST;

	rq.event  = EVT_LE_SUBRATE_CHANGE;
    rq.cparam = &cmd_param;
	rq.clen   = sizeof(le_subrate_request_cp);
	rq.rparam = NULL;
	rq.rlen   = 0;

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_periodic_advertising_subevent_data(uint8_t advertising_handle, uint8_t num_subevents,
            uint8_t * subevent, uint8_t * response_slot_start, uint8_t * response_slot_count,
            uint8_t *subevent_data_length, uint8_t * subevent_data,
            le_set_periodic_advertising_subevent_data_rp * reply)
{
    le_set_periodic_advertising_subevent_data_cp * p_cmd_param;
    uint8_t * ptr;
	struct hci_request rq;

    p_cmd_param = (le_set_periodic_advertising_subevent_data_cp *)malloc(
            sizeof(le_set_periodic_advertising_subevent_data_cp) + (num_subevents-1) * 5);

    p_cmd_param->advertising_handle = advertising_handle;
    p_cmd_param->num_subevents = num_subevents;
    ptr = p_cmd_param->subevent;

    memcpy(ptr, subevent, num_subevents * 1);
    ptr += num_subevents;
    memcpy(ptr, response_slot_start, num_subevents * 1);
    ptr += num_subevents;
    memcpy(ptr, response_slot_count, num_subevents * 1);
    ptr += num_subevents;
    memcpy(ptr, subevent_data_length, num_subevents * 1);
    ptr += num_subevents;
    memcpy(ptr, subevent_data, num_subevents * 1);
    ptr += num_subevents;

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_SCAN_ENABLE;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_scan_enable_cp);
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_periodic_advertising_subevent_data_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_periodic_advertising_response_data(uint16_t sync_handle, uint16_t request_event,
        uint8_t request_subevent, uint8_t response_subevent, uint8_t response_slot,
        uint8_t response_data_length, uint8_t * response_data,
        le_set_periodic_advertising_response_data_rp* reply)
{
    le_set_periodic_advertising_response_data_cp *p_cmd_param;

	struct hci_request rq;

    p_cmd_param = (le_set_periodic_advertising_response_data_cp*)malloc(
            sizeof(le_set_periodic_advertising_response_data_cp) + (response_data_length -1)*1);

    p_cmd_param->sync_handle = sync_handle;
    p_cmd_param->request_event = request_event;
    p_cmd_param->request_subevent = request_subevent;
    p_cmd_param->response_subevent = response_subevent;
    p_cmd_param->response_slot = response_slot;
    p_cmd_param->response_data_length = response_data_length;
    memcpy(p_cmd_param->response_data, response_data, response_data_length);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_SCAN_ENABLE;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_periodic_advertising_response_data_cp) + (response_data_length -1)*1;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_periodic_advertising_response_data_rp);

    return hci_send_req(devfd, &rq, timeout);

}

int hci_le_cmd_set_periodic_sync_subevent(uint16_t sync_handle, uint8_t periodic_advertising_properties,
            uint8_t num_subevents, uint8_t * subevent, le_set_periodic_sync_subevent_rp* reply)
{
    le_set_periodic_sync_subevent_cp * p_cmd_param;

	struct hci_request rq;
    p_cmd_param = (le_set_periodic_sync_subevent_cp*)malloc(
            sizeof(le_set_periodic_sync_subevent_cp) + (num_subevents -1) *1);
    p_cmd_param->sync_handle = sync_handle;
    p_cmd_param->periodic_advertising_properties = periodic_advertising_properties;
    p_cmd_param->num_subevents = num_subevents;
    memcpy(p_cmd_param->subevent, subevent, num_subevents * 1);

	rq.ogf    = OGF_LE_CTL;
	rq.ocf    = OCF_LE_SET_PERIODIC_SYNC_SUBEVENT;

	rq.event  = 0;
    rq.cparam = p_cmd_param;
	rq.clen   = sizeof(le_set_periodic_sync_subevent_cp) + (num_subevents -1) *1;
	rq.rparam = reply;
	rq.rlen   = sizeof(le_set_periodic_sync_subevent_rp);

    return hci_send_req(devfd, &rq, timeout);
}


/* each hci command has it own ogf, ocf, return event, and input param, output param
 * here define a command api try to handle*/
int hci_write_common_cmd(int dd, uint16_t ogf, uint16_t ocf, uint32_t expect_event,
                                uint8_t * cparam, uint32_t c_len,
								uint8_t * rparam, uint32_t r_len,
								int timeout)
{

	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));

	rq.ogf    = ogf;
	rq.ocf    = ocf;
	rq.event  = expect_event;
	rq.cparam = cparam;
	rq.clen   = c_len;
	rq.rparam = rparam;
	rq.rlen   = r_len;

	if (hci_send_req(dd, &rq, timeout) < 0)
		return -1;

	if (rparam && *rparam) {
		errno = EIO;
		return -1;
	}
	return 0;
}
/* Start hci le command apis*/
