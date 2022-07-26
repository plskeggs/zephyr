/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <net/coap.h>
#include <net/socket.h>
//#include <modem/lte_lc.h>
//#include <modem/modem_key_mgmt.h>
#if defined(CONFIG_MODEM_INFO)
#include <modem/modem_info.h>
#endif
#if defined(CONFIG_MBEDTLS)
#include <mbedtls/ssl.h>
#endif
#if defined(CONFIG_TLS_CREDENTIALS)
#include <net/tls_credentials.h>
#endif
//#include <nrf_socket.h>
//#include <nrf_modem_at.h>

#include <logging/log.h>
LOG_MODULE_DECLARE(app_coap_client, CONFIG_APP_LOG_LEVEL);

#define log_strdup(x) (x)

#if defined(CONFIG_MBEDTLS)
/* Uncomment to limit cipher negotation to a list */
#define RESTRICT_CIPHERS
/* Uncomment to display the cipherlist available */
/* #define DUMP_CIPHERLIST */
#endif

static sec_tag_t sectag = CONFIG_COAP_SECTAG;

#if defined(CONFIG_MODEM_INFO)
static struct modem_param_info mdm_param;
#endif

#if defined(CONFIG_MODEM_INFO)
static int get_device_ip_address(uint8_t *d4_addr)
{
	int err;

	err = modem_info_init();
	if (err) {
		printk("Could not init modem info: %d\n", err);
		return err;
	}
	err = modem_info_params_init(&mdm_param);
	if (err) {
		printk("Could not get modem info: %d\n", err);
		return err;
	}

	err = modem_info_params_get(&mdm_param);
	if (err) {
		printk("Could not get modem params: %d\n", err);
		return err;
	}
	LOG_DBG("nRF Connect SDK version: %s", mdm_param.device.app_version);
	LOG_DBG("Modem FW version:        %s", mdm_param.device.modem_fw.value_string);
	LOG_DBG("IMEI:                    %s", mdm_param.device.imei.value_string);

	err = inet_pton(AF_INET, mdm_param.network.ip_address.value_string, d4_addr);
	if (err == 1) {
		return 0;
	}
	return errno;
}
#endif /* CONFIG_MODEM_INFO */

int provision_psk(void)
{
	int ret;
	const char *identity = CONFIG_COAP_DTLS_PSK_IDENTITY;
	uint16_t identity_len;
	const char *psk = CONFIG_COAP_DTLS_PSK_SECRET;
	uint16_t psk_len;

	identity_len = strlen(identity);
	psk_len = strlen(psk);

	LOG_DBG("psk identity: %s len %u", log_strdup(identity), identity_len);
	LOG_HEXDUMP_DBG(psk, psk_len, "psk");

#if defined(CONFIG_NET_SOCKETS_OFFLOAD_TLS)
	char psk_hex[64];

	/* Convert PSK to a format accepted by the modem. */
	psk_len = bin2hex(psk, psk_len, psk_hex, sizeof(psk_hex));
	if (psk_len == 0) {
		printk("PSK is too large to convert (%d)\n", -EOVERFLOW);
		return -EOVERFLOW;
	}
	LOG_HEXDUMP_DBG(psk_hex, 64, "psk_hex\n");

	lte_lc_offline();

	ret = modem_key_mgmt_write(sectag, MODEM_KEY_MGMT_CRED_TYPE_PSK, psk_hex, psk_len);
	if (ret < 0) {
		printk("Setting cred tag %d type %d failed (%d)\n", sectag,
			(int)MODEM_KEY_MGMT_CRED_TYPE_PSK, ret);
		goto exit;
	}

	ret = modem_key_mgmt_write(sectag, MODEM_KEY_MGMT_CRED_TYPE_IDENTITY, identity,
				   identity_len);
	if (ret < 0) {
		printk("Setting cred tag %d type %d failed (%d)\n", sectag,
			(int)MODEM_KEY_MGMT_CRED_TYPE_IDENTITY, ret);
	}
exit:
	lte_lc_connect();
#else
	ret = tls_credential_add(sectag, TLS_CREDENTIAL_PSK, psk, psk_len);
	if (ret) {
		printk("Failed to set PSK: %d\n", ret);
	}
	ret = tls_credential_add(sectag, TLS_CREDENTIAL_PSK_ID, identity, identity_len);
	if (ret) {
		printk("Failed to set PSK identity: %d\n", ret);
	}
#endif /* CONFIG_NET_SOCKETS_OFFLOAD_TLS */
	return ret;
}

int client_dtls_init(int sock)
{
	int err;
#if defined(RESTRICT_CIPHERS)
	static const int ciphers[] = {
		MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8, 0
	};
#endif

	printk("Provisioning PSK\n");
	err = provision_psk();
	if (err) {
		return err;
	}
	printk("Setting socket options\n");

	err = setsockopt(sock, SOL_TLS, TLS_HOSTNAME, CONFIG_COAP_SERVER_HOSTNAME,
			 sizeof(CONFIG_COAP_SERVER_HOSTNAME));
	if (err) {
		printk("Error setting hostname: %d\n", errno);
	}

	err = setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, &sectag, sizeof(sec_tag_t));
	if (err) {
		printk("Error setting sectag list: %d\n", errno);
	}

#if defined(RESTRICT_CIPHERS)
	err = setsockopt(sock, SOL_TLS, TLS_CIPHERSUITE_LIST, ciphers, sizeof(ciphers));
	if (err) {
		printk("Error setting cipherlist: %d\n", errno);
	}
#endif
#if defined(DUMP_CIPHERLIST)
	int len;
	int ciphers[32];

	len = sizeof(ciphers);
	err = getsockopt(sock, SOL_TLS, TLS_CIPHERSUITE_LIST, ciphers, &len);
	if (err) {
		printk("Error getting cipherlist: %d\n", errno);
	} else {
		int count = len / sizeof(int);

		printk("New cipherlist:\n");
		for (int i = 0; i < count; i++) {
			printk("%d. 0x%04X = %s\n", i, (unsigned int)ciphers[i],
			       mbedtls_ssl_get_ciphersuite_name(ciphers[i]));
		}
	}
#endif

#if defined(CONFIG_MODEM_INFO)
	uint8_t d4_addr[4];

	err = get_device_ip_address(d4_addr);
	if (err) {
		return err;
	}
	printk("client addr %u.%u.%u.%u\n", d4_addr[0], d4_addr[1], d4_addr[2], d4_addr[3]);
#endif
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
	uint8_t dummy;

	err = setsockopt(sock, SOL_TLS, TLS_DTLS_CONNECTION_ID, &dummy, 0);
	if (err) {
		printk("Error setting connection ID: %d\n", errno);
	}
#endif
	return err;
}
