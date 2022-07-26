/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>
//#include <modem/lte_lc.h>
#include <zephyr/random/rand32.h>
//#include <nrf_socket.h>
//#include <nrf_modem_at.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(app_coap_client, CONFIG_APP_LOG_LEVEL);

#define APP_COAP_SEND_INTERVAL_MS 3000
#define APP_COAP_INTERVAL_LIMIT 360
#define APP_COAP_MAX_MSG_LEN 1280
#define APP_COAP_VERSION 1

#define COAP_SERVER_HOSTNAME CONFIG_COAP_SERVER_HOSTNAME
// "coap.us-east-1.amazonaws.com"
// "34.231.208.143"

static int sock;
static struct pollfd fds;
static struct sockaddr_storage server;
static uint16_t next_token;

static uint8_t coap_buf[APP_COAP_MAX_MSG_LEN];

static struct connection_info
{
	uint8_t s4_addr[4];
	uint8_t d4_addr[4];
} connection_info;

int client_dtls_init(int sock);

/**@brief Resolves the configured hostname. */
static int server_resolve(void)
{
	int err;
	struct addrinfo *result;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM
	};
	char ipv4_addr[NET_IPV4_ADDR_LEN];

	printk("Getting server IP address...\n");
	err = getaddrinfo(COAP_SERVER_HOSTNAME, NULL, &hints, &result);
	if (err != 0) {
		printk("ERROR: getaddrinfo failed %d\n", err);
		return -EIO;
	}

	if (result == NULL) {
		printk("ERROR: Address not found\n");
		return -ENOENT;
	}

	printk("Received address\n");

	/* IPv4 Address. */
	struct sockaddr_in *server4 = ((struct sockaddr_in *)&server);

	server4->sin_addr.s_addr =
		((struct sockaddr_in *)result->ai_addr)->sin_addr.s_addr;
	server4->sin_family = AF_INET;
	server4->sin_port = htons(CONFIG_COAP_SERVER_PORT);

	connection_info.s4_addr[0] = server4->sin_addr.s4_addr[0];
	connection_info.s4_addr[1] = server4->sin_addr.s4_addr[1];
	connection_info.s4_addr[2] = server4->sin_addr.s4_addr[2];
	connection_info.s4_addr[3] = server4->sin_addr.s4_addr[3];

	inet_ntop(AF_INET, &server4->sin_addr.s_addr, ipv4_addr,
		  sizeof(ipv4_addr));
	printk("IPv4 Address for %s:%u found %s\n",
	       COAP_SERVER_HOSTNAME, CONFIG_COAP_SERVER_PORT, ipv4_addr);

	/* Free the address. */
	freeaddrinfo(result);

	return 0;
}

/**@brief Initialize the CoAP client */
static int client_init(void)
{
	int err;

	LOG_DBG("Creating socket");
#if !defined(CONFIG_COAP_DTLS)
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
//#if CONFIG_NET_SOCKETS_OFFLOAD_PRIORITY < CONFIG_NET_SOCKETS_TLS_PRIORITY
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
//#else
//	sock = socket(AF_INET, SOCK_DGRAM | SOCK_NATIVE_TLS, IPPROTO_DTLS_1_2);
//#endif
#endif
	if (sock < 0) {
		printk("Failed to create CoAP socket: %d.\n", -errno);
		return -errno;
	}

#if defined(CONFIG_COAP_DTLS)
	err = client_dtls_init(sock);
	if (err) {
		return err;
	}
#endif
	err = connect(sock, (struct sockaddr *)&server,
		      sizeof(struct sockaddr_in));
	if (err < 0) {
		printk("Connect failed : %d\n", -errno);
		return -errno;
	} else {
		LOG_DBG("Connect succeeded.");
	}

	/* Initialize FDS, for poll. */
	fds.fd = sock;
	fds.events = POLLIN;

	/* Randomize token. */
	next_token = sys_rand32_get();

	return 0;
}

static int client_response(struct coap_packet *req)
{
	int err;
	struct coap_packet response;

	err = coap_ack_init(&response, req, coap_buf, sizeof(coap_buf), 0);
	if (err < 0) {
		printk("Failed to create CoAP response, %d\n", err);
		return err;
	}

	err = send(sock, response.data, response.offset, 0);
	if (err < 0) {
		printk("Failed to send CoAP response, %d\n", -errno);
		return -errno;
	}

	return 0;
}

/**@brief Handles responses from the remote CoAP server. */
static int client_handle_get_response(uint8_t *buf, int received)
{
	int err;
	struct coap_packet reply;
	const uint8_t *payload;
	uint16_t payload_len;
	uint8_t token[8];
	uint16_t token_len;
	uint8_t temp_buf[16] = {0};
	uint8_t type;

	err = coap_packet_parse(&reply, buf, received, NULL, 0);
	if (err < 0) {
		printk("Malformed response received: %d\n", err);
		return err;
	}

	payload = coap_packet_get_payload(&reply, &payload_len);
	token_len = coap_header_get_token(&reply, token);
	type = coap_header_get_type(&reply);

	if ((token_len != sizeof(next_token)) ||
	    (memcmp(&next_token, token, sizeof(next_token)) != 0)) {
		printk("Invalid token received: 0x%02x%02x, expected: 0x%04x\n",
		       token[1], token[0], next_token);
		return 0;
	}

	if (payload_len > 0) {
		snprintf(temp_buf, MIN(payload_len + 1, sizeof(temp_buf)), "%s", payload);
	} else {
		strcpy(temp_buf, "EMPTY");
	}

	printk("CoAP response: code: 0x%x, token 0x%02x%02x, payload: %s\n",
	       coap_header_get_code(&reply), token[1], token[0], temp_buf);

	if (type == COAP_TYPE_CON) {
		printk("Sending ACK\n");
		err = client_response(&reply);
	}
	return err;
}

/**@brief Send CoAP GET request. */
static int client_get_send(void)
{
	int err;
	struct coap_packet request;

	next_token++;

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf),
			       APP_COAP_VERSION, COAP_TYPE_CON,
			       sizeof(next_token), (uint8_t *)&next_token,
			       COAP_METHOD_GET, coap_next_id());
	if (err < 0) {
		printk("Failed to create CoAP request, %d\n", err);
		return err;
	}

	err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					(uint8_t *)CONFIG_COAP_GET_RESOURCE,
					strlen(CONFIG_COAP_GET_RESOURCE));
	if (err < 0) {
		printk("Failed to encode CoAP option, %d\n", err);
		return err;
	}

	err = send(sock, request.data, request.offset, 0);
	if (err < 0) {
		printk("Failed to send CoAP request, %d\n", errno);
		return -errno;
	}

	printk("CoAP request sent: token 0x%04x\n", next_token);

	return 0;
}

/**@brief Send CoAP PUT request. */
static int client_put_send(void)
{
	int err;
	struct coap_packet request;
	const char *payload = "deadbeef";

	next_token++;

	err = coap_packet_init(&request, coap_buf, sizeof(coap_buf),
			       APP_COAP_VERSION, COAP_TYPE_CON,
			       sizeof(next_token), (uint8_t *)&next_token,
			       COAP_METHOD_PUT, coap_next_id());
	if (err < 0) {
		printk("Failed to create CoAP request, %d\n", err);
		return err;
	}

	err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					(uint8_t *)CONFIG_COAP_PUT_RESOURCE,
					strlen(CONFIG_COAP_PUT_RESOURCE));
	if (err < 0) {
		printk("Failed to encode CoAP option, %d", err);
		return err;
	}

	err = coap_packet_append_payload_marker(&request);
	if (err < 0) {
		printk("Failed to add CoAP payload marker, %d", err);
		return err;
	}

	err = coap_packet_append_payload(&request, payload, strlen(payload));
	if (err < 0) {
		printk("Failed to add CoAP payload, %d", err);
		return err;
	}

	err = send(sock, request.data, request.offset, 0);
	if (err < 0) {
		printk("Failed to send CoAP request, %d", errno);
		return -errno;
	}

	printk("CoAP request sent: token 0x%04x\n", next_token);

	return 0;
}

/* Returns 0 if data is available.
 * Returns -EAGAIN if timeout occured and there is no data.
 * Returns other, negative error code in case of poll error.
 */
static int wait(int timeout)
{
	int ret = poll(&fds, 1, timeout);

	if (ret < 0) {
		printk("poll error: %d\n", errno);
		return -errno;
	}

	if (ret == 0) {
		/* Timeout. */
		return -EAGAIN;
	}

	if ((fds.revents & POLLERR) == POLLERR) {
		printk("wait: POLLERR\n");
		return -EIO;
	}

	if ((fds.revents & POLLNVAL) == POLLNVAL) {
		printk("wait: POLLNVAL\n");
		return -EBADF;
	}

	if ((fds.revents & POLLIN) != POLLIN) {
		return -EAGAIN;
	}

	return 0;
}

void main(void)
{
	int64_t next_msg_time = APP_COAP_SEND_INTERVAL_MS;
	int err;
	int received;
	bool do_send = false;

	printk("The nRF CoAP client sample started\n");

	if (server_resolve() != 0) {
		printk("Failed to resolve server name\n");
		return;
	}

	if (client_init() != 0) {
		printk("Failed to initialize CoAP client\n");
		return;
	}

	next_msg_time = k_uptime_get();

	while (1) {
		if (k_uptime_get() >= next_msg_time) {
			if (do_send) {
				printk("\nCalling client_put_send()\n");
				if (client_put_send() != 0) {
					printk("Failed to send PUT request, exit...\n");
					break;
				}
			} else {
				printk("\nCalling client_get_send()\n");
				if (client_get_send() != 0) {
					printk("Failed to send GET request, exit...\n");
					break;
				}
			}
			do_send = !do_send;
			next_msg_time += APP_COAP_SEND_INTERVAL_MS;
		}

		int64_t remaining = next_msg_time - k_uptime_get();

		if (remaining < 0) {
			remaining = 0;
		}

		err = wait(remaining);
		if (err < 0) {
			if (err == -EAGAIN) {
				continue;
			}

			printk("Poll error, exit...\n");
			break;
		}

		received = recv(sock, coap_buf, sizeof(coap_buf), MSG_DONTWAIT);
		if (received < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				printk("socket EAGAIN\n");
				continue;
			} else {
				printk("Socket error, exit...\n");
				break;
			}
		}

		if (received == 0) {
			printk("Empty datagram\n");
			continue;
		}

		err = client_handle_get_response(coap_buf, received);
		if (err < 0) {
			printk("Invalid response, exit...\n");
			break;
		}
	}

	(void)close(sock);
}
