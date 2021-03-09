#include <libwebsockets.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct lws *web_socket = NULL;
static int has_data = 1;

#define SIZE (4096)

static int callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lws_callback_on_writable(wsi);
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		has_data = 1;
		printf("%s\n", in);
		fflush(stdout);
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		unsigned char buffer[LWS_SEND_BUFFER_PRE_PADDING + SIZE + LWS_SEND_BUFFER_POST_PADDING];
		char *line = NULL;
		size_t length = 0;
		ssize_t nread;
		if ((nread = getline(&line, &length, stdin)) != -1) {
			if (nread > SIZE)
				nread = SIZE;
			memcpy(&buffer[LWS_SEND_BUFFER_PRE_PADDING], line, nread);
			free(line);
			lws_write(wsi, &buffer[LWS_SEND_BUFFER_PRE_PADDING], nread, LWS_WRITE_TEXT);
			has_data = 0;
			break;
		} else {
			free(line);
			return -1;
		}
	}
	case LWS_CALLBACK_CLOSED:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		web_socket = NULL;
		break;

	default:
		break;
	}

	return 0;
}

enum protocols {
	PROTOCOL_INDEX = 0, PROTOCOL_COUNT
};

static struct lws_protocols protocols[] = { { "chat", callback, 0,
SIZE, }, { NULL, NULL, 0, 0 } };

int verify(int preverify_ok, X509_STORE_CTX *x509_ctx) {
	X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(x509_ctx);
	X509_VERIFY_PARAM_set1_host(param, NULL, 0);
	return 1;
}

int main(int argc, char *argv[]) {
	int error;
	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_METHOD *method = (SSL_METHOD *) SSLv23_client_method();
	if (!method) {
		error = ERR_get_error();
		lwsl_err("Failed to create SSL method %lu: %s\n", error, ERR_error_string(error, 0));
		return 1;
	}
	SSL_CTX *ssl_context = SSL_CTX_new(method);
	if (!ssl_context) {
		error = ERR_get_error();
		lwsl_err("Failed to create SSL context %lu: %s\n", error, ERR_error_string(error, 0));
		return 1;
	}
	SSL_CTX_set_verify(ssl_context, SSL_VERIFY_NONE, &verify);

	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.provided_client_ssl_ctx = ssl_context;
	info.gid = -1;
	info.uid = -1;

	struct lws_context *context = lws_create_context(&info);
	while (1) {
		char *url = argv[1];
		const char *protocol;

		if (!web_socket) {
			struct lws_client_connect_info ccinfo = { 0 };
			ccinfo.context = context;
			ccinfo.host = url;
			ccinfo.origin = url;
			ccinfo.ssl_connection = 2;
			ccinfo.protocol = protocols[PROTOCOL_INDEX].name;

			int result = lws_parse_uri(url, &protocol, &ccinfo.address, &ccinfo.port, &ccinfo.path);
			if(result == 0){
				char path[sizeof(ccinfo.path) + 2];
				path[0] = '/';
				strncpy(path + 1, ccinfo.path, sizeof(path) - 1);
				ccinfo.path = path;
			}
			web_socket = lws_client_connect_via_info(&ccinfo);
			if (web_socket == NULL)
				break;
		}

		if(has_data == 1) {
			lws_callback_on_writable(web_socket);
		}

		lws_service(context, /* timeout_ms = */255);
		if (web_socket == NULL)
			break;
	}

	lws_context_destroy(context);

	return 0;
}
