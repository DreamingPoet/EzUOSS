#include "OSSRequest.h"
#include "EzUOSS.h"
#include "OSSLog.h"

/*
#define BUCKET_LEN 65
#define DOMAIN_LEN 254


struct obs_s3_switch
{
	time_t time_switch;
	char bucket_name[BUCKET_LEN];
	char host_name[DOMAIN_LEN];
	obs_use_api use_api;
};

FCriticalSection OSSRequest::RequestLock;



//================ request.cpp start ================

#define countof(array) (sizeof(array)/sizeof(array[0]))
#define REQUEST_STACK_SIZE 100
#define ARRAY_LENGTH_1024 1024

int API_STACK_SIZE = 100;
static char userAgentG[256];
static uint32 requestStackCountG = 0;
static uint32 current_request_cnt = 0;
obs_openssl_switch g_switch_openssl = OBS_OPENSSL_CLOSE;
obs_http_request_option* obs_default_http_request_option = NULL;
uint32 request_online_max = 1000;
http_request* requestStackG[REQUEST_STACK_SIZE] = { 0 };
int use_api_index = -1;
obs_s3_switch* api_switch = NULL;

//================ request.cpp end ================



#define do_put_header(params, values, fmt, sourceField, destField, badError, tooLongError)  \
    do {                                                                    \
        if (params->put_properties &&                                        \
            params->put_properties->sourceField &&                          \
            params->put_properties->sourceField[0]) {                       \
            const char *val = params->put_properties-> sourceField;          \
            while (*val && is_blank(*val)) {                                \
                val++;                                                      \
            }                                                               \
            if (!*val) {                                                    \
                return badError;                                            \
            }                                                               \
            int len = snprintf_s(values->destField,                          \
                               sizeof(values->destField),_TRUNCATE,  fmt, val);       \
            if (len >= (int) sizeof(values->destField) || len < 0) {                  \
                return tooLongError;                                        \
            }                                                               \
            while (is_blank(values-> destField[len])) {                     \
                if (len > 0)                                                \
                {                                                           \
                    len--;                                                  \
                }                                                           \
            }                                                               \
            values-> destField[len] = 0;                                    \
        }                                                                   \
        else {                                                              \
            values-> destField[0] = 0;                                      \
        }                                                                   \
    } while (0)

#define do_get_header(params, values, fmt, sourceField, destField, badError, tooLongError)  \
        do {                                                                            \
            if (params->get_conditions &&                                                \
                params->get_conditions-> sourceField &&                                  \
                params->get_conditions-> sourceField[0]) {                                   \
                const char *val = params->get_conditions-> sourceField;                  \
                while (*val && is_blank(*val)) {                                        \
                    val++;                                                              \
                }                                                                       \
                if (!*val) {                                                             \
                    return badError;                                                    \
                }                                                                       \
                int len = snprintf_s(values-> destField,                                \
                    sizeof(values-> destField),_TRUNCATE,  fmt, val);                   \
                if (len >= (int) sizeof(values-> destField) || len < 0) {               \
                    return tooLongError;                                                \
                }                                                                       \
                while ((len > 0) && is_blank(values-> destField[len])) {                \
                    len--;                                                              \
                }                                                                       \
                values-> destField[len] = 0;                                            \
            }                                                                           \
            else {                                                                      \
                values-> destField[0] = 0;                                              \
            }                                                                           \
        } while (0)

#define do_gp_header(params, values, fmt, sourceField, destField, badError, tooLongError) \
    do {                                                                                  \
        if (params->put_properties && params->put_properties->get_conditions &&              \
            params->put_properties->get_conditions-> sourceField &&                           \
            params->put_properties->get_conditions-> sourceField[0]) {                        \
            const char *val = params->put_properties->get_conditions-> sourceField;           \
            while (*val && is_blank(*val)) {                                                \
                val++;                                                                      \
            }                                                                               \
            if (!*val) {                                                                    \
                return badError;                                                            \
            }                                                                               \
            int len = snprintf_s(values-> destField,                                        \
                            sizeof(values-> destField),_TRUNCATE,  fmt, val);               \
            if (len >= (int) sizeof(values-> destField) || len < 0) {                       \
                return tooLongError;                                                        \
        }                                                                                   \
        while ((len > 0) && is_blank(values-> destField[len])) {                            \
            len--;                                                                          \
        }                                                                                   \
        values-> destField[len] = 0;                                                        \
        }                                                                                   \
        else {                                                                              \
            values-> destField[0] = 0;                                                      \
        }                                                                                   \
    } while (0)

// ===================== 通用方法 start ===============
void compute_md5(const char* buffer, int64 buffer_size, char* outbuffer, int64 max_out_put_buffer_size)
{
// TODO:
// 	unsigned char buffer_md5[16] = { 0 };
// 	char base64_md5[64] = { 0 };
// 	// FMD5::HashAnsiString(TEXT("someStuff"));
// 	MD5((unsigned char*)buffer, (size_t)buffer_size, buffer_md5);
// 	base64Encode(buffer_md5, sizeof(buffer_md5), base64_md5);
// 	errno_t err = strcpy_s(outbuffer, max_out_put_buffer_size, base64_md5);
// 	if (err != EOK)
// 	{
// 		// COMMLOG(OBS_LOGWARN, "%s(%d): strcpy_s failed(%d)!", __FUNCTION__, __LINE__, err);
// 	}

	
}
// ===================== 通用方法 end ===============


// ===================== request_util start ===============

obs_status response_to_status(http_request* request)
{
	switch (request->httpResponseCode) {
	case 0:
		return OBS_STATUS_ConnectionFailed;
	case 301:
		return OBS_STATUS_PermanentRedirect;
	case 307:
		return OBS_STATUS_HttpErrorMovedTemporarily;
	case 400:
		return OBS_STATUS_HttpErrorBadRequest;
	case 403:
		return OBS_STATUS_HttpErrorForbidden;
	case 404:
		return OBS_STATUS_HttpErrorNotFound;
	case 405:
		return OBS_STATUS_MethodNotAllowed;
	case 409:
		return OBS_STATUS_HttpErrorConflict;
	case 411:
		return OBS_STATUS_MissingContentLength;
	case 412:
		return OBS_STATUS_PreconditionFailed;
	case 416:
		return OBS_STATUS_InvalidRange;
	case 500:
		return OBS_STATUS_InternalError;
	case 501:
		return OBS_STATUS_NotImplemented;
	case 503:
		return OBS_STATUS_SlowDown;
	default:
		return OBS_STATUS_HttpErrorUnknown;
	}
}


const char* http_request_type_to_verb(http_request_type requestType)
{
	switch (requestType) {
	case http_request_type_get:
		return "GET";
	case http_request_type_head:
		return "HEAD";
	case http_request_type_put:
	case http_request_type_copy:
		return "PUT";
	case http_request_type_post:
		return "POST";
	case http_request_type_options:
		return "OPTIONS";
	default: //http_request_type_delete
		return "DELETE";
	}
}


CURLcode sslctx_function(CURL* curl, const void* sslctx, void* parm)
{
// TODO::

// 	(void)curl;
// 
// 	X509_STORE* store = NULL;
// 	X509* cert = NULL;
// 	BIO* bio = NULL;
// 
// 	bio = BIO_new_mem_buf((char*)parm, -1);
// 
// 	PEM_read_bio_X509(bio, &cert, 0, NULL);
// 
// 	store = SSL_CTX_get_cert_store((SSL_CTX*)sslctx);
// 	X509_STORE_add_cert(store, cert);
// 	X509_free(cert);
// 	BIO_free(bio);

	return CURLE_OK;
}


size_t curl_header_func(void* ptr, size_t size, size_t nmemb,
	void* data)
{
	http_request* request = (http_request*)data;

	int64_t len = (int64_t)size * nmemb;

	response_headers_handler::response_headers_handler_add
	(&(request->responseHeadersHandler), (char*)ptr, len);

	return len;
}


size_t curl_read_func(void* ptr, size_t size, size_t nmemb, void* data)
{
	http_request* request = (http_request*)data;


	int64_t len = (int64_t)size * nmemb;
	if (request->status != OBS_STATUS_OK) {
		return CURL_READFUNC_ABORT;
	}
	if (!request->toS3Callback || !request->toS3CallbackBytesRemaining) {
		return 0;
	}
	if (len > request->toS3CallbackBytesRemaining) {
		len = request->toS3CallbackBytesRemaining;
	}
	int64_t ret = (*(request->toS3Callback))
		((int)len, (char*)ptr, request->callback_data);
	if (ret < 0) {
		request->status = OBS_STATUS_AbortedByCallback;
		return CURL_READFUNC_ABORT;
	}
	else {
		if (ret > request->toS3CallbackBytesRemaining) {
			ret = request->toS3CallbackBytesRemaining;
		}
		request->toS3CallbackBytesRemaining -= ret;
		return (size_t)ret;
	}
}


void request_headers_done(http_request* request)
{
	if (request->propertiesCallbackMade) {
		return;
	}
	request->propertiesCallbackMade = 1;
	long httpResponseCode = 0;
	request->httpResponseCode = 0;
	if (curl_easy_getinfo(request->curl, CURLINFO_RESPONSE_CODE,
		&httpResponseCode) != CURLE_OK) {
		request->status = OBS_STATUS_InternalError;
		return;
	}
	else {
		request->httpResponseCode = httpResponseCode;
	}
	response_headers_handler::response_headers_handler_done(&(request->responseHeadersHandler),
		request->curl);
	if (request->properties_callback) {
		(*(request->properties_callback))
			(&(request->responseHeadersHandler.responseProperties),
				request->callback_data);
	}
}


size_t curl_write_func(void* ptr, size_t size, size_t nmemb,
	void* data)
{
	http_request* request = (http_request*)data;

	int64_t len = (int64_t)size * nmemb;

	request_headers_done(request);

	if (request->status != OBS_STATUS_OK) {
		return 0;
	}

	if ((request->httpResponseCode < 200) ||
		(request->httpResponseCode > 299)) {
		request->status = error_parser_add
		(&(request->errorParser), (char*)ptr, (int)len);
	}
	else if (request->fromS3Callback) {
		request->status = (*(request->fromS3Callback))
			((int)len, (char*)ptr, request->callback_data);
	}
	else {
		request->status = OBS_STATUS_InternalError;
	}

	return ((request->status == OBS_STATUS_OK) ? (size_t)len : 0);
}


// ===================== request_util end ===============

static void request_deinitialize(http_request* request)
{
	if (request->headers) {
		curl_slist_free_all(request->headers);
	}

	// TODO: error_parser_deinitialize(&(request->errorParser));

	curl_easy_reset(request->curl);
}

void request_destroy(http_request* request)
{
	request_deinitialize(request);
	curl_easy_cleanup(request->curl);
	free(request);
	request = NULL;
}


static int sockopt_callback(const void* clientp, curl_socket_t curlfd, curlsocktype purpose)
{
	(void)purpose;
	int val = *(int*)clientp;
	setsockopt(curlfd, SOL_SOCKET, SO_RCVBUF, (const char*)&val, sizeof(val));
	return CURL_SOCKOPT_OK;
}

void OSSRequest::release_token()
{
	FScopeLock ScopeLock(&RequestLock);
	if (current_request_cnt > 0)
	{
		current_request_cnt--;
	}
}

static obs_status compose_uri(char* buffer, int buffer_size,
	const obs_bucket_context* bucketContext,
	const char* urlEncodedKey,
	const char* subResource, const char* queryParams,
	temp_auth_info* tmpAuth, int temp_auth_flag)
{
	int len = 0;

	enum
	{
		Mark_Question,
		Mark_And
	};
	int appendBeforeTempSignature = Mark_Question;

	uri_append("http%s://", (bucketContext->protocol == OBS_PROTOCOL_HTTP) ? "" : "s");
	const char* host_name = bucketContext->host_name;
	if (bucketContext->bucket_name && bucketContext->bucket_name[0])
	{
		if (bucketContext->uri_style == OBS_URI_STYLE_VIRTUALHOST) {
			uri_append("%s.%s", bucketContext->bucket_name, host_name);
		}
		else {
			uri_append("%s/%s", host_name, bucketContext->bucket_name);
		}
	}
	else {
		uri_append("%s", host_name);
	}
	uri_append("%s", "/");
	uri_append("%s", urlEncodedKey);

	if (subResource && subResource[0])
	{
		uri_append("?%s", subResource);
		appendBeforeTempSignature = Mark_And;
	}

	if (queryParams) {
		uri_append("%s%s", (subResource && subResource[0]) ? "&" : "?",
			queryParams);
		appendBeforeTempSignature = Mark_And;
	}
	if (temp_auth_flag == 1) {
		uri_append("%s%s", (appendBeforeTempSignature == Mark_And) ? "&" : "?",
			tmpAuth->tempAuthParams);
	}
	return OBS_STATUS_OK;
}


obs_status set_curl_easy_setopt_safe(http_request* request, const request_params* params)
{
	CURLcode status = CURLE_OK;
	switch (params->httpRequestType) {
	case http_request_type_head:
		curl_easy_setopt_safe(CURLOPT_NOBODY, 1);
		break;
	case http_request_type_put:
	case http_request_type_copy:
		curl_easy_setopt_safe(CURLOPT_UPLOAD, 1);
		break;
	case http_request_type_delete:
		curl_easy_setopt_safe(CURLOPT_CUSTOMREQUEST, "DELETE");
		break;
	case http_request_type_post:
		curl_easy_setopt_safe(CURLOPT_POST, 1L);
		break;
	case http_request_type_options:
		curl_easy_setopt_safe(CURLOPT_CUSTOMREQUEST, "OPTIONS");
		break;
	default:
		break;
	}

	return OBS_STATUS_OK;
}


static obs_status setup_curl(http_request* request,
	const request_params* params,
	const request_computed_values* values)
{
	CURLcode status = CURLE_OK;
	curl_easy_setopt_safe(CURLOPT_PRIVATE, request);
	curl_easy_setopt_safe(CURLOPT_HEADERDATA, request);
	curl_easy_setopt_safe(CURLOPT_HEADERFUNCTION, &curl_header_func);
	curl_easy_setopt_safe(CURLOPT_READFUNCTION, &curl_read_func);
	curl_easy_setopt_safe(CURLOPT_READDATA, request);
	curl_easy_setopt_safe(CURLOPT_WRITEFUNCTION, &curl_write_func);
	curl_easy_setopt_safe(CURLOPT_WRITEDATA, request);
	curl_easy_setopt_safe(CURLOPT_FILETIME, 1);
	curl_easy_setopt_safe(CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt_safe(CURLOPT_NOPROGRESS, 1);
	curl_easy_setopt_safe(CURLOPT_TCP_NODELAY, 1);
	if (params->request_option.ssl_cipher_list != NULL) {
		curl_easy_setopt_safe(CURLOPT_SSL_CIPHER_LIST, params->request_option.ssl_cipher_list);
	}
	if (params->request_option.proxy_host != NULL) {
		curl_easy_setopt_safe(CURLOPT_PROXY, params->request_option.proxy_host);
	}
	if (params->request_option.proxy_auth != NULL) {
		curl_easy_setopt_safe(CURLOPT_PROXYUSERPWD, params->request_option.proxy_auth);
	}
	curl_easy_setopt_safe(CURLOPT_NETRC, CURL_NETRC_IGNORED);
	if (1 == params->isCheckCA) {
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 1);
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0);
		curl_easy_setopt_safe(CURLOPT_SSL_CTX_DATA, (void*)params->bucketContext.certificate_info);
		curl_easy_setopt_safe(CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
	}
	else {
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0);
	}

	curl_easy_setopt_safe(CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt_safe(CURLOPT_MAXREDIRS, 10);
	curl_easy_setopt_safe(CURLOPT_USERAGENT, userAgentG);
	curl_easy_setopt_safe(CURLOPT_LOW_SPEED_LIMIT, params->request_option.speed_limit);
	curl_easy_setopt_safe(CURLOPT_LOW_SPEED_TIME, params->request_option.speed_time);
	curl_easy_setopt_safe(CURLOPT_CONNECTTIMEOUT_MS, params->request_option.connect_time);
	curl_easy_setopt_safe(CURLOPT_TIMEOUT, params->request_option.max_connected_time);
	curl_easy_setopt_safe(CURLOPT_BUFFERSIZE, params->request_option.buffer_size);

	if ((params->httpRequestType == http_request_type_put) || (params->httpRequestType == http_request_type_post)) {
		char header[256] = { 0 };
		int ret = snprintf_s(header, sizeof(header), _TRUNCATE, "Content-Length: %llu",
			(unsigned long long) params->toObsCallbackTotalSize);
		OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
		request->headers = curl_slist_append(request->headers, header);
		request->headers = curl_slist_append(request->headers, "Transfer-Encoding:");
	}
	else if (params->httpRequestType == http_request_type_copy) {
		request->headers = curl_slist_append(request->headers, "Transfer-Encoding:");
	}
	append_standard_header(cacheControlHeader);
	if (values->contentTypeHeader[0]) {
		request->headers = curl_slist_append(request->headers, values->contentTypeHeader);
	}
	else {
		request->headers = curl_slist_append(request->headers, "Content-Type:");
	}
	append_standard_header(md5Header);
	append_standard_header(contentDispositionHeader);
	append_standard_header(contentEncodingHeader);
	append_standard_header(expiresHeader);
	append_standard_header(ifModifiedSinceHeader);
	append_standard_header(ifUnmodifiedSinceHeader);
	append_standard_header(ifMatchHeader);
	append_standard_header(ifNoneMatchHeader);
	append_standard_header(rangeHeader);
	append_standard_header(authorizationHeader);
	append_standard_header(userAgent);
	append_standard_header(websiteredirectlocationHeader);
	int i;
	for (i = 0; i < values->amzHeadersCount; i++) {
		request->headers = curl_slist_append(request->headers, values->amzHeaders[i]);
	}
	curl_easy_setopt_safe(CURLOPT_HTTPHEADER, request->headers);
	// COMMLOG(OBS_LOGINFO, "%s request_perform setup_url: uri request_get = %s", __FUNCTION__, request->uri);
	curl_easy_setopt_safe(CURLOPT_URL, request->uri);
	int recvbuffersize = 256 * 1024;
	if (params->request_option.bbr_switch == OBS_BBR_OPEN) {
		curl_easy_setopt_safe(CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
		curl_easy_setopt_safe(CURLOPT_SOCKOPTDATA, &recvbuffersize);
	}
// 	if( params->request_option.http2_switch == OBS_HTTP2_OPEN )
// 	{
// 		curl_easy_setopt_safe(CURLOPT_HTTP_VERSION ,CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
// 	}

	curl_easy_setopt_safe(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	return set_curl_easy_setopt_safe(request, params);
}


obs_status OSSRequest::request_get(const request_params* params,
	const request_computed_values* values,
	http_request** reqReturn,
	temp_auth_info* stTempAuthInfo)
{
	http_request* request = 0;
	int temp_auth_flag = 0;
	int is_no_token = 0;
	if (params->temp_auth)
	{
		temp_auth_flag = 1;
	}

	{
	FScopeLock ScopeLock(&RequestLock);
	if ((current_request_cnt + 1) > request_online_max) {
		is_no_token = 1;
	}
	else {
		current_request_cnt++;
		if (requestStackCountG) {
			request = requestStackG[--requestStackCountG];
		}
	}
	}

	if (is_no_token)
	{
		// COMMLOG(OBS_LOGWARN, "request is no token,cur token num=%u", current_request_cnt);
		return OBS_STATUS_NoToken;
	}

	if (request) {
		request_deinitialize(request);
	}
	else {
		if ((request = (http_request*)malloc(sizeof(http_request))) == NULL) {
			release_token();
			return OBS_STATUS_OutOfMemory;
		}
		FMemory::Memset(request, 0, sizeof(http_request));
		if ((request->curl = curl_easy_init()) == NULL) {
			free(request);
			request = NULL;
			release_token();
			return OBS_STATUS_FailedToIInitializeRequest;
		}
	}

	request->prev = 0;
	request->next = 0;
	request->status = OBS_STATUS_OK;
	obs_status status = OBS_STATUS_OK;
	request->headers = 0;
	if ((status = compose_uri(request->uri, sizeof(request->uri),
		&(params->bucketContext), values->urlEncodedKey,
		params->subResource, params->queryParams, stTempAuthInfo, temp_auth_flag)) != OBS_STATUS_OK) {
		curl_easy_cleanup(request->curl);
		free(request);
		request = NULL;
		release_token();
		return status;
	}
	if ((status = setup_curl(request, params, values)) != OBS_STATUS_OK) {
		curl_easy_cleanup(request->curl);
		free(request);
		request = NULL;
		release_token();
		return status;
	}
	request->properties_callback = params->properties_callback;
	request->toS3Callback = params->toObsCallback;
	request->toS3CallbackBytesRemaining = params->toObsCallbackTotalSize;
	request->fromS3Callback = params->fromObsCallback;
	request->complete_callback = params->complete_callback;
	request->callback_data = params->callback_data;
	response_headers_handler::response_headers_handler_initialize(&(request->responseHeadersHandler));
	request->propertiesCallbackMade = 0;
	//TODO: error_parser_initialize(&(request->errorParser));
	*reqReturn = request;
	return OBS_STATUS_OK;
}


void request_finish_log(struct curl_slist* tmp, OBS_LOGLEVEL logLevel) {
	if (0 != strncmp(tmp->data, "Authorization:", 14)) {
		if (0 == strncmp(tmp->data, "x-amz-server-side-encryption-customer-key:", 42)) {
			// COMMLOG(logLevel, "x-amz-server-side-encryption-customer-key:***********");
		}
		else if (0 == strncmp(tmp->data, "x-obs-server-side-encryption-customer-key:", 42)) {
			// COMMLOG(logLevel, "x-obs-server-side-encryption-customer-key:***********");
		}
		else if (0 == strncmp(tmp->data, "x-amz-server-side-encryption-customer-key-md5:", 46)) {
			// COMMLOG(logLevel, "x-amz-server-side-encryption-customer-key-md5:**********");
		}
		else if (0 == strncmp(tmp->data, "x-obs-server-side-encryption-customer-key-md5:", 46)) {
			// COMMLOG(logLevel, "x-obs-server-side-encryption-customer-key-md5:**********");
		}
		else if (0 == strncmp(tmp->data, "x-amz-copy-source-server-side-encryption-customer-key:", 54)) {
			// COMMLOG(logLevel, "x-amz-copy-source-server-side-encryption-customer-key:**********");
		}
		else if (0 == strncmp(tmp->data, "x-obs-copy-source-server-side-encryption-customer-key:", 54)) {
			// COMMLOG(logLevel, "x-obs-copy-source-server-side-encryption-customer-key:**********");
		}
		else if (0 == strncmp(tmp->data, "x-amz-copy-source-server-side-encryption-customer-key-md5:", 58)) {
			// COMMLOG(logLevel, "x-amz-copy-source-server-side-encryption-customer-key-md5:************");
		}
		else if (0 == strncmp(tmp->data, "x-obs-copy-source-server-side-encryption-customer-key-md5:", 58)) {
			// COMMLOG(logLevel, "x-obs-copy-source-server-side-encryption-customer-key-md5:************");
		}
		else if (0 == strncmp(tmp->data, "x-amz-security-token:", strlen("x-amz-security-token:"))) {
			// COMMLOG(logLevel, "x-amz-security-token:************");
		}
		else if (0 == strncmp(tmp->data, "x-obs-security-token:", strlen("x-obs-security-token:"))) {
			// COMMLOG(logLevel, "x-obs-security-token:************");
		}
		else {
			// COMMLOG(logLevel, "%s", tmp->data);
		}
	}
}




int sort_bucket_name(const char* bucket_name, const char* host_name)
{
	int index = -1;
	for (int i = 0; i < (use_api_index + 1); i++)
	{
		if (!strncmp(api_switch[i].bucket_name, bucket_name, strlen(bucket_name)) &&
			!strncmp(api_switch[i].host_name, host_name, strlen(host_name)))
		{
			index = i;
			break;
		}
	}
	if (index == -1) {
		if (use_api_index == API_STACK_SIZE * 3 / 4) {
			API_STACK_SIZE = 2 * API_STACK_SIZE;
			obs_s3_switch* temp_api_switch = api_switch;
			api_switch = (obs_s3_switch*)malloc(sizeof(obs_s3_switch) * API_STACK_SIZE);
			//api_switch = (obs_s3_switch *)realloc(api_switch,sizeof(obs_s3_switch)*API_STACK_SIZE);
			if (api_switch == NULL) {
				use_api_index--;
				API_STACK_SIZE = API_STACK_SIZE / 2;
				api_switch = temp_api_switch;
			}
			else {
				FMemory::Memcpy(api_switch, temp_api_switch, sizeof(obs_s3_switch) * API_STACK_SIZE / 2);
				free(temp_api_switch);
			}
		}
	}
	return index;
}

obs_status header_name_tolower_copy(request_computed_values* values, int* len, const char* str, int l) {
	values->amzHeaders[values->amzHeadersCount++] = &(values->amzHeadersRaw[*len]);
	if (((*len) + l) >= (int)sizeof(values->amzHeadersRaw)) {
		return OBS_STATUS_MetadataHeadersTooLong;
	}
	int todo = l;
	while (todo--) {
		if ((*(str) >= 'A') && (*(str) <= 'Z')) {
			values->amzHeadersRaw[(*len)++] = 'a' + (*(str)-'A');
		}
		else {
			values->amzHeadersRaw[(*len)++] = *(str);
		}
		(str)++;
	}
	return OBS_STATUS_OK;
}

obs_status headers_append(int* len, request_computed_values* values, int isNewHeader,
	const char* format, const char* chstr1, const char* chstr2)
{
	if (isNewHeader)
	{
		values->amzHeaders[values->amzHeadersCount++] = &(values->amzHeadersRaw[*len]);
	}
	if (chstr2)
	{
		if (snprintf_s(&(values->amzHeadersRaw[*len]), sizeof(values->amzHeadersRaw) - (*len),
			_TRUNCATE, format, chstr1, chstr2) > 0)
		{
			(*len) += snprintf_s(&(values->amzHeadersRaw[*len]),
				sizeof(values->amzHeadersRaw) - (*len), _TRUNCATE, format, chstr1, chstr2);
		}
	}
	else {
		if (snprintf_s(&(values->amzHeadersRaw[*len]), sizeof(values->amzHeadersRaw) - (*len),
			_TRUNCATE, format, chstr1) > 0)
		{
			(*len) += snprintf_s(&(values->amzHeadersRaw[*len]),
				sizeof(values->amzHeadersRaw) - (*len), _TRUNCATE, format, chstr1);
		}
	}
	if (*len >= (int)sizeof(values->amzHeadersRaw)) {
		return OBS_STATUS_MetadataHeadersTooLong;
	}
	while ((*len > 0) && (values->amzHeadersRaw[*len - 1] == ' ')) {
		(*len)--;
	}
	values->amzHeadersRaw[(*len)++] = 0;
	return OBS_STATUS_OK;
}


obs_status headers_append_acl(obs_canned_acl acl, request_computed_values* values, int* len, const request_params* params)
{
	char* cannedAclString = NULL;
	switch (acl)
	{
	case OBS_CANNED_ACL_PRIVATE:
		cannedAclString = "private";
		break;
	case OBS_CANNED_ACL_PUBLIC_READ:
		cannedAclString = "public-read";
		break;
	case OBS_CANNED_ACL_PUBLIC_READ_WRITE:
		cannedAclString = "public-read-write";
		break;
	case OBS_CANNED_ACL_AUTHENTICATED_READ:
		cannedAclString = "authenticated-read";
		break;
	case OBS_CANNED_ACL_BUCKET_OWNER_READ:
		cannedAclString = "bucket-owner-read";
		break;
	case OBS_CANNED_ACL_BUCKET_OWNER_FULL_CONTROL:
		cannedAclString = "bucket-owner-full-control";
		break;
	case OBS_CANNED_ACL_LOG_DELIVERY_WRITE:
		cannedAclString = "log-delivery-write";
		break;
	case OBS_CANNED_ACL_PUBLIC_READ_DELIVERED:
		cannedAclString = "public-read-delivered";
		break;
	case OBS_CANNED_ACL_PUBLIC_READ_WRITE_DELIVERED:
		cannedAclString = "public-read-write-delivered";
		break;
	case OBS_CANNED_ACL_BUTT:
		cannedAclString = NULL;
		break;
	default:
		cannedAclString = "authenticated-read";
		break;
	}

	if (params->use_api == OBS_USE_API_S3) {
		return headers_append(len, values, 1, "x-amz-acl: %s", cannedAclString, NULL);
	}
	else
	{
		return headers_append(len, values, 1, "x-obs-acl: %s", cannedAclString, NULL);
	}

}


obs_status headers_append_az_redundancy(obs_az_redundancy az_redundancy, request_computed_values* values, int* len, const request_params* params)
{
	char* azRedundancyString = NULL;
	switch (az_redundancy)
	{
	case OBS_REDUNDANCY_3AZ:
		azRedundancyString = "3az";
		break;
	default:
		break;
	}

	if (params->use_api == OBS_USE_API_OBS && azRedundancyString != NULL)
	{
		return headers_append(len, values, 1, "x-obs-az-redundancy: %s", azRedundancyString, NULL);
	}

	return OBS_STATUS_OK;
}

obs_status headers_append_domin(const obs_put_properties* properties,
	request_computed_values* values, int* len)
{
	char* grant_domain = NULL;
	if (!properties->domain_config)
	{
		return OBS_STATUS_OK;
	}

	switch (properties->domain_config->grant_domain)
	{
	case OBS_GRANT_READ:
		grant_domain = "x-obs-grant-read: %s";
		break;
	case OBS_GRANT_WRITE:
		grant_domain = "x-obs-grant-write: %s";
		break;
	case OBS_GRANT_READ_ACP:
		grant_domain = "x-obs-grant-read-acp: %s";
		break;
	case OBS_GRANT_WRITE_ACP:
		grant_domain = "x-obs-grant-write-acp: %s";
		break;
	case OBS_GRANT_FULL_CONTROL:
		grant_domain = "x-obs-grant-full-control: %s";
		break;
	case OBS_GRANT_FULL_CONTROL_DELIVERED:
		grant_domain = "x-obs-grant-full-control-delivered: %s";
		break;
	case OBS_GRANT_READ_DELIVERED:
		grant_domain = "x-obs-grant-read-delivered: %s";
		break;
	case OBS_GRANT_BUTT:
		grant_domain = NULL;
		break;
	default:
		grant_domain = NULL;
		break;
	}

	if (NULL != grant_domain) {
		return headers_append(len, values, 1, grant_domain, properties->domain_config->domain, NULL);
	}

	return OBS_STATUS_OK;
}

obs_status headers_append_bucket_type(obs_bucket_type bucket_type,
	request_computed_values* values, int* len)
{
	if (bucket_type == OBS_BUCKET_PFS) {
		return headers_append(len, values, 1, "x-obs-fs-file-interface: %s", "Enabled", NULL);
	}
	return OBS_STATUS_OK;
}

obs_status headers_append_storage_class(obs_storage_class input_storage_class,
	request_computed_values* values, const request_params* params, int* len)
{
	const char* storageClassString = NULL;
	if (params->use_api == OBS_USE_API_S3) {
		switch (input_storage_class) {
		case OBS_STORAGE_CLASS_STANDARD_IA:
			storageClassString = "STANDARD_IA";
			break;
		case OBS_STORAGE_CLASS_GLACIER:
			storageClassString = "GLACIER";
			break;
		default:
			storageClassString = "STANDARD";
			break;
		}
	}
	else {
		switch (input_storage_class) {
		case OBS_STORAGE_CLASS_STANDARD_IA:
			storageClassString = "WARM";
			break;
		case OBS_STORAGE_CLASS_GLACIER:
			storageClassString = "COLD";
			break;
		default:
			storageClassString = "STANDARD";
			break;
		}
	}

	if (params->use_api == OBS_USE_API_S3) {
		if (params->storageClassFormat == storage_class) {
			return headers_append(len, values, 1, "x-amz-storage-class: %s", storageClassString, NULL);
		}
		else if (params->storageClassFormat == default_storage_class) {
			return headers_append(len, values, 1, "x-default-storage-class: %s", storageClassString, NULL);
		}
	}
	else
	{
		if (params->storageClassFormat != no_need_storage_class) {
			return headers_append(len, values, 1, "x-obs-storage-class: %s", storageClassString, NULL);
		}
	}

	return OBS_STATUS_OK;
}

obs_status headers_append_epid(const char* epid, request_computed_values* values, const request_params* params, int* len)
{
	if (params->use_api == OBS_USE_API_S3) {
		return headers_append(len, values, 1, "x-amz-epid: %s", epid, NULL);
	}
	else
	{
		return headers_append(len, values, 1, "x-obs-epid: %s", epid, NULL);
	}
}

obs_status request_compose_properties(request_computed_values* values, const request_params* params, int* len)
{
	const obs_put_properties* properties = params->put_properties;
	int i;
	int j;
	obs_status ret_status;

	if (properties != NULL)
	{
		// The name field of the user-defined metadata cannot be duplicated
		for (i = 0; i < properties->meta_data_count; i++)
		{
			for (j = i + 1; j < properties->meta_data_count; j++)
			{
				if (!strcmp(properties->meta_data[i].name, properties->meta_data[j].name))
				{
					return  OBS_STATUS_MetadataNameDuplicate;
				}
			}
		}

		for (i = 0; i < properties->meta_data_count; i++) {
			const obs_name_value* property = &(properties->meta_data[i]);
			char headerName[OBS_MAX_METADATA_SIZE - sizeof(": v")];
			int l = 0;
			if (params->use_api == OBS_USE_API_S3) {
				l = snprintf_s(headerName, sizeof(headerName), _TRUNCATE,
					OBS_METADATA_HEADER_NAME_PREFIX "%s",
					property->name);
			}
			else {
				l = snprintf_s(headerName, sizeof(headerName), _TRUNCATE,
					"x-obs-meta-%s",
					property->name);
			}
			char* hn = headerName;
			if (header_name_tolower_copy(values, len, hn, l) != OBS_STATUS_OK) {
				return header_name_tolower_copy(values, len, hn, l);
			}
			if (headers_append(len, values, 0, ": %s", property->value, NULL) != OBS_STATUS_OK) {
				return headers_append(len, values, 0, ": %s", property->value, NULL);
			}
		}

		ret_status = headers_append_acl(properties->canned_acl, values, len, params);
		if (OBS_STATUS_OK != ret_status) {
			return ret_status;
		}

		ret_status = headers_append_az_redundancy(properties->az_redundancy, values, len, params);
		if (OBS_STATUS_OK != ret_status) {
			return ret_status;
		}

		ret_status = headers_append_domin(properties, values, len);
		if (OBS_STATUS_OK != ret_status) {
			return ret_status;
		}
	}

	ret_status = headers_append_bucket_type(params->bucketContext.bucket_type,
		values, len);
	ret_status = headers_append_storage_class(params->bucketContext.storage_class,
		values, params, len);
	if (OBS_STATUS_OK != ret_status)
	{
		// COMMLOG(OBS_LOGERROR, "compose_properties err,return %d.\n", ret_status);
		return ret_status;
	}

	if (params->bucketContext.epid != NULL) {
		ret_status = headers_append_epid(params->bucketContext.epid, values, params, len);
	}
	return ret_status;
}

obs_status headers_append_list_bucket_type(obs_bucket_list_type bucket_list_type,
	request_computed_values* values, int* len)
{
	if (bucket_list_type == OBS_BUCKET_LIST_OBJECT)
	{
		return headers_append(len, values, 1, "x-obs-bucket-type: %s", "OBJECT", NULL);
	}
	else if (bucket_list_type == OBS_BUCKET_LIST_PFS)
	{
		return headers_append(len, values, 1, "x-obs-bucket-type: %s", "POSIX", NULL);
	}
	return OBS_STATUS_OK;
}

obs_status request_compose_encrypt_params_s3(request_computed_values* values, const request_params* params, int* len)
{
	obs_status status = OBS_STATUS_OK;
	if (params->encryption_params->encryption_type == OBS_ENCRYPTION_KMS) {
		if (params->encryption_params->kms_server_side_encryption) {
			if ((status = headers_append(len, values, 1,
				"x-amz-server-side-encryption: %s",
				params->encryption_params->kms_server_side_encryption, NULL)) != OBS_STATUS_OK) {
				return status;
			}
		}
		if (params->encryption_params->kms_key_id)
			if ((status = headers_append(len, values, 1,
				"x-amz-server-side-encryption-aws-kms-key-id: %s",
				params->encryption_params->kms_key_id, NULL)) != OBS_STATUS_OK) {
				return status;
			}
	}

	if (params->encryption_params->encryption_type == OBS_ENCRYPTION_SSEC) {
		if (params->encryption_params->ssec_customer_algorithm)
			if ((status = headers_append(len, values, 1,
				"x-amz-server-side-encryption-customer-algorithm: %s",
				params->encryption_params->ssec_customer_algorithm, NULL)) != OBS_STATUS_OK) {
				return status;
			}
		if (params->encryption_params->ssec_customer_key)
		{
			if ((status = headers_append(len, values, 1,
				"x-amz-server-side-encryption-customer-key: %s",
				params->encryption_params->ssec_customer_key, NULL)) != OBS_STATUS_OK) {
				return status;
			}
			char buffer[SSEC_KEY_MD5_LENGTH] = { 0 };
			char ssec_key_md5[SSEC_KEY_MD5_LENGTH] = { 0 };


			
// 			 * Decodes a Base64 string into a FString
// 			 *
// 			 * @param Source The Base64 encoded string
// 			 * @param OutDest Receives the decoded string data
// 
// 			static bool Decode(const FString & Source, FString & OutDest);
// 
// 
// 			 * Decodes a Base64 string into an array of bytes
// 			 *
// 			 * @param Source The Base64 encoded string
// 			 * @param Dest Array to receive the decoded data
// 
// 			static bool Decode(const FString & Source, TArray<uint8>&Dest);
// 
// 
// 			 * Decodes a Base64 string into a preallocated buffer
// 			 *
// 			 * @param Source The Base64 encoded string
// 			 * @param Length Length of the Base64 encoded string
// 			 * @param Dest Buffer to receive the decoded data
// 			 *
// 			 * @return true if the buffer was decoded, false if it was invalid.
// 
// 			template<typename CharType> static bool Decode(const CharType * Source, uint32 Length, uint8 * Dest);
// 
// 			char* base64Decode(const char* base64Char, const long base64CharSize, char* originChar, long originCharSize);
// 
// 			base64Decode(params->encryption_params->ssec_customer_key,
// 				strlen(params->encryption_params->ssec_customer_key), buffer, SSEC_KEY_MD5_LENGTH);
// 			compute_md5(buffer, strlen(buffer), ssec_key_md5, SSEC_KEY_MD5_LENGTH);
// 			
			if ((status = headers_append(len, values, 1,
				"x-amz-server-side-encryption-customer-key-md5: %s",
				ssec_key_md5, NULL)) != OBS_STATUS_OK) {
				return status;
			}
		}
		if (params->encryption_params->des_ssec_customer_algorithm)
			if ((status = headers_append(len, values, 1,
				"x-amz-copy-source-server-side-encryption-customer-algorithm: %s",
				params->encryption_params->des_ssec_customer_algorithm, NULL)) != OBS_STATUS_OK) {
				return status;
			}
		if (params->encryption_params->des_ssec_customer_key)
		{
			if ((status = headers_append(len, values, 1,
				"x-amz-copy-source-server-side-encryption-customer-key: %s",
				params->encryption_params->des_ssec_customer_key, NULL)) != OBS_STATUS_OK) {
				return status;
			}
			char buffer[SSEC_KEY_MD5_LENGTH] = { 0 };
			char ssec_key_md5[SSEC_KEY_MD5_LENGTH] = { 0 };
			// TODO::
			
// 			base64Decode(params->encryption_params->ssec_customer_key,
// 				strlen(params->encryption_params->ssec_customer_key), buffer, SSEC_KEY_MD5_LENGTH);
// 			compute_md5(buffer, strlen(buffer), ssec_key_md5, SSEC_KEY_MD5_LENGTH);
// 			status = headers_append(len, values, 1,
// 				"x-amz-copy-source-server-side-encryption-customer-key-md5: %s",
// 				ssec_key_md5, NULL);
				
		}
	}
	return status;
}



obs_status request_compose_encrypt_params_obs(request_computed_values* values, const request_params* params, int* len)
{
	obs_status status = OBS_STATUS_OK;
	if (params->encryption_params->encryption_type == OBS_ENCRYPTION_KMS) {
		if (params->encryption_params->kms_server_side_encryption) {
			if ((status = headers_append(len, values, 1,
				"x-obs-server-side-encryption: %s",
				params->encryption_params->kms_server_side_encryption, NULL)) != OBS_STATUS_OK) {
				return status;
			}
		}
		if (params->encryption_params->kms_key_id)
			if ((status = headers_append(len, values, 1,
				"x-obs-server-side-encryption-aws-kms-key-id: %s",
				params->encryption_params->kms_key_id, NULL)) != OBS_STATUS_OK) {
				return status;
			}
	}

	if (params->encryption_params->encryption_type == OBS_ENCRYPTION_SSEC) {
		if (params->encryption_params->ssec_customer_algorithm)
			if ((status = headers_append(len, values, 1,
				"x-obs-server-side-encryption-customer-algorithm: %s",
				params->encryption_params->ssec_customer_algorithm, NULL)) != OBS_STATUS_OK) {
				return status;
			}
		if (params->encryption_params->ssec_customer_key)
		{
			if ((status = headers_append(len, values, 1,
				"x-obs-server-side-encryption-customer-key: %s",
				params->encryption_params->ssec_customer_key, NULL)) != OBS_STATUS_OK) {
				return status;
			}
			char buffer[SSEC_KEY_MD5_LENGTH] = { 0 };
			char ssec_key_md5[SSEC_KEY_MD5_LENGTH] = { 0 };
			// TODO::
	
// 			base64Decode(params->encryption_params->ssec_customer_key,
// 				strlen(params->encryption_params->ssec_customer_key), buffer, SSEC_KEY_MD5_LENGTH);
// 			compute_md5(buffer, strlen(buffer), ssec_key_md5, SSEC_KEY_MD5_LENGTH);
// 			if ((status = headers_append(len, values, 1,
// 				"x-obs-server-side-encryption-customer-key-md5: %s",
// 				ssec_key_md5, NULL)) != OBS_STATUS_OK) {
// 				return status;
// 			}
		
		}
		if (params->encryption_params->des_ssec_customer_algorithm)
			if ((status = headers_append(len, values, 1,
				"x-obs-copy-source-server-side-encryption-customer-algorithm: %s",
				params->encryption_params->des_ssec_customer_algorithm, NULL)) != OBS_STATUS_OK) {
				return status;
			}
		if (params->encryption_params->des_ssec_customer_key)
		{
			if ((status = headers_append(len, values, 1,
				"x-obs-copy-source-server-side-encryption-customer-key: %s",
				params->encryption_params->des_ssec_customer_key, NULL)) != OBS_STATUS_OK) {
				return status;
			}
			char buffer[SSEC_KEY_MD5_LENGTH] = { 0 };
			char ssec_key_md5[SSEC_KEY_MD5_LENGTH] = { 0 };
			//	TODO::


// 			base64Decode(params->encryption_params->ssec_customer_key,
// 				strlen(params->encryption_params->ssec_customer_key), buffer, SSEC_KEY_MD5_LENGTH);
// 			compute_md5(buffer, strlen(buffer), ssec_key_md5, SSEC_KEY_MD5_LENGTH);
// 			status = headers_append(len, values, 1,
// 				"x-obs-copy-source-server-side-encryption-customer-key-md5: %s",
// 				ssec_key_md5, NULL);

		}
	}
	return status;
}


obs_status request_compose_encrypt_params(request_computed_values* values, const request_params* params, int* len)
{
	if (params->use_api == OBS_USE_API_S3) {
		return request_compose_encrypt_params_s3(values, params, len);
	}
	else {
		return request_compose_encrypt_params_obs(values, params, len);
	}
}

obs_status request_compose_cors_conf(request_computed_values* values, const request_params* params, int* len)
{
	obs_status status = OBS_STATUS_OK;
	const obs_cors_conf* corsConf = params->corsConf;
	if (corsConf->origin) {
		if ((status = headers_append(len, values, 1, "Origin: %s", corsConf->origin, NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	unsigned int i;
	for (i = 0; i < corsConf->rmNumber; i++)
	{
		if ((status = headers_append(len, values, 1, "Access-Control-Request-Method: %s",
			corsConf->requestMethod[i], NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	for (i = 0; i < corsConf->rhNumber; i++)
	{
		if ((status = headers_append(len, values, 1, "Access-Control-Request-Headers: %s",
			corsConf->requestHeader[i], NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	return status;
}

obs_status request_compose_data(request_computed_values* values, int* len, const request_params* params)
{
	time_t now = time(NULL);
	char date[64] = { 0 };
	struct tm flagTemp;
	struct tm* flag = NULL;
#if defined __GNUC__ || defined LINUX            
	flag = gmtime_r(&now, &flagTemp);
#else
	if (_gmtime64_s(&flagTemp, &now) == 0) {
		flag = &flagTemp;
	}
#endif

	if (flag != NULL) {
		strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &flagTemp);
	}
	else {
		// COMMLOG(OBS_LOGWARN, "in request_compose_data, gmtime failed\n");
	}
	if (params->use_api == OBS_USE_API_S3) {
		if (headers_append(len, values, 1, "x-amz-date: %s", date, NULL) != OBS_STATUS_OK) {
			return headers_append(len, values, 1, "x-amz-date: %s", date, NULL);
		}
	}
	else {
		if (headers_append(len, values, 1, "x-obs-date: %s", date, NULL) != OBS_STATUS_OK) {
			return headers_append(len, values, 1, "x-obs-date: %s", date, NULL);
		}
	}
	return OBS_STATUS_OK;
}

int check_copy_params(const request_params* params) {
	return params->subResource != NULL && !strcmp(params->subResource, "metadata") && params->put_properties;
}

obs_status request_compose_token_and_httpcopy_s3(request_computed_values* values, const request_params* params, int* len)
{
	obs_status status = OBS_STATUS_OK;
	const obs_put_properties* properties = params->put_properties;
	obs_bucket_context bucketContext = params->bucketContext;
	if ((bucketContext.token) && (bucketContext.token[0]))
	{
		if ((status = headers_append(len, values, 1, "x-amz-security-token: %s", bucketContext.token, NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	if (params->httpRequestType == http_request_type_copy) {
		if (params->copySourceBucketName && params->copySourceBucketName[0] &&
			params->copySourceKey && params->copySourceKey[0]) {
			if ((status = headers_append(len, values, 1, "x-amz-copy-source: /%s/%s",
				params->copySourceBucketName,
				values->urlEncodedSrcKey)) != OBS_STATUS_OK) {
				return status;
			}
		}
		if (properties && 0 != properties->meta_data_count) {
			if ((status = headers_append(len, values, 1, "%s", "x-amz-metadata-directive: REPLACE", NULL)) != OBS_STATUS_OK) {
				return status;
			}
		}
	}
	else if (check_copy_params(params) && params->put_properties->metadata_action == OBS_REPLACE)
	{
		if ((status = headers_append(len, values, 1, "%s", "x-amz-metadata-directive: REPLACE", NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	else if (check_copy_params(params) && params->put_properties->metadata_action == OBS_REPLACE_NEW)
	{
		if ((status = headers_append(len, values, 1, "%s", "x-amz-metadata-directive: REPLACE_NEW", NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	return status;
}

obs_status request_compose_token_and_httpcopy_obs(request_computed_values* values, const request_params* params, int* len)
{
	obs_status status = OBS_STATUS_OK;
	const obs_put_properties* properties = params->put_properties;
	obs_bucket_context bucketContext = params->bucketContext;
	if ((bucketContext.token) && (bucketContext.token[0]))
	{
		if ((status = headers_append(len, values, 1, "x-obs-security-token: %s", bucketContext.token, NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	if (params->httpRequestType == http_request_type_copy) {
		if (params->copySourceBucketName && params->copySourceBucketName[0] &&
			params->copySourceKey && params->copySourceKey[0]) {
			if ((status = headers_append(len, values, 1, "x-obs-copy-source: /%s/%s",
				params->copySourceBucketName,
				values->urlEncodedSrcKey)) != OBS_STATUS_OK) {
				return status;
			}
		}
		if (properties && 0 != properties->meta_data_count) {
			if ((status = headers_append(len, values, 1, "%s", "x-obs-metadata-directive: REPLACE", NULL)) != OBS_STATUS_OK) {
				return status;
			}
		}
	}
	else if (check_copy_params(params) && params->put_properties->metadata_action == OBS_REPLACE)
	{
		if ((status = headers_append(len, values, 1, "%s", "x-obs-metadata-directive: REPLACE", NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}
	else if (check_copy_params(params) && params->put_properties->metadata_action == OBS_REPLACE_NEW)
	{
		if ((status = headers_append(len, values, 1, "%s", "x-obs-metadata-directive: REPLACE_NEW", NULL)) != OBS_STATUS_OK) {
			return status;
		}
	}

	return status;
}

obs_status request_compose_token_and_httpcopy(request_computed_values* values, const request_params* params, int* len)
{
	if (params->use_api == OBS_USE_API_S3) {
		return request_compose_token_and_httpcopy_s3(values, params, len);
	}
	else {
		return request_compose_token_and_httpcopy_obs(values, params, len);
	}
}


obs_status compose_obs_headers(const request_params* params,
	request_computed_values* values)
{
	const obs_put_properties* properties = params->put_properties;
	const obs_cors_conf* corsConf = params->corsConf;
	const server_side_encryption_params* encryption_params = params->encryption_params;

	values->amzHeadersCount = 0;
	values->amzHeadersRaw[0] = 0;
	int len = 0;
	obs_status status = OBS_STATUS_OK;
	if (properties) {
		if ((status = request_compose_properties(values, params, &len)) != OBS_STATUS_OK) {
			return status;
		}
	}

	if ((status = headers_append_list_bucket_type(params->bucketContext.bucket_list_type,
		values, &len)) != OBS_STATUS_OK)
	{
		return status;
	}

	if (encryption_params) {
		if ((status = request_compose_encrypt_params(values, params, &len)) != OBS_STATUS_OK) {
			return status;
		}
	}
	if (corsConf) {
		if ((status = request_compose_cors_conf(values, params, &len)) != OBS_STATUS_OK) {
			return status;
		}
	}
	if (params->temp_auth == NULL) {
		if ((status = request_compose_data(values, &len, params)) != OBS_STATUS_OK) {
			return status;
		}
	}
	if ((status = request_compose_token_and_httpcopy(values, params, &len)) != OBS_STATUS_OK) {
		return status;
	}
	return status;
}

obs_status compose_put_header(const request_params* params,
	request_computed_values* values)
{
	do_put_header(params, values, "Cache-Control: %s", cache_control, cacheControlHeader,
		OBS_STATUS_BadCacheControl, OBS_STATUS_CacheControlTooLong);
	do_put_header(params, values, "Content-Type: %s", content_type, contentTypeHeader,
		OBS_STATUS_BadContentType, OBS_STATUS_ContentTypeTooLong);
	do_put_header(params, values, "Content-MD5: %s", md5, md5Header, OBS_STATUS_BadMd5,
		OBS_STATUS_Md5TooLong);
	do_put_header(params, values, "Content-Disposition: attachment; file_name=\"%s\"",
		content_disposition_filename, contentDispositionHeader,
		OBS_STATUS_BadContentDispositionFilename,
		OBS_STATUS_ContentDispositionFilenameTooLong);
	do_put_header(params, values, "Content-Encoding: %s", content_encoding,
		contentEncodingHeader, OBS_STATUS_BadContentEncoding,
		OBS_STATUS_ContentEncodingTooLong);
	if (params->put_properties && (params->put_properties->expires >= 0)) {
		time_t t = (time_t)params->put_properties->expires;
		struct tm* flag = gmtime(&t);
		if (flag != NULL) {
			strftime(values->expiresHeader, sizeof(values->expiresHeader),
				"Expires: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else {
		values->expiresHeader[0] = 0;
	}
	if (params->use_api == OBS_USE_API_S3) {
		do_put_header(params, values, "x-amz-website-redirect-location: %s", website_redirect_location,
			websiteredirectlocationHeader, OBS_STATUS_BadContentEncoding,
			OBS_STATUS_ContentEncodingTooLong);
	}
	else {
		do_put_header(params, values, "x-obs-website-redirect-location: %s", website_redirect_location,
			websiteredirectlocationHeader, OBS_STATUS_BadContentEncoding,
			OBS_STATUS_ContentEncodingTooLong);
	}
	return OBS_STATUS_OK;
}


obs_status compose_get_put_header_s3(const request_params* params,
	request_computed_values* values)
{
	int is_true1 = 0;
	int is_true2 = 0;
	is_true1 = (params->get_conditions && (params->get_conditions->if_modified_since >= 0));
	is_true2 = (params->put_properties && params->put_properties->get_conditions &&
		(params->put_properties->get_conditions->if_modified_since >= 0));
	if (is_true1) {
		time_t t = (time_t)params->get_conditions->if_modified_since;
		struct tm* flag = gmtime(&t);
		if (flag != NULL) {
			strftime(values->ifModifiedSinceHeader, sizeof(values->ifModifiedSinceHeader),
				"If-Modified-Since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else if (is_true2) {
		time_t t = (time_t)params->put_properties->get_conditions->if_modified_since;
		struct tm* flag = gmtime(&t);
		if (flag != NULL) {
			strftime(values->ifModifiedSinceHeader, sizeof(values->ifModifiedSinceHeader),
				"x-amz-copy-source-if-modified-since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else {
		values->ifModifiedSinceHeader[0] = 0;
	}

	is_true1 = (params->get_conditions && (params->get_conditions->if_not_modified_since >= 0));
	is_true2 = (params->put_properties && params->put_properties->get_conditions &&
		(params->put_properties->get_conditions->if_not_modified_since >= 0));
	if (is_true1) {
		time_t t = (time_t)params->get_conditions->if_not_modified_since;
		struct tm* flag = gmtime(&t);
		if (flag != NULL)
		{
			strftime(values->ifUnmodifiedSinceHeader, sizeof(values->ifUnmodifiedSinceHeader),
				"If-Unmodified-Since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else if (is_true2) {
		time_t t = (time_t)params->put_properties->get_conditions->if_not_modified_since;

		struct tm* flag = gmtime(&t);
		if (flag != NULL) {
			strftime(values->ifUnmodifiedSinceHeader, sizeof(values->ifUnmodifiedSinceHeader),
				"x-amz-copy-source-if-unmodified-since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else {
		values->ifUnmodifiedSinceHeader[0] = 0;
	}
	do_get_header(params, values, "If-Match: %s", if_match_etag, ifMatchHeader,
		OBS_STATUS_BadIfMatchEtag, OBS_STATUS_IfMatchEtagTooLong);
	if (!values->ifMatchHeader[0]) {
		do_gp_header(params, values, "x-amz-copy-source-if-match: %s", if_match_etag, ifMatchHeader,
			OBS_STATUS_BadIfMatchEtag, OBS_STATUS_IfMatchEtagTooLong);
	}
	do_get_header(params, values, "If-None-Match: %s", if_not_match_etag, ifNoneMatchHeader,
		OBS_STATUS_BadIfNotMatchEtag, OBS_STATUS_IfNotMatchEtagTooLong);
	if (!values->ifNoneMatchHeader[0]) {
		do_gp_header(params, values, "x-amz-copy-source-if-none-match: %s", if_not_match_etag, ifNoneMatchHeader,
			OBS_STATUS_BadIfNotMatchEtag, OBS_STATUS_IfNotMatchEtagTooLong);
	}
	return OBS_STATUS_OK;
}

obs_status compose_get_put_header_obs(const request_params* params,
	request_computed_values* values)
{
	int is_true1 = 0;
	int is_true2 = 0;
	is_true1 = (params->get_conditions && (params->get_conditions->if_modified_since >= 0));
	is_true2 = (params->put_properties && params->put_properties->get_conditions &&
		(params->put_properties->get_conditions->if_modified_since >= 0));
	if (is_true1) {
		time_t t = (time_t)params->get_conditions->if_modified_since;
		struct tm* flag = gmtime(&t);
		if (flag != NULL) {
			strftime(values->ifModifiedSinceHeader, sizeof(values->ifModifiedSinceHeader),
				"If-Modified-Since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else if (is_true2) {
		time_t t = (time_t)params->put_properties->get_conditions->if_modified_since;
		struct tm* flag = gmtime(&t);
		if (flag != NULL) {
			strftime(values->ifModifiedSinceHeader, sizeof(values->ifModifiedSinceHeader),
				"x-obs-copy-source-if-modified-since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else {
		values->ifModifiedSinceHeader[0] = 0;
	}

	is_true1 = (params->get_conditions && (params->get_conditions->if_not_modified_since >= 0));
	is_true2 = (params->put_properties && params->put_properties->get_conditions &&
		(params->put_properties->get_conditions->if_not_modified_since >= 0));
	if (is_true1) {
		time_t t = (time_t)params->get_conditions->if_not_modified_since;
		struct tm* flag = gmtime(&t);
		if (flag != NULL)
		{
			strftime(values->ifUnmodifiedSinceHeader, sizeof(values->ifUnmodifiedSinceHeader),
				"If-Unmodified-Since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else if (is_true2) {
		time_t t = (time_t)params->put_properties->get_conditions->if_not_modified_since;

		struct tm* flag = gmtime(&t);
		if (flag != NULL) {
			strftime(values->ifUnmodifiedSinceHeader, sizeof(values->ifUnmodifiedSinceHeader),
				"x-obs-copy-source-if-unmodified-since: %a, %d %b %Y %H:%M:%S UTC", flag);
		}
	}
	else {
		values->ifUnmodifiedSinceHeader[0] = 0;
	}
	do_get_header(params, values, "If-Match: %s", if_match_etag, ifMatchHeader,
		OBS_STATUS_BadIfMatchEtag, OBS_STATUS_IfMatchEtagTooLong);
	if (!values->ifMatchHeader[0]) {
		do_gp_header(params, values, "x-obs-copy-source-if-match: %s", if_match_etag, ifMatchHeader,
			OBS_STATUS_BadIfMatchEtag, OBS_STATUS_IfMatchEtagTooLong);
	}
	do_get_header(params, values, "If-None-Match: %s", if_not_match_etag, ifNoneMatchHeader,
		OBS_STATUS_BadIfNotMatchEtag, OBS_STATUS_IfNotMatchEtagTooLong);
	if (!values->ifNoneMatchHeader[0]) {
		do_gp_header(params, values, "x-obs-copy-source-if-none-match: %s", if_not_match_etag, ifNoneMatchHeader,
			OBS_STATUS_BadIfNotMatchEtag, OBS_STATUS_IfNotMatchEtagTooLong);
	}
	return OBS_STATUS_OK;
}

obs_status compose_get_put_header(const request_params* params,
	request_computed_values* values)
{
	if (params->use_api == OBS_USE_API_S3) {
		return compose_get_put_header_s3(params, values);
	}
	else {
		return compose_get_put_header_obs(params, values);
	}
}

obs_status compose_range_header(const request_params* params,
	request_computed_values* values)
{
	int ret = 0;
	if (params->get_conditions && (params->get_conditions->start_byte || params->get_conditions->byte_count)) {
		if (params->get_conditions->byte_count) {
			ret = snprintf_s(values->rangeHeader, sizeof(values->rangeHeader), _TRUNCATE,
				"Range: bytes=%llu-%llu",
				(unsigned long long) params->get_conditions->start_byte,
				(unsigned long long) (params->get_conditions->start_byte +
					params->get_conditions->byte_count - 1));
			OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
		}
		else {
			ret = snprintf_s(values->rangeHeader, sizeof(values->rangeHeader), _TRUNCATE,
				"Range: bytes=%llu-",
				(unsigned long long) params->get_conditions->start_byte);
			OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
		}
	}
	else  if (params->put_properties && (params->put_properties->start_byte || params->put_properties->byte_count)) {
		if (params->use_api == OBS_USE_API_S3) {
			if (params->put_properties->byte_count) {
				ret = snprintf_s(values->rangeHeader, sizeof(values->rangeHeader), _TRUNCATE,
					"x-amz-copy-source-range: bytes=%llu-%llu",
					(unsigned long long) params->put_properties->start_byte,
					(unsigned long long) (params->put_properties->start_byte +
						params->put_properties->byte_count - 1));
				OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
			}
			else {
				ret = snprintf_s(values->rangeHeader, sizeof(values->rangeHeader), _TRUNCATE,
					"x-amz-copy-source-range: bytes=%llu-",
					(unsigned long long) params->put_properties->start_byte);
				OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
			}
		}
		else {
			if (params->put_properties->byte_count) {
				ret = snprintf_s(values->rangeHeader, sizeof(values->rangeHeader), _TRUNCATE,
					"x-obs-copy-source-range: bytes=%llu-%llu",
					(unsigned long long) params->put_properties->start_byte,
					(unsigned long long) (params->put_properties->start_byte +
						params->put_properties->byte_count - 1));
				OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
			}
			else {
				ret = snprintf_s(values->rangeHeader, sizeof(values->rangeHeader), _TRUNCATE,
					"x-obs-copy-source-range: bytes=%llu-",
					(unsigned long long) params->put_properties->start_byte);
				OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
			}
		}
	}
	else {
		values->rangeHeader[0] = 0;
	}

	return OBS_STATUS_OK;
}

obs_status compose_standard_headers(const request_params* params,
	request_computed_values* values)
{
	obs_status status = OBS_STATUS_OK;
	if ((status = compose_put_header(params, values)) != OBS_STATUS_OK) {
		return status;
	}

	if ((status = compose_get_put_header(params, values)) != OBS_STATUS_OK) {
		return status;
	}

	if ((status = compose_range_header(params, values)) != OBS_STATUS_OK) {
		return status;
	}
	return OBS_STATUS_OK;
}

void pre_compute_header(const char** sortedHeaders, request_computed_values* values, int* nCount, obs_use_api use_api)
{
	char match_str[7];
	int is_true = 0;
	errno_t err = EOK;
	if (use_api == OBS_USE_API_S3) {
		err = strcpy_s(match_str, sizeof(match_str), "x-amz-");
	}
	else {
		err = strcpy_s(match_str, sizeof(match_str), "x-obs-");
	}
	// CheckAndLogNoneZero(err, "strcpy_s", __FUNCTION__, __LINE__);
	is_true = (0 != values->rangeHeader[0]
		&& strlen(values->rangeHeader) >= strlen(match_str)
		&& 0 == strncmp(match_str, values->rangeHeader, strlen(match_str)));
	if (is_true) {
		sortedHeaders[*nCount] = values->rangeHeader;
		(*nCount)++;
	}

	is_true = (0 != values->ifModifiedSinceHeader[0]
		&& strlen(values->ifModifiedSinceHeader) >= strlen(match_str)
		&& 0 == strncmp(match_str, values->ifModifiedSinceHeader, strlen(match_str)));
	if (is_true) {
		sortedHeaders[*nCount] = values->ifModifiedSinceHeader;
		(*nCount)++;
	}

	is_true = (0 != values->ifUnmodifiedSinceHeader[0]
		&& strlen(values->ifUnmodifiedSinceHeader) >= strlen(match_str)
		&& 0 == strncmp(match_str, values->ifUnmodifiedSinceHeader, strlen(match_str)));
	if (is_true) {
		sortedHeaders[*nCount] = values->ifUnmodifiedSinceHeader;
		(*nCount)++;
	}

	is_true = (0 != values->ifMatchHeader[0]
		&& strlen(values->ifMatchHeader) >= strlen(match_str)
		&& 0 == strncmp(match_str, values->ifMatchHeader, strlen(match_str)));

	if (is_true) {
		sortedHeaders[*nCount] = values->ifMatchHeader;
		(*nCount)++;
	}

	is_true = (0 != values->ifNoneMatchHeader[0]
		&& strlen(values->ifNoneMatchHeader) >= strlen(match_str)
		&& 0 == strncmp(match_str, values->ifNoneMatchHeader, strlen(match_str)));
	if (is_true) {
		sortedHeaders[*nCount] = values->ifNoneMatchHeader;
		(*nCount)++;
	}

	is_true = (0 != values->websiteredirectlocationHeader[0]
		&& strlen(values->websiteredirectlocationHeader) >= strlen(match_str)
		&& 0 == strncmp(match_str, values->websiteredirectlocationHeader, strlen(match_str)));
	if (is_true) {
		sortedHeaders[*nCount] = values->websiteredirectlocationHeader;
		(*nCount)++;
	}

	is_true = (0 != values->tokenHeader[0]
		&& strlen(values->tokenHeader) >= strlen(match_str)
		&& 0 == strncmp(match_str, values->tokenHeader, strlen(match_str)));
	if (is_true) {
		sortedHeaders[*nCount] = values->tokenHeader;
		(*nCount)++;
	}
}

int headerle(const char* header1, const char* header2)
{
	while (1) {
		if (*header1 == ':') {
			return (*header2 != ':');
		}
		else if (*header2 == ':') {
			return 0;
		}
		else if (*header2 < *header1) {
			return 0;
		}
		else if (*header2 > *header1) {
			return 1;
		}
		header1++, header2++;
	}
}

void header_gnome_sort(const char** headers, int size)
{
	int i = 0, last_highest = 0;

	while (i < size) {
		if ((i == 0) || headerle(headers[i - 1], headers[i])) {
			i = ++last_highest;
		}
		else {
			const char* tmp = headers[i];
			headers[i] = headers[i - 1];
			headers[--i] = tmp;
		}
	}
}

void canonicalize_headers(request_computed_values* values, const char** sortedHeaders, int nCount)
{
	int lastHeaderLen = 0, i;
	char* buffer = values->canonicalizedAmzHeaders;
	for (i = 0; i < nCount; i++) {
		const char* header = sortedHeaders[i];
		const char* c = header;
		if ((i > 0) &&
			!strncmp(header, sortedHeaders[i - 1], lastHeaderLen)) {
			*(buffer - 1) = ',';
			c += (lastHeaderLen + 1);
		}
		else {
			while (*c != ' ') {
				*buffer++ = *c++;
			}
			lastHeaderLen = c - header;
			c++;
		}
		while (*c) {
			if ((*c == '\r') && (*(c + 1) == '\n') && is_blank(*(c + 2))) {
				c += 3;
				while (is_blank(*c)) {
					c++;
				}
				while (is_blank(*(buffer - 1))) {
					buffer--;
				}
				continue;
			}
			*buffer++ = *c++;
		}
		*buffer++ = '\n';
	}
	*buffer = 0;
}

void canonicalize_obs_headers(request_computed_values* values, obs_use_api use_api)
{
	const char* sortedHeaders[OBS_MAX_METADATA_COUNT] = { 0 };
	int iLoop = 0;
	int nCount = 0;

	for (iLoop = 0; iLoop < values->amzHeadersCount; iLoop++)
	{
		if (use_api == OBS_USE_API_S3) {
			if (0 == strncmp("x-amz-", values->amzHeaders[iLoop], strlen("x-amz-"))) {
				sortedHeaders[nCount] = values->amzHeaders[iLoop];
				nCount++;
			}
		}
		else {
			if (0 == strncmp("x-obs-", values->amzHeaders[iLoop], strlen("x-obs-"))) {
				sortedHeaders[nCount] = values->amzHeaders[iLoop];
				nCount++;
			}
		}
	}
	pre_compute_header(sortedHeaders, values, &nCount, use_api);
	header_gnome_sort(sortedHeaders, nCount);
	canonicalize_headers(values, sortedHeaders, nCount);
}


void canonicalize_resource(const request_params* params,
	const char* urlEncodedKey,
	char* buffer, int buffer_size)
{
	int len = 0;
	*buffer = 0;
	const obs_bucket_context* bucketContext = &params->bucketContext;
	const char* bucket_name = bucketContext->bucket_name;
	const char* subResource = params->subResource;

	if (bucket_name && bucket_name[0]) {
		buffer[len++] = '/';
		append_request(bucket_name);
	}

	append_request("/");
	if (urlEncodedKey && urlEncodedKey[0]) {
		append_request(urlEncodedKey);
	}

	if (subResource && subResource[0]) {
		if (strcmp(subResource, "truncate") == 0)
		{
			if (params->queryParams && strstr(params->queryParams, "length") != NULL)
			{
				append_request("?");
				append_request(params->queryParams);
				append_request("&");
				append_request(subResource);
			}
		}
		else if (strcmp(subResource, "rename") == 0)
		{
			if (params->queryParams && strstr(params->queryParams, "name") != NULL)
			{
				append_request("?");
				char decoded[3 * 1024];
				urlDecode(decoded, params->queryParams, strlen(params->queryParams));
				append_request(decoded);
				append_request("&");
				append_request(subResource);
			}
		}
		else
		{
			append_request("?");
			append_request(subResource);
		}
	}
}

obs_status compose_temp_header(const request_params* params,
	request_computed_values* values,
	temp_auth_info* stTempAuthInfo)
{
	// COMMLOG(OBS_LOGINFO, "enter compose_temp_header successful");
	int is_true = 0;
	char signbuf[17 + 129 + 129 + 64 +
		(sizeof(values->canonicalizedAmzHeaders) - 1) +
		(sizeof(values->canonicalizedResource) - 1) + 1] = { 0 };
	int len = 0;
	int64 local_expires = 0;
	char* pString = NULL;

	local_expires = (params->temp_auth == NULL) ? 0 : params->temp_auth->expires;
	local_expires = (int64)(local_expires + time(NULL));

	signbuf_attach("%s\n", http_request_type_to_verb(params->httpRequestType));
	signbuf_attach("%s\n", values->md5Header[0] ?
		&(values->md5Header[sizeof("Content-MD5: ") - 1]) : "");
	signbuf_attach("%s\n", values->contentTypeHeader[0] ?
		&(values->contentTypeHeader[sizeof("Content-Type: ") - 1]) : "");

	signbuf_attach("%lld\n", (long long int)local_expires);

	pString = values->canonicalizedAmzHeaders;
	is_true = ((pString != NULL) && (strlen(pString) > 0));
	if (is_true)
	{
		signbuf_attach("%s", pString);
	}
	pString = values->canonicalizedResource;

	is_true = ((pString != NULL) && (strlen(pString) > 0));
	if (is_true)
	{
		signbuf_attach("%s", pString);
	}

	if (NULL != params->queryParams)
	{
		const char* pos;
		char tmp[1024] = { 0 };
		if ((pos = strstr(params->queryParams, "uploadId")) != NULL)
		{
			int len1 = pos - params->queryParams;
			if ((pos = strstr(params->queryParams + len1, "&")) != NULL)
			{
				len1 = pos - params->queryParams;
			}
			else
			{
				len1 = strlen(params->queryParams);
			}
			int ret = strncpy_s(tmp, sizeof(tmp), params->queryParams, len1);
			// CheckAndLogNoneZero(ret, "strncpy_s", __FUNCTION__, __LINE__);
			signbuf_attach("?%s", tmp);
		}
		if ((pos = strstr(params->queryParams, "versionId")) != NULL)
		{
			if (params->subResource)
			{
				signbuf_attach("&%s", params->queryParams);
			}
			else
			{
				signbuf_attach("?%s", params->queryParams);
			}
		}
		if ((pos = strstr(params->queryParams, "x-image-process")) != NULL)
		{
			int len1 = pos - params->queryParams;
			const char* pos2 = NULL;
			int len2 = strlen(params->queryParams + len1);
			char* decodedStr = NULL;
			pos2 = strstr(params->queryParams + len1, "&");
			if (pos2 != NULL)
			{
				len2 = pos2 - pos;
			}

			if (len2 > 0)
			{
				int ret = strncpy_s(tmp, sizeof(tmp), params->queryParams, len2);
				// CheckAndLogNoneZero(ret, "strncpy_s", __FUNCTION__, __LINE__);
				decodedStr = (char*)malloc(len2 + 1);

				if (decodedStr == NULL)
				{
					// COMMLOG(OBS_LOGWARN, "compose_temp_header : decodedStr malloc failed!\n");
					return OBS_STATUS_InternalError;
				}

				FMemory::Memset(decodedStr, 0, len2 + 1);
				urlDecode(decodedStr, tmp, len2 + 1);
				ret = strncpy_s(tmp, ARRAY_LENGTH_1024, decodedStr, strlen(decodedStr) + 1);
				// CheckAndLogNoneZero(ret, "strncpy_s", __FUNCTION__, __LINE__);
				CHECK_NULL_FREE(decodedStr);
				signbuf_attach("?%s", tmp);
			}
		}
	}
	unsigned char hmac[20] = { 0 };
	// TODO::

// 	HMAC_SHA1(hmac, (unsigned char*)params->bucketContext.secret_access_key,
// 		strlen(params->bucketContext.secret_access_key),
// 		(unsigned char*)signbuf, len);

	char b64[((20 + 1) * 4) / 3] = { 0 };
	// (void)base64Encode(hmac, 20, b64);
	char cUrlEncode[512] = { 0 };
	(void)urlEncode(cUrlEncode, b64, 28, 0);
	int ret = snprintf_s(stTempAuthInfo->tempAuthParams, ARRAY_LENGTH_1024, _TRUNCATE,
		"AWSAccessKeyId=%s&Expires=%lld&Signature=%s", params->bucketContext.access_key,
		(long long int)local_expires, cUrlEncode);
	OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);

	ret = snprintf_s(stTempAuthInfo->temp_auth_headers, ARRAY_LENGTH_1024, _TRUNCATE, "%s",
		values->canonicalizedAmzHeaders);
	OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
	// COMMLOG(OBS_LOGINFO, "Leave compose_temp_header successful \n");
	return OBS_STATUS_OK;
}

obs_status request_curl_code_to_status(CURLcode code) {
	switch (code) {
	case CURLE_OUT_OF_MEMORY:
		return OBS_STATUS_OutOfMemory;
	case CURLE_COULDNT_RESOLVE_PROXY:
	case CURLE_COULDNT_RESOLVE_HOST:
		return OBS_STATUS_NameLookupError;
	case CURLE_COULDNT_CONNECT:
		return OBS_STATUS_FailedToConnect;
	case CURLE_WRITE_ERROR:
	case CURLE_OPERATION_TIMEDOUT:
		return OBS_STATUS_ConnectionFailed;
	case CURLE_PARTIAL_FILE:
		return OBS_STATUS_PartialFile;
	case CURLE_SSL_CACERT:
		return OBS_STATUS_ServerFailedVerification;
	default:
		return OBS_STATUS_InternalError;
	}
}

static obs_status set_query_params(const request_params* params, char* signbuf,
	int* buf_now_len, int buf_len)
{
	int len = *buf_now_len;
	const char* pos;
	char tmp[1024] = { 0 };
	int ret = 0;

	if ((pos = strstr(params->queryParams, "uploadId=")) != NULL)
	{
		int len1 = pos - params->queryParams;
		if ((pos = strstr(params->queryParams + len1, "&")) != NULL)
		{
			len1 = pos - params->queryParams;
		}
		else
		{
			len1 = strlen(params->queryParams);
		}
		ret = strncpy_s(tmp, sizeof(tmp), params->queryParams, len1);
		OSSLog::CheckAndLogNoneZero(ret, "strncpy_s", __FUNCTION__, __LINE__);
		signbuf_append("?%s", tmp);
	}

	if ((pos = strstr(params->queryParams, "versionId=")) != NULL)
	{
		if (params->subResource)
		{
			signbuf_append("&%s", params->queryParams);
		}
		else
		{
			signbuf_append("?%s", params->queryParams);
		}
	}

	if ((pos = strstr(params->queryParams, "position=")) != NULL)
	{
		if (params->subResource)
		{
			signbuf_append("&%s", params->queryParams);
		}
		else
		{
			signbuf_append("?%s", params->queryParams);
		}
	}

	if ((pos = strstr(params->queryParams, "x-image-process=")) != NULL)
	{
		int len1 = pos - params->queryParams;
		const char* pos2 = NULL;
		int len2 = strlen(params->queryParams + len1);
		char* decodedStr = NULL;
		if ((pos2 = strstr(params->queryParams + len1, "&")) != NULL)
		{
			len2 = pos2 - pos;
		}

		if (len2 > 0)
		{
			ret = strncpy_s(tmp, sizeof(tmp), params->queryParams, len2);
			OSSLog::CheckAndLogNoneZero(ret, "strncpy_s", __FUNCTION__, __LINE__);
			decodedStr = (char*)malloc(len2 + 1);

			if (decodedStr == NULL)
			{
				// COMMLOG(OBS_LOGWARN, "set_query_params: malloc failed!\n");
				return OBS_STATUS_InternalError;
			}

			FMemory::Memset(decodedStr, 0, len2 + 1);
			urlDecode(decodedStr, tmp, len2 + 1);
			ret = strncpy_s(tmp, ARRAY_LENGTH_1024, decodedStr, strlen(decodedStr) + 1);
			OSSLog::CheckAndLogNoneZero(ret, "strncpy_s", __FUNCTION__, __LINE__);
			CHECK_NULL_FREE(decodedStr);
			signbuf_append("?%s", tmp);
		}
	}

	*buf_now_len = len;
	return OBS_STATUS_OK;
}

obs_status compose_auth_header(const request_params* params,
	request_computed_values* values)
{
	char signbuf[17 + 129 + 129 + 1 +
		(sizeof(values->canonicalizedAmzHeaders) - 1) +
		(sizeof(values->canonicalizedResource) - 1) + 1];
	int buf_len = sizeof(signbuf);
	int len = 0;

	signbuf_append("%s\n", http_request_type_to_verb(params->httpRequestType));
	signbuf_append("%s\n", values->md5Header[0] ?
		&(values->md5Header[sizeof("Content-MD5: ") - 1]) : "");
	signbuf_append("%s\n", values->contentTypeHeader[0] ?
		&(values->contentTypeHeader[sizeof("Content-Type: ") - 1]) : "");
	signbuf_append("%s", "\n");
	signbuf_append("%s", values->canonicalizedAmzHeaders);
	signbuf_append("%s", values->canonicalizedResource);
	if (NULL != params->queryParams) {
		obs_status ret_status = set_query_params(params, signbuf, &len, buf_len);
		if (ret_status != OBS_STATUS_OK) {
			// COMMLOG(OBS_LOGERROR, "set_query_params return %d !", ret_status);
			return ret_status;
		}
	}

	unsigned char hmac[20] = { 0 };

	FSHA1::HMACBuffer(
	(unsigned char*)params->bucketContext.secret_access_key, 
	strlen(params->bucketContext.secret_access_key), 
	(unsigned char*)signbuf, 
	len, 
	hmac
	);

	char b64[((20 + 1) * 4) / 3] = { 0 };
	int b64Len = FBase64::Encode(hmac, 20, b64);

	char* sts_marker;
	if (params->use_api == OBS_USE_API_S3) {
		sts_marker = "x-amz-security-token:";
	}
	else {
		sts_marker = "x-obs-security-token:";
	}
	char* secutiry_token = strstr(signbuf, sts_marker);
	if (NULL != secutiry_token) {
		char* secutiry_token_begin = secutiry_token + strlen(sts_marker);
		char* secutiry_token_end = strchr(secutiry_token_begin, '\n');
		if (NULL != secutiry_token_end) {
			for (int i = 0; i < secutiry_token_end - secutiry_token_begin; i++) {
				secutiry_token_begin[i] = '*';
			}
		}
	}
	// COMMLOG(OBS_LOGWARN, "%s request_perform : StringToSign:  %.*s", __FUNCTION__, buf_len, signbuf);

	if (params->use_api == OBS_USE_API_S3)
	{
		int ret = snprintf_s(values->authorizationHeader, sizeof(values->authorizationHeader), _TRUNCATE,
			"Authorization: AWS %s:%.*s", params->bucketContext.access_key,
			b64Len, b64);
		OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
		// COMMLOG(OBS_LOGINFO, "%s request_perform : Authorization: AWS %s:*****************", __FUNCTION__, params->bucketContext.access_key);
	}
	else
	{
		int ret = snprintf_s(values->authorizationHeader, sizeof(values->authorizationHeader), _TRUNCATE,
			"Authorization: OBS %s:%.*s", params->bucketContext.access_key,
			b64Len, b64);
		OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);
		// COMMLOG(OBS_LOGINFO, "%s request_perform : Authorization: OBS %s:*****************", __FUNCTION__, params->bucketContext.access_key);
	}

	char* userAgent = USER_AGENT_VALUE;
	int strLen = (int)(strlen(userAgent));
	int ret = snprintf_s(values->userAgent, sizeof(values->userAgent), _TRUNCATE, "User-Agent: %.*s", strLen, userAgent);
	OSSLog::CheckAndLogNeg(ret, "snprintf_s", __FUNCTION__, __LINE__);

	return OBS_STATUS_OK;
}



void OSSRequest::set_use_api_switch(const obs_options* options, obs_use_api* use_api_temp)
{
	if (options->bucket_options.uri_style == OBS_URI_STYLE_PATH)
	{
		return;
	}

	if (options->request_options.auth_switch == OBS_OBS_TYPE)
	{
		*use_api_temp = OBS_USE_API_OBS;
		return;
	}

	if (options->request_options.auth_switch == OBS_S3_TYPE)
	{
		*use_api_temp = OBS_USE_API_S3;
		return;
	}

	int index = -1;


	{
	FScopeLock ScopeLock(&RequestLock);

	time_t time_obs_ = time(NULL);

	if (use_api_index == -1) {
		use_api_index++;
		if (get_api_version(options->bucket_options.bucket_name, options->bucket_options.host_name,
			options->bucket_options.protocol) == OBS_STATUS_OK)
		{
			FMemory::Memcpy(api_switch[use_api_index].bucket_name, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));

			api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

			FMemory::Memcpy(api_switch[use_api_index].host_name, options->bucket_options.host_name, strlen(options->bucket_options.host_name));

			api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';
			api_switch[use_api_index].use_api = OBS_USE_API_OBS;
			api_switch[use_api_index].time_switch = time_obs_;
			*use_api_temp = OBS_USE_API_OBS;
		}
		else {
			FMemory::Memcpy(api_switch[use_api_index].bucket_name, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));

			api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

			FMemory::Memcpy(api_switch[use_api_index].host_name, options->bucket_options.host_name, strlen(options->bucket_options.host_name));

			api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';

			api_switch[use_api_index].use_api = OBS_USE_API_S3;
			api_switch[use_api_index].time_switch = time_obs_;

			*use_api_temp = OBS_USE_API_S3;
		}
	}
	else {
		if ((index = sort_bucket_name(options->bucket_options.bucket_name, options->bucket_options.host_name)) > -1)
		{
			if (difftime(time_obs_, api_switch[index].time_switch) > 900.00)
			{
				if (get_api_version(options->bucket_options.bucket_name, options->bucket_options.host_name,
					options->bucket_options.protocol) == OBS_STATUS_OK)
				{
					api_switch[index].use_api = OBS_USE_API_OBS;
					api_switch[index].time_switch = time_obs_;
					*use_api_temp = OBS_USE_API_OBS;

				}
				else {
					api_switch[index].use_api = OBS_USE_API_S3;
					api_switch[index].time_switch = time_obs_;
					*use_api_temp = OBS_USE_API_S3;
				}
			}
			else {
				api_switch[index].time_switch = time_obs_;
			}
		}
		else {
			use_api_index++;
			if (get_api_version(options->bucket_options.bucket_name, options->bucket_options.host_name,
				options->bucket_options.protocol) == OBS_STATUS_OK)
			{
				FMemory::Memcpy(api_switch[use_api_index].bucket_name, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));

				api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

				FMemory::Memcpy(api_switch[use_api_index].host_name, options->bucket_options.host_name, strlen(options->bucket_options.host_name));

				api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';

				api_switch[use_api_index].use_api = OBS_USE_API_OBS;
				api_switch[use_api_index].time_switch = time_obs_;
				*use_api_temp = OBS_USE_API_OBS;

			}
			else {
				FMemory::Memcpy(api_switch[use_api_index].bucket_name, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));

				api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

				FMemory::Memcpy(api_switch[use_api_index].host_name, options->bucket_options.host_name, strlen(options->bucket_options.host_name));

				api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';

				api_switch[use_api_index].use_api = OBS_USE_API_S3;
				api_switch[use_api_index].time_switch = time_obs_;
				*use_api_temp = OBS_USE_API_S3;
			}
		}
	}
	}
}


void OSSRequest::request_perform(const request_params* params)
{
	UE_LOG(LogOSS, Warning, TEXT("Enter request perform!!!"));
	http_request* request = NULL;
	obs_status status = OBS_STATUS_OK;
	int is_true = 0;

	UE_LOG(LogOSS, Log, TEXT("Ente request_perform object key= %s\n!"), params->key);
	request_computed_values computed;
	FMemory::Memset(&computed, 0, sizeof(request_computed_values));
	char errorBuffer[CURL_ERROR_SIZE];
	FMemory::Memset(errorBuffer, 0, CURL_ERROR_SIZE);
	char authTmpParams[1024] = { 0 };
	char authTmpActualHeaders[1024] = { 0 };
	temp_auth_info stTempAuthInfo;
	FMemory::Memset(&stTempAuthInfo, 0, sizeof(temp_auth_info));
	stTempAuthInfo.temp_auth_headers = authTmpActualHeaders;
	stTempAuthInfo.tempAuthParams = authTmpParams;

	if ((status = encode_key(params->copySourceKey, computed.urlEncodedSrcKey)) != OBS_STATUS_OK) {
		return_status(status);
	}

	if ((status = compose_obs_headers(params, &computed)) != OBS_STATUS_OK) {
		return_status(status);
	}
	if ((status = compose_standard_headers(params, &computed)) != OBS_STATUS_OK) {
		return_status(status);
	}
	if ((status = encode_key(params->key, computed.urlEncodedKey)) != OBS_STATUS_OK) {
		return_status(status);
	}
	UE_LOG(LogOSS, Log, TEXT("Enter get_object object computed key= %s\n!"), computed.urlEncodedKey);
	canonicalize_obs_headers(&computed, params->use_api);
	canonicalize_resource(params, computed.urlEncodedKey, computed.canonicalizedResource,
		sizeof(computed.canonicalizedResource));
	if (params->temp_auth)
	{
		if ((status = compose_temp_header(params, &computed, &stTempAuthInfo)) != OBS_STATUS_OK) {
			return_status(status);
		}
	}
	else if ((status = compose_auth_header(params, &computed)) != OBS_STATUS_OK)
	{
		return_status(status);
	}

	if ((status = request_get(params, &computed, &request, &stTempAuthInfo)) != OBS_STATUS_OK) {
		return_status(status);
	}

	is_true = ((params->temp_auth) && (params->temp_auth->temp_auth_callback != NULL));
	if (is_true) {
		(params->temp_auth->temp_auth_callback)(request->uri,
			authTmpActualHeaders, params->temp_auth->callback_data);
		request_release(request);
		return_status(status);
	}
	CURLcode setoptResult = curl_easy_setopt(request->curl, CURLOPT_ERRORBUFFER, errorBuffer);
	if (setoptResult != CURLE_OK) {
		UE_LOG(LogOSS, Warning, TEXT("%s curl_easy_setopt failed! CURLcode = %d"), __FUNCTION__, setoptResult);
	}

	char* accessmode = "Virtual Hosting";
	if (params->bucketContext.uri_style == OBS_URI_STYLE_PATH)
	{
		accessmode = "Path";
	}

	UE_LOG(LogOSS, Log, TEXT("%s OBS SDK Version= %s; Endpoint = http://%s; Access Mode = %s"), __FUNCTION__, OBS_SDK_VERSION,
		params->bucketContext.host_name, accessmode);

	UE_LOG(LogOSS, Log, TEXT("%s start curl_easy_perform now"), __FUNCTION__);
	CURLcode code = curl_easy_perform(request->curl);
	is_true = ((code != CURLE_OK) && (request->status == OBS_STATUS_OK));
	if (is_true) {
		request->status = request_curl_code_to_status(code);
		char* proxyBuf = strstr(errorBuffer, "proxy:");
		if (NULL != proxyBuf) {
			FMemory::Memcpy(proxyBuf, "proxy: *****", CURL_ERROR_SIZE - (proxyBuf - errorBuffer));
		}
		UE_LOG(LogOSS, Warning, TEXT("%s curl_easy_perform code = %d,status = %d,errorBuffer = %s"), __FUNCTION__, code,
			request->status, errorBuffer);
	}
	request_finish(request);
}



void OSSRequest::request_finish(http_request* request)
{
	request_headers_done(request);
	OBS_LOGLEVEL logLevel;
	int is_true = 0;

	is_true = ((request->status != OBS_STATUS_OK) || (((request->httpResponseCode < 200) || (request->httpResponseCode > 299))
		&& (100 != request->httpResponseCode)));
	logLevel = is_true ? OBS_LOGWARN : OBS_LOGINFO;

	struct curl_slist* tmp = request->headers;
	while (NULL != tmp)
	{
		request_finish_log(tmp, logLevel);
		tmp = tmp->next;
	}
	// COMMLOG(logLevel, "%s request_finish status = %d,httpResponseCode = %d", __FUNCTION__,
		// request->status, request->httpResponseCode);
	// COMMLOG(logLevel, "Message: %s", request->errorParser.obsErrorDetails.message);
	// COMMLOG(logLevel, "Request Id: %s", request->responseHeadersHandler.responseProperties.request_id);
	// COMMLOG(logLevel, "Reserved Indicator: %s", request->responseHeadersHandler.responseProperties.reserved_indicator);
	if (request->errorParser.codeLen) {
		// COMMLOG(logLevel, "Code: %s", request->errorParser.code);
	}
	if (request->status == OBS_STATUS_OK) {
		// TODO: error_parser_convert_status(&(request->errorParser), &(request->status));
		is_true = ((request->status == OBS_STATUS_OK) && ((request->httpResponseCode < 200) ||
			(request->httpResponseCode > 299)) && request->httpResponseCode != 100);
		if (is_true) {
			request->status = response_to_status(request);
		}
	}
	(*(request->complete_callback))
		(request->status, &(request->errorParser.obsErrorDetails),
			request->callback_data);
	request_release(request);
}


void OSSRequest::request_release(http_request* request)
{
	FScopeLock ScopeLock(&RequestLock);

	if (requestStackCountG == REQUEST_STACK_SIZE || request->status != OBS_STATUS_OK) {
		if (current_request_cnt > 0)
		{
			current_request_cnt--;
		}

	}
	else {
		requestStackG[requestStackCountG++] = request;
		if (current_request_cnt > 0)
		{
			current_request_cnt--;
		}
	}
}

static obs_status compose_api_version_uri(char* buffer, int buffer_size,
	const char* bucket_name, const char* host_name,
	const char* subResource, obs_protocol protocol)
{
	int len = 0;
	uri_append("http%s://", (protocol == OBS_PROTOCOL_HTTP) ? "" : "s");
	if (bucket_name && bucket_name[0]) {
		uri_append("%s.%s", bucket_name, host_name);
	}
	else {
		uri_append("%s", host_name);
	}
	uri_append("%s", "/");
	uri_append("?%s", subResource);
	return OBS_STATUS_OK;
}

size_t api_header_func(void* ptr, size_t size, size_t nmemb,
	void* data)
{
	obs_status* status = (obs_status*)data;
	if (!strncmp((char*)ptr, "x-obs-api: 3.0", 14)) {
		*status = OBS_STATUS_OK;
		// COMMLOG(OBS_LOGINFO, "get api version !!!  %s", (char*)ptr);
	}
	return size * nmemb;
}

obs_status OSSRequest::get_api_version(char* bucket_name, char* host_name, obs_protocol protocol)
{
	// COMMLOG(OBS_LOGINFO, "get api version start!");
	obs_status status = OBS_STATUS_ErrorUnknown;
	char uri[MAX_URI_SIZE + 1] = { 0 };
	CURL* curl = NULL;
	long httpResponseCode = 0;
	char errorBuffer[CURL_ERROR_SIZE];
	FMemory::Memset(errorBuffer, 0, CURL_ERROR_SIZE);

#define easy_setopt_safe(opt, val)                                 \
        if (curl_easy_setopt(curl, opt, val) != CURLE_OK) {                      \
            curl_easy_cleanup(curl);                                            \
            return OBS_STATUS_FailedToIInitializeRequest;                       \
        }


	if ((curl = curl_easy_init()) == NULL) {
		return OBS_STATUS_FailedToIInitializeRequest;
	}
	obs_status statu = OBS_STATUS_OK;
	if ((statu = compose_api_version_uri(uri, sizeof(uri), bucket_name, host_name, "apiversion", protocol)) != OBS_STATUS_OK) {
		curl_easy_cleanup(curl);
		return statu;
	}
	if (protocol == OBS_PROTOCOL_HTTPS) {
		easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 0);
		easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0);
	}

	easy_setopt_safe(CURLOPT_HEADERDATA, &status);
	easy_setopt_safe(CURLOPT_HEADERFUNCTION, &api_header_func);

	easy_setopt_safe(CURLOPT_NOSIGNAL, 1);
	easy_setopt_safe(CURLOPT_TCP_NODELAY, 1);
	easy_setopt_safe(CURLOPT_NOPROGRESS, 1);
	easy_setopt_safe(CURLOPT_FOLLOWLOCATION, 1);
	easy_setopt_safe(CURLOPT_URL, uri);
	easy_setopt_safe(CURLOPT_NOBODY, 1);

	easy_setopt_safe(CURLOPT_LOW_SPEED_LIMIT, DEFAULT_LOW_SPEED_LIMIT);
	easy_setopt_safe(CURLOPT_LOW_SPEED_TIME, DEFAULT_LOW_SPEED_TIME_S);
	easy_setopt_safe(CURLOPT_CONNECTTIMEOUT_MS, DEFAULT_CONNECTTIMEOUT_MS);
	easy_setopt_safe(CURLOPT_TIMEOUT, DEFAULT_TIMEOUT_S);

	CURLcode setoptResult = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
	// COMMLOG(OBS_LOGWARN, "curl_easy_setopt curl path= %s", uri);
	if (setoptResult != CURLE_OK) {
		// COMMLOG(OBS_LOGWARN, "%s curl_easy_setopt failed! CURLcode = %d", __FUNCTION__, setoptResult);
	}
	CURLcode code = curl_easy_perform(curl);
	if (code != CURLE_OK) {
		obs_status sta = request_curl_code_to_status(code);
		// COMMLOG(OBS_LOGWARN, "%s curl_easy_perform code = %d,status = %d,errorBuffer = %s", __FUNCTION__, code,
			// sta, errorBuffer);
		curl_easy_cleanup(curl);
		return sta;
	}

	if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
		&httpResponseCode) != CURLE_OK) {
		curl_easy_cleanup(curl);
		return OBS_STATUS_InternalError;
	}

	// COMMLOG(OBS_LOGINFO, "curl_easy_setopt curl with httpResponseCode = %d", httpResponseCode);
	if (status == OBS_STATUS_OK && httpResponseCode == 200)
	{
		curl_easy_cleanup(curl);
		return OBS_STATUS_OK;
	}
	else {
		curl_easy_cleanup(curl);
		return status;
	}
}


// 
// ** encode_key 对object_key做encode
// ** 目前的特别处理逻辑为：默认不对/字符encode(分享的时候m3u8需要依赖目录结构)，
// ** 但是有./的还是需要encode，原因在于./在libcurl去request的时候会被自动去掉，
// ** 从而会导致sdk计算的CanonicalizedResource和服务端计算的不一致，最终会签名不匹配
// 
obs_status OSSRequest::encode_key(const char* params, char* values)
{
	char ingoreChar = '/';
	if (NULL != params && NULL != values)
	{
		if (NULL != strstr(params, "./"))
		{
			ingoreChar = 0;
		}
		return (urlEncode(values, params, OBS_MAX_KEY_SIZE, ingoreChar) ?
			OBS_STATUS_OK : OBS_STATUS_UriTooLong);
	}
	else
	{
		int nRet = urlEncode(values, params, OBS_MAX_KEY_SIZE, ingoreChar);
		if (nRet == -1) {
			return OBS_STATUS_InvalidArgument;
		}
		return (nRet ? OBS_STATUS_OK : OBS_STATUS_UriTooLong);
	}
}

*/