#include "OSSRequest.h"


void OSSRequest::set_use_api_switch(const oss_options* options, oss_use_api* use_api_temp)
{
	if (options->bucket_options.uri_style == OSS_URI_STYLE_PATH)
	{
		return;
	}

	if (options->request_options.auth_switch == OSS_OSS_TYPE)
	{
		*use_api_temp = OSS_USE_API_OSS;
		return;
	}

	if (options->request_options.auth_switch == OSS_S3_TYPE)
	{
		*use_api_temp = OSS_USE_API_S3;
		return;
	}

	int index = -1;
#if defined __GNUC__ || defined LINUX
	pthread_mutex_lock(&use_api_mutex);
#else
	WaitForSingleObject(use_api_mutex, INFINITE);
#endif
	time_t time_oss = time(NULL);
	errno_t err = EOK;
	if (use_api_index == -1) {
		use_api_index++;
		if (get_api_version(options->bucket_options.bucket_name, options->bucket_options.host_name,
			options->bucket_options.protocol) == OSS_STATUS_OK)
		{
			err = memcpy_s(api_switch[use_api_index].bucket_name, BUCKET_LEN - 1, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));
			CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

			api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

			err = memcpy_s(api_switch[use_api_index].host_name, DOMAIN_LEN - 1, options->bucket_options.host_name, strlen(options->bucket_options.host_name));
			CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

			api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';
			api_switch[use_api_index].use_api = OSS_USE_API_OSS;
			api_switch[use_api_index].time_switch = time_oss;
			*use_api_temp = OSS_USE_API_OSS;
		}
		else {
			err = memcpy_s(api_switch[use_api_index].bucket_name, BUCKET_LEN - 1, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));
			CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

			api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

			err = memcpy_s(api_switch[use_api_index].host_name, DOMAIN_LEN - 1, options->bucket_options.host_name, strlen(options->bucket_options.host_name));
			CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

			api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';

			api_switch[use_api_index].use_api = OSS_USE_API_S3;
			api_switch[use_api_index].time_switch = time_oss;

			*use_api_temp = OSS_USE_API_S3;
		}
	}
	else {
		if ((index = sort_bucket_name(options->bucket_options.bucket_name, options->bucket_options.host_name)) > -1)
		{
			if (difftime(time_oss, api_switch[index].time_switch) > 900.00)
			{
				if (get_api_version(options->bucket_options.bucket_name, options->bucket_options.host_name,
					options->bucket_options.protocol) == OSS_STATUS_OK)
				{
					api_switch[index].use_api = OSS_USE_API_OSS;
					api_switch[index].time_switch = time_oss;
					*use_api_temp = OSS_USE_API_OSS;

				}
				else {
					api_switch[index].use_api = OSS_USE_API_S3;
					api_switch[index].time_switch = time_oss;
					*use_api_temp = OSS_USE_API_S3;
				}
			}
			else {
				api_switch[index].time_switch = time_oss;
			}
		}
		else {
			use_api_index++;
			if (get_api_version(options->bucket_options.bucket_name, options->bucket_options.host_name,
				options->bucket_options.protocol) == OSS_STATUS_OK)
			{
				err = memcpy_s(api_switch[use_api_index].bucket_name, BUCKET_LEN - 1, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));
				CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

				api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

				err = memcpy_s(api_switch[use_api_index].host_name, DOMAIN_LEN - 1, options->bucket_options.host_name, strlen(options->bucket_options.host_name));
				CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

				api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';

				api_switch[use_api_index].use_api = OSS_USE_API_OSS;
				api_switch[use_api_index].time_switch = time_oss;
				*use_api_temp = OSS_USE_API_OSS;

			}
			else {
				err = memcpy_s(api_switch[use_api_index].bucket_name, BUCKET_LEN - 1, options->bucket_options.bucket_name, strlen(options->bucket_options.bucket_name));
				CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

				api_switch[use_api_index].bucket_name[strlen(options->bucket_options.bucket_name)] = '\0';

				err = memcpy_s(api_switch[use_api_index].host_name, DOMAIN_LEN - 1, options->bucket_options.host_name, strlen(options->bucket_options.host_name));
				CheckAndLogNoneZero(err, "memcpy_s", __FUNCTION__, __LINE__);

				api_switch[use_api_index].host_name[strlen(options->bucket_options.host_name)] = '\0';

				api_switch[use_api_index].use_api = OSS_USE_API_S3;
				api_switch[use_api_index].time_switch = time_oss;
				*use_api_temp = OSS_USE_API_S3;
			}
		}
	}

#if defined __GNUC__ || defined LINUX
	pthread_mutex_unlock(&use_api_mutex);
#else
	ReleaseMutex(use_api_mutex);
#endif
}
