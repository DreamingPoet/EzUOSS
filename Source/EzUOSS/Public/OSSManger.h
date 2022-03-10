// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "OSSType.h"

class OSSManager {

	static void put_object(const obs_options* options, char* key, uint64 content_length,
		obs_put_properties* put_properties,
		server_side_encryption_params* encryption_params,
		obs_put_object_handler* handler, void* callback_data);

};