// Copyright Epic Games, Inc. All Rights Reserved.

#pragma once

#include "CoreMinimal.h"
#include "OSSType.h"


static void put_object(const oss_options* options, char* key, uint64_t content_length,
	oss_put_properties* put_properties,
	server_side_encryption_params* encryption_params,
	oss_put_object_handler* handler, void* callback_data);