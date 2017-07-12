// =============================================================================
// Copyright 2017 Othmane AIT EL CADI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// =============================================================================

/*
 * \file      MQTTStringUtils.h
 *
 * \brief     <brief description>
 * \details   <detailed description>
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      28-05-2017
 */

#ifndef __MQTTSTRINGUTILS_H__
#define __MQTTSTRINGUTILS_H__

// STD includes.
#include <cstddef>
#include <cstdint>

namespace Ocelot
{
namespace MQTT
{

class UTF8String;

size_t storeUTF8String(uint8_t* pDestBuffer, const char* pSrcStr, const size_t strLen);

size_t storeUTF8String(uint8_t* pDestBuffer, const MQTT::UTF8String& srcStr);

uint32_t getUTF8String(const char* pSrcStr, const size_t strLen, MQTT::UTF8String& destStr);

} /* namespace MQTT */
} /* namespace Ocelot */

#endif /* __MQTTSTRINGUTILS_H__ */
