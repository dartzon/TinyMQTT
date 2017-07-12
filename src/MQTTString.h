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
 * \file      MQTTString.h
 *
 * \brief     MQTT String.
 * \details   MQTT uses fixed length UTF-8 strings with
 *            a maximum size of 65536 bytes. For memory
 *            and performance concerns, the global constant
 *            UTF8_STR_MAX_LEN is used with a platform
 *            specific value
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      11-04-2017
 */

#ifndef __MQTTSTRING_H__
#define __MQTTSTRING_H__

// Local includes.
#include "MQTTConfig.h"

// STD includes.
#include <cstddef>
#include <cstring>

namespace Ocelot
{
namespace MQTT
{

// 1.5.3 UTF-8 encoded strings
struct UTF8String
{
    UTF8String(void)
    {
        m_pData[0] = 0;
        m_pData[1] = 0;
    }

    bool operator==(const char* pStr) const;

    bool operator==(const UTF8String& rStr) const;

    uint16_t getLength(void) const;

    uint8_t m_pData[sizeof(uint16_t) + UTF8_STR_MAX_LEN];  ///< String buffer.
};

} /* namespace MQTT */
} /* namespace Ocelot */

#endif /* __MQTTSTRING_H__ */
