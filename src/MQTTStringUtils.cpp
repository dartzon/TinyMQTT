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
 * \file      MQTTStringUtils.cpp
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      28-05-2017
 */

#include "MQTTStringUtils.h"
#include "MQTTString.h"
#include "MQTTNumeric.h"

namespace Ocelot
{

size_t MQTT::storeUTF8String(uint8_t* pDestBuffer, const char* pSrcStr, const size_t strLen)
{
    size_t srcStrSize = strLen;

    if(srcStrSize > UTF8_STR_MAX_LEN)
    {
        srcStrSize = UTF8_STR_MAX_LEN;
    }

    const uint16_t strSizeBE = MQTT::toBigEndian(srcStrSize);
    memcpy(pDestBuffer, &strSizeBE, sizeof(uint16_t));

    if(srcStrSize > 0)
    {
        memcpy(pDestBuffer + sizeof(uint16_t), pSrcStr, srcStrSize);
    }

    return (sizeof(uint16_t) + srcStrSize);
}

/* ============================================================================================== */

size_t MQTT::storeUTF8String(uint8_t* pDestBuffer, const MQTT::UTF8String& srcStr)
{
    const size_t memSize = sizeof(uint16_t) + srcStr.getLength();
    memcpy(pDestBuffer, srcStr.m_pData, memSize);

    return (memSize);
}

/* ============================================================================================== */

uint32_t getUTF8String(const char* pSrcStr, const size_t strLen, MQTT::UTF8String& destStr)
{
    size_t srcStrSize = strLen;

    if(srcStrSize > UTF8_STR_MAX_LEN)
    {
        srcStrSize = UTF8_STR_MAX_LEN;
    }

    const uint16_t strSizeBE = MQTT::toBigEndian(srcStrSize);
    memcpy(destStr.m_pData, &strSizeBE, sizeof(uint16_t));

    if(srcStrSize > 0)
    {
        memcpy(destStr.m_pData + sizeof(uint16_t), pSrcStr, srcStrSize);
    }

    return (sizeof(uint16_t) + srcStrSize);
}

}
