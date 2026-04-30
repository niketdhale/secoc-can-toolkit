#pragma once
#include "SecOcTypes.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// AUTOSAR-style initialization [SWS_SecOC_00001]
typedef struct {
    uint16_t SecOCDataId;
    uint8_t SecOCAuthPduHeaderLength;
    uint8_t SecOCFreshnessValueTruncLength;
    uint8_t SecOCAuthInfoTruncLength;
    uint16_t SecOCRxAcceptanceWindow;
    const uint8_t* SecOCAuthKey;      // 16-byte array for AES-128
    bool SecOCUseTimestampFv;
} SecOc_ConfigType;

// Return types matching AUTOSAR Std_ReturnType
#define SECOC_E_OK          0
#define SECOC_E_NOT_OK      1
#define SECOC_E_PARAM       2
#define SECOC_E_CRYPTO      3

// Public API [SWS_SecOC_001xx series]
uint8_t SecOc_Init(const SecOc_ConfigType* config);
uint8_t SecOc_DeInit(void);
uint8_t SecOc_MainFunction(void);  // For polling mode (optional)

// TX path: Application calls this to send secured data [SWS_SecOC_00200]
uint8_t SecOc_Transmit(
    uint16_t DataId,
    const uint8_t* Payload,
    uint16_t PayloadLength,
    uint8_t* SecuredPduBuffer,
    uint16_t* SecuredPduLength);

// RX path: PduR calls this when secured PDU received [SWS_SecOC_00300]
uint8_t SecOc_Receive(
    uint16_t DataId,
    const uint8_t* SecuredPdu,
    uint16_t SecuredPduLength,
    uint8_t* PayloadBuffer,
    uint16_t* PayloadLength,
    bool* FreshnessVerified);

// Utility: Get current freshness value for debugging/testing
uint64_t SecOc_GetCurrentFreshness(uint16_t DataId);

#ifdef __cplusplus
}
#endif