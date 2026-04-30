#pragma once
#include <cstdint>
#include <vector>
#include <string>

// AUTOSAR SecOC PDU Structure: [Header][Payload][FV][MAC]
struct SecOcPdu {
    std::vector<uint8_t> header;      // Optional: SecOCAuthPduHeaderLength bytes
    std::vector<uint8_t> payload;     // Application data
    std::vector<uint8_t> freshness;   // Big Endian, truncated per config
    std::vector<uint8_t> mac;         // Big Endian, truncated per config
};

// Configuration matching AUTOSAR ECUC parameters
struct SecOcConfig {
    uint16_t data_id = 0x123;                    // SecOCDataId (16-bit)
    uint8_t auth_pdu_header_length = 0;          // SecOCAuthPduHeaderLength
    uint8_t fv_trunc_length = 4;                 // SecOCFreshnessValueTruncLength (bytes)
    uint8_t mac_trunc_length = 4;                // SecOCAuthInfoTruncLength (bytes)
    uint16_t acceptance_window = 1000;           // SecOCRxAcceptanceWindow (counter units)
    std::vector<uint8_t> auth_key;               // 16 bytes for AES-128
    bool use_timestamp_fv = false;               // Counter vs Timestamp FV mode
};

// Result structure for TX/RX operations
struct SecOcResult {
    enum class Status { Ok, InvalidFrame, MacFailed, FreshnessFailed, CryptoError };
    Status status = Status::Ok;
    std::string error_detail;
    SecOcPdu pdu;                    // Wrapped (TX) or unwrapped (RX) PDU
    uint64_t freshness_value = 0;    // Full FV (before truncation)
    bool freshness_verified = false;
};