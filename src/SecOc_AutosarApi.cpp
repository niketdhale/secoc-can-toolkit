#include "SecOc_AutosarApi.h"
#include "SecOcEngine.h"
#include "FreshnessManager.h"
#include <cstring>
#include <map>
#include <memory>
#include <mutex>

static std::map<uint16_t, std::unique_ptr<SecOcEngine>> g_secoc_instances;
static std::mutex g_init_mutex;
static bool g_initialized = false;

extern "C" {

uint8_t SecOc_Init(const SecOc_ConfigType* config) {
    if (!config || !config->SecOCAuthKey) return SECOC_E_PARAM;
    
    std::lock_guard<std::mutex> lock(g_init_mutex);
    
    auto engine = std::make_unique<SecOcEngine>();
    
    SecOcConfig cpp_cfg;
    cpp_cfg.data_id = config->SecOCDataId;
    cpp_cfg.auth_pdu_header_length = config->SecOCAuthPduHeaderLength;
    cpp_cfg.fv_trunc_length = config->SecOCFreshnessValueTruncLength;
    cpp_cfg.mac_trunc_length = config->SecOCAuthInfoTruncLength;
    cpp_cfg.acceptance_window = config->SecOCRxAcceptanceWindow;
    cpp_cfg.auth_key = {config->SecOCAuthKey, config->SecOCAuthKey + 16};
    cpp_cfg.use_timestamp_fv = config->SecOCUseTimestampFv;
    
    engine->setConfig(cpp_cfg);
    
    if (cpp_cfg.use_timestamp_fv) {
        engine->setFreshnessProvider(
            std::make_unique<SimulatedFreshnessManager>(SimulatedFreshnessManager::Mode::Timestamp));
    } else {
        engine->setFreshnessProvider(
            std::make_unique<SimulatedFreshnessManager>(SimulatedFreshnessManager::Mode::Counter));
    }
    
    g_secoc_instances[config->SecOCDataId] = std::move(engine);
    g_initialized = true;
    
    return SECOC_E_OK;
}

uint8_t SecOc_DeInit(void) {
    std::lock_guard<std::mutex> lock(g_init_mutex);
    g_secoc_instances.clear();
    g_initialized = false;
    return SECOC_E_OK;
}

uint8_t SecOc_MainFunction(void) {
    return SECOC_E_OK;
}

uint8_t SecOc_Transmit(
    uint16_t DataId,
    const uint8_t* Payload,
    uint16_t PayloadLength,
    uint8_t* SecuredPduBuffer,
    uint16_t* SecuredPduLength) 
{
    if (!g_initialized || !Payload || !SecuredPduBuffer || !SecuredPduLength) 
        return SECOC_E_PARAM;
    
    auto it = g_secoc_instances.find(DataId);
    if (it == g_secoc_instances.end()) return SECOC_E_PARAM;
    
    std::vector<uint8_t> payload_vec(Payload, Payload + PayloadLength);
    auto result = it->second->wrapTx(payload_vec);
    
    if (result.status != SecOcResult::Status::Ok) {
        return (result.status == SecOcResult::Status::CryptoError) ? SECOC_E_CRYPTO : SECOC_E_NOT_OK;
    }
    
    size_t offset = 0;
    
    if (!result.pdu.header.empty()) {
        ::memcpy(SecuredPduBuffer + offset, result.pdu.header.data(), result.pdu.header.size());
        offset += result.pdu.header.size();
    }
    
    ::memcpy(SecuredPduBuffer + offset, result.pdu.payload.data(), result.pdu.payload.size());
    offset += result.pdu.payload.size();
    
    ::memcpy(SecuredPduBuffer + offset, result.pdu.freshness.data(), result.pdu.freshness.size());
    offset += result.pdu.freshness.size();
    
    ::memcpy(SecuredPduBuffer + offset, result.pdu.mac.data(), result.pdu.mac.size());
    offset += result.pdu.mac.size();
    
    *SecuredPduLength = static_cast<uint16_t>(offset);
    return SECOC_E_OK;
}

uint8_t SecOc_Receive(
    uint16_t DataId,
    const uint8_t* SecuredPdu,
    uint16_t SecuredPduLength,
    uint8_t* PayloadBuffer,
    uint16_t* PayloadLength,
    bool* FreshnessVerified) 
{
    if (!g_initialized || !SecuredPdu || !PayloadBuffer || !PayloadLength || !FreshnessVerified) 
        return SECOC_E_PARAM;
    
    auto it = g_secoc_instances.find(DataId);
    if (it == g_secoc_instances.end()) return SECOC_E_PARAM;
    
    const auto& cfg = it->second->getConfig();
    size_t offset = 0;
    
    SecOcPdu pdu;
    
    if (cfg.auth_pdu_header_length > 0) {
        pdu.header.assign(SecuredPdu + offset, SecuredPdu + offset + cfg.auth_pdu_header_length);
        offset += cfg.auth_pdu_header_length;
    }
    
    size_t trailer_len = cfg.fv_trunc_length + cfg.mac_trunc_length;
    if (SecuredPduLength < offset + trailer_len) return SECOC_E_PARAM;
    
    pdu.freshness.assign(SecuredPdu + SecuredPduLength - trailer_len, 
                         SecuredPdu + SecuredPduLength - cfg.mac_trunc_length);
    
    pdu.mac.assign(SecuredPdu + SecuredPduLength - cfg.mac_trunc_length,
                   SecuredPdu + SecuredPduLength);
    
    size_t payload_start = offset;
    size_t payload_end = SecuredPduLength - trailer_len;
    pdu.payload.assign(SecuredPdu + payload_start, SecuredPdu + payload_end);
    
    auto result = it->second->unwrapRx(pdu);
    
    if (result.status != SecOcResult::Status::Ok) {
        return (result.status == SecOcResult::Status::CryptoError) ? SECOC_E_CRYPTO : SECOC_E_NOT_OK;
    }
    
    if (result.pdu.payload.size() > *PayloadLength) return SECOC_E_PARAM;
    ::memcpy(PayloadBuffer, result.pdu.payload.data(), result.pdu.payload.size());
    *PayloadLength = static_cast<uint16_t>(result.pdu.payload.size());
    *FreshnessVerified = result.freshness_verified;
    
    return SECOC_E_OK;
}

uint64_t SecOc_GetCurrentFreshness(uint16_t DataId) {
    auto it = g_secoc_instances.find(DataId);
    if (it == g_secoc_instances.end()) return 0;
    return 0;
}

} // extern "C"