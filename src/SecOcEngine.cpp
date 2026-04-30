#include "SecOcEngine.h"
#include "FreshnessManager.h"
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <cstring>
#include <algorithm>

SecOcEngine::SecOcEngine() {
    m_default_fv_provider = std::make_unique<SimulatedFreshnessManager>();
    m_active_fv_provider = m_default_fv_provider.get();
}

SecOcEngine::~SecOcEngine() = default;

void SecOcEngine::setConfig(const SecOcConfig& cfg) { 
    m_config = cfg; 
    if (!m_config.auth_key.empty() && m_config.auth_key.size() != 16) {
        m_config.auth_key.resize(16, 0);
    }
}

void SecOcEngine::setFreshnessProvider(std::unique_ptr<IFreshnessProvider> provider) {
    if (provider) {
        m_external_fv_provider = std::move(provider);
        m_active_fv_provider = m_external_fv_provider.get();
    } else {
        m_external_fv_provider.reset();
        m_active_fv_provider = m_default_fv_provider.get();
    }
}

std::vector<uint8_t> SecOcEngine::buildDataToAuthenticator(
    uint16_t data_id,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& full_freshness) 
{
    std::vector<uint8_t> result;
    result.reserve(2 + payload.size() + full_freshness.size());
    result.push_back((data_id >> 8) & 0xFF);
    result.push_back(data_id & 0xFF);
    result.insert(result.end(), payload.begin(), payload.end());
    result.insert(result.end(), full_freshness.begin(), full_freshness.end());
    return result;
}

std::vector<uint8_t> SecOcEngine::computeMacAesCmac(const std::vector<uint8_t>& data) const {
    if (m_config.auth_key.empty() || m_config.auth_key.size() != 16) {
        return {};
    }
    
    unsigned char mac[16];
    size_t mac_len = 0;
    
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx) return {};
    
    if (CMAC_Init(ctx, m_config.auth_key.data(), 16, EVP_aes_128_cbc(), nullptr) != 1) {
        CMAC_CTX_free(ctx);
        return {};
    }
    
    if (CMAC_Update(ctx, data.data(), data.size()) != 1) {
        CMAC_CTX_free(ctx);
        return {};
    }
    
    if (CMAC_Final(ctx, mac, &mac_len) != 1) {
        CMAC_CTX_free(ctx);
        return {};
    }
    
    CMAC_CTX_free(ctx);
#pragma GCC diagnostic pop
    
    return {mac, mac + mac_len};
}

std::vector<uint8_t> SecOcEngine::truncateBe(const std::vector<uint8_t>& be_data, uint8_t target_bytes) {
    if (be_data.empty() || target_bytes == 0) return {};
    size_t take = std::min(static_cast<size_t>(target_bytes), be_data.size());
    return {be_data.begin(), be_data.begin() + take};
}

uint64_t SecOcEngine::extractUintBe(const std::vector<uint8_t>& be_data) {
    uint64_t val = 0;
    for (size_t i = 0; i < std::min(be_data.size(), sizeof(uint64_t)); ++i) {
        val = (val << 8) | be_data[i];
    }
    return val;
}

SecOcResult SecOcEngine::wrapTx(const std::vector<uint8_t>& payload) {
    SecOcResult res;
    
    auto [full_fv_bytes, fv_bits] = m_active_fv_provider->getFreshness(m_config.data_id);
    res.freshness_value = extractUintBe(full_fv_bytes);
    
    std::vector<uint8_t> truncated_fv = truncateBe(full_fv_bytes, m_config.fv_trunc_length);
    
    std::vector<uint8_t> data_to_auth = buildDataToAuthenticator(
        m_config.data_id, payload, full_fv_bytes);
    
    std::vector<uint8_t> full_mac = computeMacAesCmac(data_to_auth);
    if (full_mac.empty()) {
        res.status = SecOcResult::Status::CryptoError;
        res.error_detail = "AES-CMAC computation failed";
        return res;
    }
    
    std::vector<uint8_t> truncated_mac = truncateBe(full_mac, m_config.mac_trunc_length);
    
    SecOcPdu pdu;
    if (m_config.auth_pdu_header_length > 0) {
        pdu.header.resize(m_config.auth_pdu_header_length, 0);
    }
    pdu.payload = payload;
    pdu.freshness = truncated_fv;
    pdu.mac = truncated_mac;
    
    res.pdu = std::move(pdu);
    res.status = SecOcResult::Status::Ok;
    
    m_active_fv_provider->confirmFreshness(m_config.data_id, true);
    
    return res;
}

SecOcResult SecOcEngine::unwrapRx(const SecOcPdu& secured_pdu) {
    SecOcResult res;
    
    if (secured_pdu.freshness.size() != m_config.fv_trunc_length ||
        secured_pdu.mac.size() != m_config.mac_trunc_length) {
        res.status = SecOcResult::Status::InvalidFrame;
        res.error_detail = "Trailer length mismatch";
        return res;
    }
    
    std::vector<uint8_t> reconstructed_fv(8, 0);
    size_t offset = 8 - secured_pdu.freshness.size();
    std::memcpy(reconstructed_fv.data() + offset, 
                secured_pdu.freshness.data(), 
                secured_pdu.freshness.size());
    
    uint64_t received_fv = extractUintBe(reconstructed_fv);
    res.freshness_value = received_fv;
    
    auto [last_fv_bytes, _] = m_active_fv_provider->getFreshness(m_config.data_id);
    uint64_t last_confirmed = last_fv_bytes.empty() ? 0 : extractUintBe(last_fv_bytes);
    
    if (received_fv <= last_confirmed - m_config.acceptance_window) {
        res.status = SecOcResult::Status::FreshnessFailed;
        res.error_detail = "Stale Freshness Value (anti-replay)";
        return res;
    }
    
    std::vector<uint8_t> data_to_auth = buildDataToAuthenticator(
        m_config.data_id, secured_pdu.payload, reconstructed_fv);
    
    std::vector<uint8_t> expected_full_mac = computeMacAesCmac(data_to_auth);
    if (expected_full_mac.empty()) {
        res.status = SecOcResult::Status::CryptoError;
        res.error_detail = "AES-CMAC computation failed during verification";
        return res;
    }
    
    std::vector<uint8_t> expected_truncated = truncateBe(expected_full_mac, m_config.mac_trunc_length);
    if (std::memcmp(expected_truncated.data(), secured_pdu.mac.data(), m_config.mac_trunc_length) != 0) {
        res.status = SecOcResult::Status::MacFailed;
        res.error_detail = "MAC verification failed";
        return res;
    }
    
    res.status = SecOcResult::Status::Ok;
    res.freshness_verified = true;
    res.pdu = secured_pdu;
    
    m_active_fv_provider->confirmFreshness(m_config.data_id, true);
    
    return res;
}