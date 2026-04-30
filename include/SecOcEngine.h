#pragma once
#include "SecOcTypes.h"
#include "FreshnessManager.h"
#include <memory>
#include <vector>
#include <cstdint>

class SecOcEngine {
public:
    SecOcEngine();
    ~SecOcEngine();
    
    // Configuration
    void setConfig(const SecOcConfig& cfg);
    const SecOcConfig& getConfig() const { return m_config; }
    
    // Freshness Manager injection (external FVM or internal simulator)
    void setFreshnessProvider(std::unique_ptr<IFreshnessProvider> provider);
    
    // Core operations [PRS_SecOc_00200 series]
    SecOcResult wrapTx(const std::vector<uint8_t>& payload);
    SecOcResult unwrapRx(const SecOcPdu& secured_pdu);
    
    // Utility: Build DataToAuthenticator per [PRS_SecOc_00208]
    static std::vector<uint8_t> buildDataToAuthenticator(
        uint16_t data_id, 
        const std::vector<uint8_t>& payload, 
        const std::vector<uint8_t>& full_freshness);

private:
    SecOcConfig m_config;
    
    // Freshness providers: one owns, one is raw pointer to active
    std::unique_ptr<IFreshnessProvider> m_default_fv_provider;   // Internal simulator (owned)
    std::unique_ptr<IFreshnessProvider> m_external_fv_provider;  // External FVM (owned, optional)
    IFreshnessProvider* m_active_fv_provider;                    // Raw pointer to whichever is active (non-owning)
    
    // Cryptographic backend (OpenSSL AES-CMAC)
    std::vector<uint8_t> computeMacAesCmac(const std::vector<uint8_t>& data) const;
    
    // Helper: truncate Big Endian byte array to N bytes
    static std::vector<uint8_t> truncateBe(const std::vector<uint8_t>& be_data, uint8_t target_bytes);
    
    // Helper: extract integer from Big Endian byte array
    static uint64_t extractUintBe(const std::vector<uint8_t>& be_data);
};