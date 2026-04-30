#pragma once
#include "SecOcTypes.h"
#include <functional>
#include <mutex>
#include <chrono>

// Interface for external Freshness Value Manager (FVM)
// Matches AUTOSAR requirement: FVM provides FV via byte arrays [PRS_SecOc_00105]
class IFreshnessProvider {
public:
    virtual ~IFreshnessProvider() = default;
    
    // Get current FV for given DataId (Big Endian byte array, length in bits)
    virtual std::pair<std::vector<uint8_t>, uint16_t> getFreshness(uint16_t data_id) = 0;
    
    // Confirm FV usage (for synchronization in distributed systems)
    virtual void confirmFreshness(uint16_t data_id, bool verification_success) = 0;
};

// Built-in simulator implementation (counter-based or timestamp-based)
class SimulatedFreshnessManager : public IFreshnessProvider {
public:
    enum class Mode { Counter, Timestamp };
    
    explicit SimulatedFreshnessManager(Mode mode = Mode::Counter);
    
    std::pair<std::vector<uint8_t>, uint16_t> getFreshness(uint16_t data_id) override;
    void confirmFreshness(uint16_t data_id, bool verification_success) override;
    
    // For testing: manually set counter/timestamp
    void setCounterValue(uint64_t val);
    void setTimestampValue(uint64_t epoch_ms);
    
    uint64_t getCurrentValue() const;

private:
    Mode m_mode;
    mutable std::mutex m_mutex;
    uint64_t m_counter = 0;
    uint64_t m_timestamp_epoch_ms = 0;
};