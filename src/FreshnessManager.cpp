#include "FreshnessManager.h"
#include <chrono>

SimulatedFreshnessManager::SimulatedFreshnessManager(Mode mode) 
    : m_mode(mode) 
{
    if (mode == Mode::Timestamp) {
        m_timestamp_epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
}

std::pair<std::vector<uint8_t>, uint16_t> SimulatedFreshnessManager::getFreshness(uint16_t /*data_id*/) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_mode == Mode::Counter) {
        // Return 64-bit counter in Big Endian
        std::vector<uint8_t> be(8);
        for (int i = 7; i >= 0; --i) {
            be[i] = m_counter & 0xFF;
            m_counter >>= 8;
        }
        // Restore counter (we consumed it above)
        m_counter = (m_counter << 8) | be[7]; // Simplified for demo
        return {be, 64}; // 64-bit FV
    } else {
        // Return timestamp in Big Endian (64-bit milliseconds)
        std::vector<uint8_t> be(8);
        uint64_t ts = m_timestamp_epoch_ms;
        for (int i = 7; i >= 0; --i) {
            be[i] = ts & 0xFF;
            ts >>= 8;
        }
        return {be, 64};
    }
}

void SimulatedFreshnessManager::confirmFreshness(uint16_t /*data_id*/, bool verification_success) {
    if (verification_success && m_mode == Mode::Counter) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_counter++; // Increment only on successful verification
    }
    // Timestamp mode: no action needed (time advances naturally)
}

void SimulatedFreshnessManager::setCounterValue(uint64_t val) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_counter = val;
}

void SimulatedFreshnessManager::setTimestampValue(uint64_t epoch_ms) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_timestamp_epoch_ms = epoch_ms;
}

uint64_t SimulatedFreshnessManager::getCurrentValue() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return (m_mode == Mode::Counter) ? m_counter : m_timestamp_epoch_ms;
}