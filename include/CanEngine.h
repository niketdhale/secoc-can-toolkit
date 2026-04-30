#pragma once
#include "CanTypes.h"
#include <functional>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>

class CanEngine {
public:
    using FrameCallback = std::function<void(const CanFrame&)>;
    using ErrorCallback = std::function<void(const std::string&)>;

    bool open(const std::string& iface);
    void close();
    bool send(const CanFrame& frame);
    void setRxCallback(FrameCallback cb);
    void setErrorCallback(ErrorCallback cb);
    bool isOpen() const { return m_is_open; }

private:
    void rxLoop();
    int m_sock = -1;
    std::atomic<bool> m_is_open{false};
    std::atomic<bool> m_rx_running{false};
    std::thread m_rx_thread;
    FrameCallback m_rx_cb;
    ErrorCallback m_err_cb;
    std::mutex m_cb_mutex;
};