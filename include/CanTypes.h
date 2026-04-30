#pragma once
#include <cstdint>
#include <vector>
#include <string>

struct CanFrame {
    uint32_t id;
    bool is_extended;
    bool is_fd;
    std::vector<uint8_t> data;
    uint64_t timestamp_ns; // monotonic nanoseconds
};

enum class CanError {
    Ok,
    SocketCreateFailed,
    InterfaceNotFound,
    BindFailed,
    SendFailed,
    InvalidFrame
};