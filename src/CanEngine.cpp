#include "CanEngine.h"
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <chrono>

bool CanEngine::open(const std::string& iface) {
    close();
    m_sock = socket(AF_CAN, SOCK_RAW, CAN_RAW);
    if (m_sock < 0) return false;

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(m_sock, SIOCGIFINDEX, &ifr) < 0) {
        ::close(m_sock); m_sock = -1; return false;
    }

    struct sockaddr_can addr{};
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(m_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(m_sock); m_sock = -1; return false;
    }

    int enable_fd = 1;
    setsockopt(m_sock, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_fd, sizeof(enable_fd));
    
    int recv_own = 1;
    setsockopt(m_sock, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &recv_own, sizeof(recv_own));

    m_is_open = true;
    m_rx_running = true;
    m_rx_thread = std::thread(&CanEngine::rxLoop, this);
    return true;
}

void CanEngine::close() {
    m_rx_running = false;
    if (m_rx_thread.joinable()) m_rx_thread.join();
    if (m_sock >= 0) { ::close(m_sock); m_sock = -1; }
    m_is_open = false;
}

bool CanEngine::send(const CanFrame& frame) {
    if (!m_is_open) return false;

    if (frame.is_fd) {
        struct canfd_frame fd_frame{};
        fd_frame.can_id = frame.id | (frame.is_extended ? CAN_EFF_FLAG : 0) | CANFD_BRS;
        fd_frame.len = std::min(frame.data.size(), static_cast<size_t>(CANFD_MAX_DLEN));
        std::memcpy(fd_frame.data, frame.data.data(), fd_frame.len);
        return ::write(m_sock, &fd_frame, sizeof(fd_frame)) > 0;
    } else {
        struct can_frame c_frame{};
        c_frame.can_id = frame.id | (frame.is_extended ? CAN_EFF_FLAG : 0);
        c_frame.can_dlc = std::min(frame.data.size(), static_cast<size_t>(CAN_MAX_DLEN));
        std::memcpy(c_frame.data, frame.data.data(), c_frame.can_dlc);
        return ::write(m_sock, &c_frame, sizeof(c_frame)) > 0;
    }
}

void CanEngine::setRxCallback(FrameCallback cb) {
    std::lock_guard<std::mutex> lock(m_cb_mutex);
    m_rx_cb = std::move(cb);
}

void CanEngine::setErrorCallback(ErrorCallback cb) {
    std::lock_guard<std::mutex> lock(m_cb_mutex);
    m_err_cb = std::move(cb);
}

void CanEngine::rxLoop() {
    struct pollfd pfd{m_sock, POLLIN, 0};
    while (m_rx_running.load()) {
        int ret = poll(&pfd, 1, 100); // 100ms timeout
        if (ret > 0 && (pfd.revents & POLLIN)) {
            struct canfd_frame fd_frame;
            ssize_t nbytes = read(m_sock, &fd_frame, sizeof(fd_frame));
            if (nbytes < 0) continue;

            CanFrame frame;
            frame.is_fd = (fd_frame.len > CAN_MAX_DLEN);
            frame.is_extended = fd_frame.can_id & CAN_EFF_FLAG;
            frame.id = fd_frame.can_id & CAN_EFF_MASK;
            frame.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();

            int dlc = std::min(fd_frame.len, static_cast<__u8>(CANFD_MAX_DLEN));
            frame.data.assign(fd_frame.data, fd_frame.data + dlc);

            std::lock_guard<std::mutex> lock(m_cb_mutex);
            if (m_rx_cb) m_rx_cb(frame);
        }
    }
}