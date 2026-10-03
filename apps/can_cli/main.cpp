#include "../../include/CanEngine.h"
#include "../../include/SecOcEngine.h"
#include "../../include/SecOc_AutosarApi.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <cstring>
#include <cctype>
#include <stdexcept>
#include <algorithm> // ADD: for std::remove

static std::string hexDump(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data)
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    return oss.str();
}

static std::vector<uint8_t> parseHex(const std::string& hex) {
    // Accepts "DEADBEEF", "DE AD BE EF" or mixed; throws std::invalid_argument on bad input
    std::string clean;
    for (char c : hex) {
        if (c == ' ' || c == '\t') continue;
        if (!std::isxdigit(static_cast<unsigned char>(c))) throw std::invalid_argument("non-hex character in data");
        clean.push_back(c);
    }
    if (clean.size() % 2 != 0) throw std::invalid_argument("odd number of hex digits");
    std::vector<uint8_t> out;
    for (size_t i = 0; i < clean.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16)));
    return out;
}

int main() {
    CanEngine can;
    SecOcEngine secoc;
    bool secoc_enabled = false;
    bool monitor_on = false;

    std::cout << "=== CAN/SecOC Terminal ===\n"
              << "Commands: open <iface>, tx <id>#<data>, secoc <enable|disable|config|test_c_api>, monitor <on|off>, quit\n";

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit" || cmd == "exit") break;
        else if (cmd == "open") {
            std::string iface; iss >> iface;
            if (can.open(iface)) std::cout << "[OK] Opened " << iface << "\n";
            else std::cout << "[ERR] Failed to open " << iface << "\n";
        }
        else if (cmd == "tx") {
            std::string raw; iss >> raw;
            auto hash = raw.find('#');
            if (hash == std::string::npos) { std::cout << "[ERR] Format: tx ID#DATA\n"; continue; }
            
            uint32_t id;
            std::vector<uint8_t> data;
            try {
                unsigned long id_ul = std::stoul(raw.substr(0, hash), nullptr, 16);
                if (id_ul > 0x1FFFFFFF) { std::cout << "[ERR] ID out of range (max 0x1FFFFFFF)\n"; continue; }
                id = static_cast<uint32_t>(id_ul);
                data = parseHex(raw.substr(hash + 1));
            } catch (const std::exception& e) {
                std::cout << "[ERR] Invalid tx argument: " << e.what() << "\n";
                continue;
            }
            
            CanFrame frame{id, id > 0x7FF, false, data, 0};
            
            if (secoc_enabled) {
                auto res = secoc.wrapTx(data);
                if (res.status == SecOcResult::Status::Ok) {
                    std::vector<uint8_t> secured;
                    secured.insert(secured.end(), res.pdu.header.begin(), res.pdu.header.end());
                    secured.insert(secured.end(), res.pdu.payload.begin(), res.pdu.payload.end());
                    secured.insert(secured.end(), res.pdu.freshness.begin(), res.pdu.freshness.end());
                    secured.insert(secured.end(), res.pdu.mac.begin(), res.pdu.mac.end());
                    frame.data = std::move(secured);
                    frame.is_fd = true;
                    std::cout << "[SecOC] Wrapped | FV=" << res.freshness_value << "\n";
                } else {
                    std::cout << "[SecOC ERR] " << res.error_detail << "\n";
                    continue;
                }
            }
            
            if (can.send(frame)) std::cout << "[TX] 0x" << std::hex << id << std::dec << " | " << frame.data.size() << " bytes\n";
            else std::cout << "[ERR] Send failed\n";
        }
        else if (cmd == "secoc") {
            std::string sub; iss >> sub;
            if (sub == "enable") { 
                secoc_enabled = true; 
                std::cout << "[SecOC] Enabled (C++ API)\n"; 
            }
            else if (sub == "disable") { 
                secoc_enabled = false; 
                std::cout << "[SecOC] Disabled\n"; 
            }
            else if (sub == "config") {
                SecOcConfig cfg = secoc.getConfig();
                std::string param;
                while (iss >> param) {
                    auto eq = param.find('=');
                    if (eq == std::string::npos) continue;
                    std::string k = param.substr(0, eq);
                    std::string v = param.substr(eq + 1);
                    try {
                    if (k == "data_id") {
                        unsigned long n = std::stoul(v, nullptr, 16);
                        if (n > 0xFFFF) throw std::out_of_range("data_id > 0xFFFF");
                        cfg.data_id = static_cast<uint16_t>(n);
                    }
                    else if (k == "fv") {
                        unsigned long n = std::stoul(v);
                        if (n > 255) throw std::out_of_range("fv > 255");
                        cfg.fv_trunc_length = static_cast<uint8_t>(n);
                    }
                    else if (k == "mac") {
                        unsigned long n = std::stoul(v);
                        if (n > 255) throw std::out_of_range("mac > 255");
                        cfg.mac_trunc_length = static_cast<uint8_t>(n);
                    }
                    else if (k == "key") {
                        // ✅ FIXED: Robust hex parser for continuous or spaced keys
                        cfg.auth_key.clear();
                        std::string hex_str = v;
                        hex_str.erase(std::remove(hex_str.begin(), hex_str.end(), ' '), hex_str.end());
                        for (size_t i = 0; i + 1 < hex_str.length(); i += 2) {
                            std::string byte_str = hex_str.substr(i, 2);
                            char* end;
                            long val = std::strtol(byte_str.c_str(), &end, 16);
                            if (end != byte_str.c_str()) {
                                cfg.auth_key.push_back(static_cast<uint8_t>(val));
                            }
                        }
                        if (cfg.auth_key.size() != 16) {
                            std::cout << "[WARN] Key parsed as " << cfg.auth_key.size() << " bytes (expected 16 for AES-128)\n";
                        }
                    }
                    } catch (const std::exception& e) {
                        std::cout << "[ERR] Bad value for '" << k << "': " << e.what() << "\n";
                    }
                }
                if (!secoc.setConfig(cfg)) {
                    std::cout << "[ERR] Invalid config (need 1<=mac<=16, 1<=fv<=8, 16-byte key); not applied\n";
                    continue;
                }
                std::cout << "[SecOC] Config updated | DataId=0x" << std::hex << cfg.data_id << std::dec 
                          << " FV=" << static_cast<int>(cfg.fv_trunc_length) 
                          << " MAC=" << static_cast<int>(cfg.mac_trunc_length)
                          << " KeyLen=" << cfg.auth_key.size() << "\n";
            }
            else if (sub == "test_c_api") {
                uint8_t test_key[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
                SecOc_ConfigType c_cfg{};
                c_cfg.SecOCDataId = 0x123;
                c_cfg.SecOCFreshnessValueTruncLength = 4;
                c_cfg.SecOCAuthInfoTruncLength = 4;
                c_cfg.SecOCAuthKey = test_key;
                c_cfg.SecOCRxAcceptanceWindow = 1000;
                
                uint8_t ret = SecOc_Init(&c_cfg);
                if (ret == SECOC_E_OK) {
                    std::cout << "[SecOC C API] Init OK\n";
                    uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
                    uint8_t secured_buf[64];
                    uint16_t secured_len = sizeof(secured_buf); // in: capacity
                    
                    ret = SecOc_Transmit(0x123, payload, sizeof(payload), secured_buf, &secured_len);
                    if (ret == SECOC_E_OK) {
                        std::cout << "[SecOC C API] TX OK | SecuredLen=" << secured_len << "\n";
                    }
                    SecOc_DeInit();
                } else {
                    std::cout << "[SecOC C API] Init failed: " << static_cast<int>(ret) << "\n";
                }
            }
        }
        else if (cmd == "monitor") {
            std::string state; iss >> state;
            monitor_on = (state == "on");
            if (monitor_on) {
                can.setRxCallback([&](const CanFrame& f) {
                    std::cout << "[RX] ts=" << f.timestamp_ns << " ID=0x" << std::hex << f.id << std::dec
                              << " DLC=" << f.data.size() << " Data=" << hexDump(f.data) << "\n";
                });
                std::cout << "[Monitor] ON\n";
            } else {
                can.setRxCallback(nullptr);
                std::cout << "[Monitor] OFF\n";
            }
        }
        else if (!cmd.empty()) {
            std::cout << "[?] Unknown command: " << cmd << "\n";
        }
    }

    can.close();
    std::cout << "Shutdown complete.\n";
    return 0;
}
