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
#include <algorithm> // ADD: for std::remove

static std::string hexDump(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data)
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    return oss.str();
}

static std::vector<uint8_t> parseHex(const std::string& hex) {
    std::vector<uint8_t> out;
    std::istringstream iss(hex);
    std::string byte;
    while (iss >> std::hex >> byte) {
        if (byte.size() == 2) out.push_back(static_cast<uint8_t>(std::stoul(byte, nullptr, 16)));
    }
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
            
            uint32_t id = std::stoul(raw.substr(0, hash), nullptr, 16);
            auto data = parseHex(raw.substr(hash + 1));
            
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
                    if (k == "data_id") cfg.data_id = std::stoul(v, nullptr, 16);
                    else if (k == "fv") cfg.fv_trunc_length = std::stoul(v);
                    else if (k == "mac") cfg.mac_trunc_length = std::stoul(v);
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
                }
                secoc.setConfig(cfg);
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
                
                uint8_t ret = SecOc_Init(&c_cfg);
                if (ret == SECOC_E_OK) {
                    std::cout << "[SecOC C API] Init OK\n";
                    uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
                    uint8_t secured_buf[64];
                    uint16_t secured_len = 0;
                    
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
