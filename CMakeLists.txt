cmake_minimum_required(VERSION 3.16)
project(secoc-can-toolkit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# Core library (no Qt, cross-platform friendly)
add_library(secoc_core STATIC
    src/CanEngine.cpp
    src/SecOcEngine.cpp
    src/FreshnessManager.cpp
    src/SecOc_AutosarApi.cpp
)
target_include_directories(secoc_core PUBLIC include)
target_link_libraries(secoc_core PRIVATE pthread OpenSSL::Crypto)

# CLI application
add_executable(secoc_cli apps/can_cli/main.cpp)
target_link_libraries(secoc_cli PRIVATE secoc_core)

# Optional: Install targets for system-wide use
install(TARGETS secoc_core secoc_cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
