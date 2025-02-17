cmake_minimum_required(VERSION 3.10)
project(encrypt_decrypt)

set(CMAKE_CXX_STANDARD 17)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Manually set OpenSSL include and library paths
include_directories(/opt/homebrew/opt/openssl/include)
link_directories(/opt/homebrew/opt/openssl/lib)

# Add executable
add_executable(encrypt_decrypt main.cpp aes_utils.cpp)

# Link OpenSSL
target_link_libraries(encrypt_decrypt OpenSSL::SSL OpenSSL::Crypto)
