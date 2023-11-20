cmake_minimum_required(VERSION 3.17)
project(CS7339_PasswordCracking)

include_directories("hashlib2plus/trunk/src")

set(CMAKE_CXX_STANDARD 14)
set(SOURCE_FILES main.cpp "hashlib2plus/trunk/src/hashlibpp.h")

add_executable(CS7339_PasswordCracking main.cpp
        "hashlib2plus/trunk/src/hashlibpp.h"
        "hashlib2plus/trunk/src/hl_md5wrapper.cpp"
        "hashlib2plus/trunk/src/hl_md5.cpp"
        "hashlib2plus/trunk/src/hl_sha256wrapper.cpp"
        "hashlib2plus/trunk/src/hl_sha256.cpp"
        )