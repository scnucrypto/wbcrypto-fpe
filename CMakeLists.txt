cmake_minimum_required(VERSION 3.9.0)

project(wbcrypto-fpe)

# option for opening openssl
find_package(OpenSSL REQUIRED)
option(IMPORT_OPENSSL "option for import openssl dependency" OFF)
set(IMPORT_OPENSSL ON)
message("Note: Import_OPENSSL option is ON. Please make sure openssl is imported into the environment")
add_definitions(-DIMPORT_OPENSSL)

# open test
ADD_SUBDIRECTORY(test)

# global import header file
set(WBCRYPTO_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(WBMATRIX_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/WBMatrix/include)
include_directories(${WBCRYPTO_INCLUDE_DIR})
include_directories(${WBMATRIX_INCLUDE_DIR})

# set the output location of compiled library file and header file
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
file(COPY ${CMAKE_SOURCE_DIR}/include DESTINATION ${CMAKE_BINARY_DIR}/out)

# files in library
aux_source_directory(WBMatrix/src wbcrypto_src)
aux_source_directory(src/modes wbcrypto_src)
aux_source_directory(src/utils wbcrypto_src)
aux_source_directory(src/fpe wbcrypto_src)
aux_source_directory(src/fpe_app wbcrypto_src)

aux_source_directory(src/aes wbcrypto_src)
aux_source_directory(src/sm3 wbcrypto_src)
aux_source_directory(src/sm4 wbcrypto_src)
aux_source_directory(src/wbsm4 wbcrypto_src)
aux_source_directory(src/se_wbsm4 wbcrypto_src)

# static library
add_library(wbcrypto-static ${wbcrypto_src})
SET_TARGET_PROPERTIES(wbcrypto-static PROPERTIES OUTPUT_NAME "wbcrypto")

# dynamic library
add_library(wbcrypto SHARED ${wbcrypto_src})

# install the header and library files to the environment
install(DIRECTORY ${WBCRYPTO_INCLUDE_DIR}/ ${WBMATRIX_INCLUDE_DIR}/ DESTINATION include)
install(TARGETS wbcrypto wbcrypto-static
        LIBRARY DESTINATION lib  
        ARCHIVE DESTINATION lib  
        )

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

