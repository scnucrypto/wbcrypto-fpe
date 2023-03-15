cmake_minimum_required(VERSION 3.9.0)

project(fpe_udf)

set(CMAKE_BUILD_TYPE Release)

include_directories(/usr/include/mysql)
include_directories(../include)

link_directories(/usr/lib/mysql)
#link_directories(/usr/lib64/mysql)
link_directories(../build/out)

option(MYSQL8 "using mysql8" OFF)
if (MYSQL8)
    add_library(udf SHARED mysql8.cpp)
    message("Note: mysql version should be 8")
else()
    add_library(udf SHARED mysql5.cpp)
    message("Note: mysql version should be 5")
endif()
    
target_link_libraries(udf mysqlclient wbcrypto -lm)

set_target_properties(udf PROPERTIES PREFIX "")

install(TARGETS udf DESTINATION /usr/lib/mysql/plugin)
#install(TARGETS udf DESTINATION /usr/lib64/mysql/plugin)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wl,-rpath=\"/usr/local/lib\" -O3")

