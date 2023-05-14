include_directories(${CMAKE_SOURCE_DIR}/include)

set(TEST_BUILD_NAME fpe_test)
add_executable(${TEST_BUILD_NAME} fpe_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)

set(TEST_BUILD_NAME fpe_app_test)
add_executable(${TEST_BUILD_NAME} fpe_app_test.c test_utils.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto -lssl -lcrypto -lm)
