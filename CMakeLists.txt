cmake_minimum_required(VERSION 3.23.0)

project("HashDB Test Suite" VERSION 0.0.1)

# Add source to this project's executable.
set(HASHDB_TARGET_NAME "hashdb-tests-${TARGET_NAME}")
file(GLOB SOURCE_FILES CONFIGURE_DEPENDS "*/*.hpp" "*/*.cpp")
add_executable(${HASHDB_TARGET_NAME} ${SOURCE_FILES})

# C++ Language Standard
set_property(TARGET ${HASHDB_TARGET_NAME} PROPERTY CXX_STANDARD 23)

# TODO: Add tests and install targets if needed.
