cmake_minimum_required(VERSION 3.23.0)

project("HashDB Test Suite" VERSION 0.0.1)

# Add source to this project's executable.
add_executable (CMakeTarget "src/main.cpp")

set_property(TARGET CMakeTarget PROPERTY CXX_STANDARD 23)

# TODO: Add tests and install targets if needed.
