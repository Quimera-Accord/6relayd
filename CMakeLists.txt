cmake_minimum_required(VERSION 3.13)

project(6relayd C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(6relayd
	src/6relayd.c
	src/router.c
	src/dhcpv6.c
	src/ndp.c
	src/md5.c
	src/dhcpv6-ia.c
	src/pd-sniffer.c
)

target_compile_definitions(6relayd PRIVATE
	_GNU_SOURCE
	_FORTIFY_SOURCE=2
)

# -O2 rather than -O3: this is a small, syscall/IO-bound network daemon,
# not a numeric hot loop -- -O3's extra inlining/vectorization tends to
# just grow code size (and instruction-cache pressure) on a small-cache
# embedded MIPS target without a measurable runtime win here. No -g:
# release build, size/speed only, no debug symbols. Kept
# -fstack-protector-strong per explicit request (cheap insurance, not
# worth trading away for this).
target_compile_options(6relayd PRIVATE
	-O2
	-Wall -Wextra -Werror -pedantic
	-Wformat -Wformat-security
	-fstack-protector-strong
	-ffunction-sections -fdata-sections
)

# Cross toolchain target: mips32r2 (per project SoC). Only applied when
# actually cross-compiling for MIPS -- harmless/skipped on a native x86_64
# dev/test build, so this doesn't break `cmake .` on a regular machine.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")
	target_compile_options(6relayd PRIVATE -march=mips32r2)
endif()

target_link_options(6relayd PRIVATE -Wl,--gc-sections -s -static)

target_link_libraries(6relayd resolv)

# Installation
install(TARGETS 6relayd DESTINATION sbin/)

# Packaging information
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "6relayd")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

set(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)
