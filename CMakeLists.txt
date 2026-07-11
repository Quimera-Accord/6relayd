cmake_minimum_required(VERSION 3.10)

project(6relayd C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # needed for _GNU_SOURCE-gated glibc/musl bits

add_executable(6relayd
	src/6relayd.c
	src/router.c
	src/dhcpv6.c
	src/ndp.c
	src/md5.c
	src/dhcpv6-ia.c
	src/pd-lease-watcher.c
)

target_compile_definitions(6relayd PRIVATE _GNU_SOURCE)
target_compile_options(6relayd PRIVATE -g -Wall -Wextra -Werror -pedantic)

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
