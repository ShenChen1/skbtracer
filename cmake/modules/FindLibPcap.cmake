# - Try to find libpcap
# Once done this will define
#
#  LIBPCAP_INCLUDE_DIRS - where to find pcap/pcap.h
#  LIBPCAP_LIBRARIES    - List of libraries when using pcap
#  LIBPCAP_FOUND        - True if pcap found.

set(LIBPCAP_INCLUDE_DIRS "${PROJECT_BINARY_DIR}/3rdparty/libpcap/include")
set(LIBPCAP_LIBRARIES "${PROJECT_BINARY_DIR}/3rdparty/libpcap/lib/libpcap.a")
set(LIBPCAP_FOUND TRUE)
