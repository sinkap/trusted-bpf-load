# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/../libbpf/src"
  "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf/src/libbpf-build"
  "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf"
  "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf/tmp"
  "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf/src/libbpf-stamp"
  "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf/src"
  "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf/src/libbpf-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf/src/libbpf-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf/src/libbpf-stamp${cfgdir}") # cfgdir has leading slash
endif()
