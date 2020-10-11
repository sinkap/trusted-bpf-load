# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src

# Include any dependencies generated for this target.
include CMakeFiles/policy.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/policy.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/policy.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/policy.dir/flags.make

policy.skel.h: policy.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: policy"
	bash -c "/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/bpftool/bootstrap/bpftool gen skeleton /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/policy.bpf.o > /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/policy.skel.h"

policy.bpf.o: policy.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: policy"
	/usr/local/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/local/lib/clang/19/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/../vmlinux/x86 -isystem /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/libbpf -c /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/policy.bpf.c -o /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/policy.bpf.o

CMakeFiles/policy.dir/policy.c.o: CMakeFiles/policy.dir/flags.make
CMakeFiles/policy.dir/policy.c.o: policy.c
CMakeFiles/policy.dir/policy.c.o: CMakeFiles/policy.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/policy.dir/policy.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/policy.dir/policy.c.o -MF CMakeFiles/policy.dir/policy.c.o.d -o CMakeFiles/policy.dir/policy.c.o -c /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/policy.c

CMakeFiles/policy.dir/policy.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/policy.dir/policy.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/policy.c > CMakeFiles/policy.dir/policy.c.i

CMakeFiles/policy.dir/policy.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/policy.dir/policy.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/policy.c -o CMakeFiles/policy.dir/policy.c.s

# Object files for target policy
policy_OBJECTS = \
"CMakeFiles/policy.dir/policy.c.o"

# External object files for target policy
policy_EXTERNAL_OBJECTS =

policy: CMakeFiles/policy.dir/policy.c.o
policy: CMakeFiles/policy.dir/build.make
policy: libbpf/libbpf.a
policy: CMakeFiles/policy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable policy"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/policy.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/policy.dir/build: policy
.PHONY : CMakeFiles/policy.dir/build

CMakeFiles/policy.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/policy.dir/cmake_clean.cmake
.PHONY : CMakeFiles/policy.dir/clean

CMakeFiles/policy.dir/depend: policy.bpf.o
CMakeFiles/policy.dir/depend: policy.skel.h
	cd /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src /usr/local/google/home/kpsingh/projects/trusted-bpf-load/src/CMakeFiles/policy.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/policy.dir/depend
