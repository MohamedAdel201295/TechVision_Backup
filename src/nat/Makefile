# tvnat.exe — the native half of the TechVision gateway NAT service.
#
# Cross-compiled for Windows x64 with mingw (the sandbox is Linux;
# the .exe cannot run here — see below). The output is a BUILD
# ARTIFACT, never committed: it is rebuilt from source whenever the
# app is packaged for Windows, and the Node side (src/nat-gateway.js)
# reports a clear error when it is missing instead of pretending
# the service works.
#
#   make            build src/nat/tvnat.exe (default)
#   make check      build it, then verify it is a real x64 Windows
#                   .exe that links WinDivert + iphlpapi
#   make clean      remove the built .exe
#
# Layout (relative to this directory, src/nat/):
#   tvnat.c / tvnat_core.c / tvnat_core.h  — this helper (do not edit
#     the vendor tree below; the WinDivert binaries ship unmodified)
#   vendor/WinDivert-2.2.2-A/
#     include/windivert.h                 — WinDivert API header
#     x64/WinDivert.lib                   — import library (linked)
#     x64/WinDivert.dll                   — loaded at runtime from
#       the same folder as the .exe's PATH entry (see nat-gateway.js:
#       the vendor dir is prepended to PATH when tvnat.exe spawns)
#     x64/WinDivert64.sys                 — the signed driver, loaded
#       by WinDivert.dll from its own directory on first open
#
# Windows-only, provable only on the user's machine: driver load,
# real packet translation, throughput, proxy ARP / secondary IPs.
# What `make check` DOES prove here: the helper compiles clean with
# -Wall -Wextra, links against the real WinDivert import library,
# and is a valid PE32+ x64 binary.
#
# Link notes: mingw's ld consumes the MSVC import library
# WinDivert.lib directly. If a toolchain ever refuses it, generate
# an import library from the DLL instead:
#   x86_64-w64-mingw32-dlltool -d WinDivert.def -l libwindivert.a
# (the .def is not shipped — the .lib works with the mingw in this
# sandbox, verified 2026-11-24.)

CC      := x86_64-w64-mingw32-gcc
WINDIR  := vendor/WinDivert-2.2.2-A
CFLAGS  := -O2 -Wall -Wextra -std=c99 -I$(WINDIR)/include
LDFLAGS := $(WINDIR)/x64/WinDivert.lib -liphlpapi -lws2_32

SRC := tvnat.c tvnat_core.c
OBJ := $(SRC:.c=.o)
EXE := tvnat.exe

.PHONY: all check clean

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c tvnat_core.h
	$(CC) $(CFLAGS) -c $< -o $@

check: $(EXE)
	@file $(EXE) | grep -q 'PE32+ executable.*x86-64' || \
		{ echo 'FAIL: $(EXE) is not an x64 Windows executable'; exit 1; }
	@x86_64-w64-mingw32-objdump -p $(EXE) | grep -qi 'WinDivert.dll' || \
		{ echo 'FAIL: $(EXE) does not link WinDivert.dll'; exit 1; }
	@x86_64-w64-mingw32-objdump -p $(EXE) | grep -qi 'IPHLPAPI.dll' || \
		{ echo 'FAIL: $(EXE) does not link IPHLPAPI.dll'; exit 1; }
	@echo 'OK: $(EXE) is a valid x64 Windows executable linked against WinDivert + IPHLPAPI'
	@ls -l $(EXE)

clean:
	rm -f $(OBJ) $(EXE)
