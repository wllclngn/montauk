#pragma once

// The analyzer and the decoder are entry points inside montauk, not separate
// executables. They used to be their own binaries because montauk hard-linked
// libbpf, liburing and NVML, so a merged binary would have failed to LOAD on a
// box missing any of them -- even to run --decode, which needs none of the
// three. Those are dlopen'd now (util/BpfDyn, util/UringDyn, util/NvmlDyn), so
// the split has nothing left to protect.
//
// Both keep argc/argv main() signatures: they are reached either as a flag
// (`montauk --analyze FILE`) or through an argv[0] symlink that preserves the
// historical `montauk_analyze` / `montauk_trace_decode` names.
int montauk_analyze_main(int argc, char** argv);
int montauk_decode_main(int argc, char** argv);
