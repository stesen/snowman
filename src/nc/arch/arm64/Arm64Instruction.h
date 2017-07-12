/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#pragma once

#include <nc/config.h>

#include <nc/core/arch/CapstoneInstruction.h>

namespace nc {
namespace arch {
namespace arm64 {

typedef core::arch::CapstoneInstruction<CS_ARCH_ARM64, 4> Arm64Instruction;

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
