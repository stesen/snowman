/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#pragma once

#include <nc/config.h>

#include <nc/core/arch/Registers.h>

namespace nc { namespace arch { namespace arm64 {

/**
 * Container class for ARM64 registers.
 */
class Arm64Registers: public core::arch::StaticRegisters<Arm64Registers> {
public:
    Arm64Registers();

#define REGISTER_TABLE <nc/arch/arm64/Arm64RegisterTable.i>
#include <nc/core/arch/Registers.i>
};

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
