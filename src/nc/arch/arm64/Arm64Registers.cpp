/* The file is part of Snowman decompiler. */
/* See doc/licenses.asciidoc for the licensing information. */

#include "Arm64Registers.h"

namespace nc { namespace arch { namespace arm64 {

Arm64Registers::Arm64Registers() {
#define REGISTER_TABLE <nc/arch/arm64/Arm64RegisterTable.i>
#include <nc/core/arch/RegistersConstructor.i>
}

}}} // namespace nc::arch::arm64

/* vim:set et sts=4 sw=4: */
