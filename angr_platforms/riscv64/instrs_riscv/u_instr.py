# pylint: disable=W0221
from .instruction_patterns import U_Instruction
from pyvex.lifting.util import Type

class Instruction_LUI(U_Instruction):
    opcode='0110111'
    name='LUI'

    def compute_result(self, _, imm):
        ui = (imm << self.constant(12, Type.int_8)) & self.constant(0xffffffff, Type.int_32)
        return ui.cast_to(Type.int_64, signed=True)

class Instruction_AUIPC(U_Instruction):
    opcode='0010111'
    name='AUIPC'

    def compute_result(self, _ , imm):
        ui = (imm << self.constant(12, Type.int_8)) & self.constant(0xffffffff, Type.int_32)
        return self.addr + ui.cast_to(Type.int_64, signed=True)
