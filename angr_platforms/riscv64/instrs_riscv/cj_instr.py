# pylint: disable=W0221
from .instruction_patterns import CJ_Instruction
from pyvex.lifting.util import Type

class Instruction_CJ(CJ_Instruction):
    opcode = '01'
    func3 = '101'
    name = "CJ"

    def compute_result(self, imm):
        self.jump(None, self.addr + imm)

'''C.JAL is a RV32C-only instruction'''
