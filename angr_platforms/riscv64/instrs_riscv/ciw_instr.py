from .instruction_patterns import RISCV_Instruction, CIW_Instruction
from pyvex.lifting.util import Type, Instruction, ParseError
from bitstring import BitArray


class Instruction_CADDI4SPN(CIW_Instruction):
    opcode = '00'
    func3 = '000'
    name = 'CADDI4SPN'

    def extra_constraints(self, data, bitstream):
        if data['i'] == '00000000':
            raise ParseError("Immediate can not be 0")
        return data

    def compute_result(self, dst):
        immstr = '{1}{0}{2}{3}00'.format(self.data['i'][0:2], self.data['i'][2:6], self.data['i'][7], self.data['i'][6])
        val = self.constant(BitArray(bin=immstr).int, Type.int_32) + self.get(2, Type.int_32)
        self.put(val, dst)
