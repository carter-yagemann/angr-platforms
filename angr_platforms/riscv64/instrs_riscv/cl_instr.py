# pylint: disable=W0613,R0201,W0221
from .instruction_patterns import CL_Instruction
from pyvex.lifting.util import Type, ParseError
from bitstring import BitArray


class Instruction_CLW(CL_Instruction):
    opcode = '00'
    func3 = '010'
    name = 'CLW'

    def compute_result(self, src1, dst_addr):
        bitstr = '{2}{1}{0}00'.format(self.data['i'][0], self.data['I'], self.data['i'][1])
        offset = self.constant(BitArray(bin=bitstr).int, Type.int_64)
        val = self.load(offset + src1, Type.int_32)
        self.put(val, dst_addr)


class Instruction_CLD(CL_Instruction):
    opcode = '10'
    func3 = '011'
    name = 'CLD'

    def compute_result(self, src1, dst_addr):
        bitstr = '{1}{0}000'.format(self.data['I'], self.data['i'])
        offset = self.constant(BitArray(bin=bitstr).int, Type.int_64)
        val = self.load(offset + src1, Type.int_64)
        self.put(val, dst_addr)
