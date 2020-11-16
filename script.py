import idc
from idc import *
from idautils import *
from sympy import Symbol, Function, Eq, Ne, IndexedBase, Integer
from ctypes import c_int64
import imp
import sys

sys.path.append('D:\\VUZ\\NIR\\idapython\\')

import arm
import asmstructs
import symstack
import codestructs
import fprint
from fprint import printf

imp.reload(fprint)
imp.reload(arm)
imp.reload(asmstructs)
imp.reload(symstack)
imp.reload(codestructs)

asmstructs.command
asmstructs.operand

print("Hello from VSCode")

f = fprint.fopen('D:\\VUZ\\NIR\\idapython_output\\output.txt')
print >> f, 'Helo'

class Analyzer():
    def __init__(self):
        functions = []
        dfunctions = {}
        previous_ea = -1
        previous_cmd = ''
        for segea in Segments():
            for funcea in Functions(segea, SegEnd(segea)):
            #for funcea in Functions(ea, 0x0620):
                functionName = GetFunctionName(funcea)
                code_function = codestructs.function(functionName, funcea)
                block = codestructs.block(0)
                for (startea, endea) in Chunks(funcea):
                    for head in Heads(startea, endea):
                        print(hex(head)[2:-1], ':', [' ' + hex(i)[2:-1] + ' ' for i in CodeRefsTo(head, True)])
                        t = type(GetDisasm(head))
                        #print functionName, ":", "0x%08x"%(head), ":", GetDisasm(head)
                        instruction = DecodeInstruction(head)
                        operands = instruction.Operands
                        asm_cmd = asmstructs.command(print_insn_mnem(head), head)
                        i = 0
                        while True:
                            op_type = get_operand_type(head, i)
                            if op_type in [0, -1]:
                                break
                            op_name = print_operand(head, i)
                            op_value = get_operand_value(head, i)
                            asm_cmd.op_append(asmstructs.operand(op_name, op_type, op_value))
                            i += 1
                        refs = [(True, r) for r in CodeRefsTo(head, False)]
                        
                        if (not refs 
                                and previous_cmd not in ['B.NE']
                                and previous_cmd not in ['BL']):
                            block.code_append(asm_cmd)
                        else:
                            if block.code:
                                block.endea = previous_ea
                                code_function.codeblock_append(block)
                            block = codestructs.block(asm_cmd.ea)
                            block.code_append(asm_cmd)
                            if previous_cmd not in ['B']:
                                if previous_cmd not in ['B.NE']:
                                    block.refs_to_it = [(True, previous_ea)] + refs
                                else:
                                    block.refs_to_it = [(False, previous_ea)] + refs
                            else:
                                block.refs_to_it = refs

                        previous_ea = head
                        previous_cmd = asm_cmd.name
                    
                    if block.code:
                        block.endea = previous_ea
                        code_function.codeblock_append(block)
                functions.append(code_function)
                dfunctions[code_function.startea] = code_function
        self.functions = functions
        self.dfunctions = dfunctions

    def static_analyze(self):
        path = []
        #path.append(0x0620)
        path.append(0x0644)
        return path

    def back_symbol_propagation(self, path):
        printf(self.dfunctions[0x0644])
        printf(self.dfunctions[0x0644].create_restrictions(0x67c))
        C, Stack_C = self.dfunctions.get(path[0]).create_restrictions()
        return C, Stack_C


a = Analyzer()


printf(a.back_symbol_propagation(a.static_analyze()))

fprint.fclose()

#sys.stdout.close()
#sys.stdout = stdout


