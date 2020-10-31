from idc import *
from idautils import *
import symstack
from sympy import Symbol, Function, Eq, Ne, IndexedBase
import arm

from debugprint import printf

class block():
    def __init__(self, ea):
        self.startea = ea
        self.endea = ea
        self.code = []
        self.refs_to_it = []
    
    def code_append(self, value):
        self.code.append(value)
    
    def refs_append(self, value):
        self.refs_to_it.append(value)

    def __getitem__(self, index):
        return self.code[index]

    def __len__(self):
        return len(self.code)

    def __str__(self, prefix='', postfix='', w=68):
        endline = '|' + postfix + '\n' + prefix
        result = prefix
        result +=  ' ' + '_'*w + ' ' + postfix + '\n' + prefix
        result += '| beg: ' + '%08x'%self.startea + (w - 14)*' ' + endline
        result += '|' + '-'*w + endline
        for r in self.refs_to_it:
            result += '| ' + ('[+]' if r[0] else '[-]') + ' %08x ->'%r[1] + (w - 16)*' ' + endline
        result += '|' + '-'*w + endline
        for cmd in self.code:
            result += '| ' + '%-*s'%(w - 1, str(cmd)) + endline
        result += '|' + '-'*w + endline
        result += '| end: ' + '%08x'%self.endea + (w - 14)*' ' + endline
        result += '|' + '_'*w + '|' + postfix + '\n'
        return result

    def __repr__(self):
        return self.__str__()

class function():
    def __init__(self, name, ea):
        self.name = name
        self.startea = ea
        self.refs_to_it = [ref for ref in CodeRefsTo(ea, False)]
        self.codeblocks = []
        self.dcodeblocks = {}
        self.C = []
        self.SP_C = {}
        try:
            self.stack = symstack.stack(ea)
        except Exception:
            self.stack = None
    
    def codeblock_append(self, codeblock):
        self.dcodeblocks[codeblock.endea] = codeblock
        self.codeblocks.append(codeblock)

    def subs_restriction(self, *args):
        for i in range(len(self.C)):
            self.C[i] = self.C[i].subs(*args)
        for key in self.SP_C.keys():
            self.SP_C[key] = self.SP_C[key].subs(*args)

    def simplify_restriction(self):
        new_SP_var = {}
        if self.stack is not None:
            for key, val in self.SP_C.items():
                if arm.SP == val or arm.SP in val.args:
                    self.SP_C.pop(key)
                    offset = val.subs('SP', 0)
                    new_SP_var[key] = self.stack.member_size(offset)
        for i in range(len(self.C)):
            self.C[i] = self.C[i].subs(new_SP_var).simplify()


    def create_restrictions(self, block_endea = 0x5fc):
        self.C = []
        self.SP_C = {}
        strlen = Function('strlen')
        mem = IndexedBase('mem')
        memlen = Function('memlen')
        cond = True
        cur_block = self.dcodeblocks.get(block_endea)
        var_SP_id = 0
        printf(cur_block)
        while cur_block is not None:
            for cmd in reversed(cur_block):
                if cmd.name == 'BL':
                    function_name = get_func_name(cmd.operands[0].value)
                    printf(function_name)
                    if function_name == '.strcpy':
                        self.C.append(strlen(arm.X1) < Symbol('STACK_%d'%var_SP_id))
                        self.SP_C['STACK_%d'%var_SP_id] = arm.X0
                        var_SP_id += 1
                    elif function_name == 'bad_code':
                        printf('bad')
                        self.C.append(strlen(arm.X1) < 12)
                        self.C.append(Eq(arm.W0, 12))
                elif cmd.name == 'MOV':
                    op0 = cmd.operands[0].value
                    op1 = cmd.operands[1].value
                    self.subs_restriction(op0, op1)
                elif cmd.name == 'LDR' or cmd.name == 'LDUR':
                    op0 = cmd.operands[0].value
                    op1 = cmd.operands[1].value
                    self.subs_restriction(op0, mem[op1])
                elif cmd.name == 'STR' or cmd.name == 'STUR':
                    op0 = cmd.operands[0].value
                    op1 = cmd.operands[1].value
                    self.subs_restriction(mem[op1], op0)
                elif cmd.name == 'B.NE':
                    if cond:
                        self.C.append(Ne(Symbol('B.NE.0'), Symbol('B.NE.1')))
                    else:
                        self.C.append(Eq(Symbol('B.NE.0'), Symbol('B.NE.1')))
                elif cmd.name == 'CMP':
                    op0 = cmd.operands[0].value
                    op1 = cmd.operands[1].value
                    self.subs_restriction({'B.NE.0':op0, 'B.NE.1':op1})
                elif cmd.name == 'ADD':
                    op0 = cmd.operands[0].value
                    op1 = cmd.operands[1].value
                    op2 = cmd.operands[2].value
                    self.subs_restriction(op0, op1 + op2)
                elif cmd.name == 'SUB':
                    op0 = cmd.operands[0].value
                    op1 = cmd.operands[1].value
                    op2 = cmd.operands[2].value
                    self.subs_restriction(op0, op1 - op2)
            cond, block_endea = cur_block.refs_to_it[0]
            cur_block = self.dcodeblocks.get(block_endea)
        self.simplify_restriction()
        return self.C, self.SP_C

    def __str__(self, w=80):
        result = '  ' + '_'*(w) + '\n'
        result += ' / ' + '%08x: '%self.startea + '%-*s'%(w-12, self.name) + '/\n'
        result += '/_' + '_'*(w - 2) + '/\n'
        
        result += '| Refs to me: ' + ' '*(w-15) + '|\n'
        if self.refs_to_it:
            for ref in self.refs_to_it:
                 result += '| [%-4s] %08x ->'%(print_insn_mnem(ref), ref) + ' '*(w - 21) + '|\n'
            result += '|' + '-'*(w - 2) + '|\n'

        if self.stack:
            result += '| Stack Members:  ' + ('_'*43).center(w - 1)[18:] + '|\n'
            for i in self.stack.print_table_generator():
                result += '|' + i.center(w - 2) + '|\n'

            result += '|' + '-'*(w - 2) + '|\n'
            result += '| Stak visual:' + ' '*(w-15) + '|\n'
            for i in self.stack.print_list_generator():
                result += '|' + i.center(w - 2) + '|\n'

            result += '|' + '-'*(w - 2) + '|\n'
        result += '| Code Blocks:' + ' '*(w-15) + '|\n'
        for block in self.codeblocks:
            result += block.__str__('| ', ' |', w - 6)
        result += '|' + '_'*(w - 2) + '|\n'
        result += '\\' + ' '*(w - 1) + '\\\n'
        result += ' \\' + '_'*(w - 1) + '\\\n'
        return result

    def __repr__(self):
        return self.__str__()
