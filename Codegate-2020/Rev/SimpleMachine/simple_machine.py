#!/usr/bin/python3

class VM():
    def __init__(self, binary):
        self.memory = binary.ljust(0x10000, b'\0')
        self.begin = 0
        self.end = 0x10000
        self.end2 = 0x10000
        self.enable = 1
        self.caches = [0 for i in range(3)]
        self.pc = 0
        self.pre_opcode = 0
        self.passing1 = 0
        self.mode1 = 0
        self.mode2 = 0
        self.cacheIdx1 = 0
        self.rawdata1 = 0
        self.rawdata2 = 0
        self.fetchOK = 0
        self.opcode = 0
        self.passing2 = 0
        self.cacheIdx2 = 0
        self.data1 = 0
        self.data2 = 0
        self.prepareOK = 0
        self.passing3 = 0
        self.cacheIdx3 = 0
        self.result = 0
        self.executeOK = 0
    
    def writeMem(self, data, where, debug=False):
        for i, c in enumerate(data):
            self.memory = self.memory[:where+i] + bytes([c]) + self.memory[where+i+1:]
        if debug == True:
            print('@@ Debug: writeMem')
            print('memory[{}] : {}'.format(where, self.memory[where:where+len(data)]))
        return(len(data)+1)
    
    def getRev2b(self, where, debug=False):
        if debug == True:
            print('@@ Debug: getRev2b')
            print('memory[{}] : {}'.format(where, int.from_bytes(self.memory[where:where+2], byteorder='little')))
            print('memory[{}] : {}'.format(where, self.memory[where-2:where+8]))
        return int.from_bytes(self.memory[where:where+2], byteorder='little')
    
    def fetchCmd(self):
        v1 = self.getRev2b(self.pc)
        self.pre_opcode = v1 & 0x7f
        self.passing1 = (v1 >> 7) & 7
        self.mode1 = (v1 >> 10) & 7
        self.mode2 = (v1 >> 13) & 7
        self.cacheIdx1 = self.getRev2b(self.pc+2)
        self.rawdata1 = self.getRev2b(self.pc+4)
        self.rawdata2 = self.getRev2b(self.pc+6)
        self.fetchOK = 1
        self.pc += 8
        
    def prepareCmd(self):
        v1 = self.executeOK
        v2 = self.mode1
        v3 = 0
        Label_8 = False
        Label_12 = False
        Label_14 = False
        Label_15 = False
        Label_23 = False
        if v1 != 0 and self.passing3 == v2 and self.cacheIdx3 == self.rawdata1:
            self.data1 = self.result
            v3 = self.mode2
            Label_15 = True
        if Label_15 == False:
            if v2 == 2:
                self.data1 = self.getRev2b(self.rawdata1)
            else:
                if v2 == 1:
                    v3 = self.mode2
                    self.data1 = self.rawdata1
                    if v1 == 0:
                        Label_8 = True
                    else:
                        Label_14 = True
                if Label_8 == False and Label_14 == False:
                    if v2 != 0:
                        Label_23 = True
                    else:
                        self.data1 = self.caches[self.rawdata1]
            if Label_8 == False and Label_14 == False and Label_23 == False:
                v3 = self.mode2
                if v1 == 0:
                    Label_8 = True
        if Label_8 == False and Label_15 == False and Label_23 == False:
            v2 = self.passing3
        if Label_8 == False and Label_23 == False:
            if v3 == v2 and self.cacheIdx3 == self.rawdata2:
                self.data2 = self.result
                Label_12 = True
        if Label_12 == False and Label_23 == False:
            if v3 == 2:
                self.data2 = self.getRev2b(self.rawdata2)
                Label_12 = True
        if Label_12 == False and Label_23 == False:
            if v3 == 1:
                self.data2 = self.rawdata2
                Label_12 = True
        if Label_12 == False and (v3 != 0 or Label_23 == True):
            print('GG at prepare stage')
            exit(-1)
        if Label_12 == False:
            self.data2 = self.caches[self.rawdata2]
        self.prepareOK = 1
        self.opcode = self.pre_opcode
        self.passing2 = self.passing1
        self.cacheIdx2 = self.cacheIdx1
        
    def executeCmd(self):
        v1 = self.opcode
        if v1 == 0:
            print('data1: {:#x}'.format(self.data1))
            print('mov result, data1')
            print('')
            self.result = self.data1
        elif v1 == 1:
            print('data1: {:#x}'.format(self.data1))
            print('data2: {:#x}'.format(self.data2))
            print('add result, data1, data2')
            print('')
            self.result = (self.data1 + self.data2) & 0xffff
        elif v1 == 2:
            print('data1: {:#x}'.format(self.data1))
            print('data2: {:#x}'.format(self.data2))
            print('mul result, data1, data2')
            print('')
            self.result = (self.data1 * self.data2) & 0xffff
        elif v1 == 3:
            print('data1: {:#x}'.format(self.data1))
            print('data2: {:#x}'.format(self.data2))
            print('xor result, data1, data2')
            print('')
            self.result = (self.data1 ^ self.data2) & 0xffff
        elif v1 == 4:
            print('data1: {:#x}'.format(self.data1))
            print('data2: {:#x}'.format(self.data2))
            print('cmp result, data1, data2')
            print('')
            if self.data1 < self.data2:
                self.result = 1
            else:
                self.result = 0
        elif v1 == 5 and self.data1 != 0:
            print('data2: {:#x}'.format(self.data2))
            print('jmp data2')
            print('')
            self.fetchOK = 0
            self.prepareOK = 0
            self.executeOK = 0
            self.pc = self.data2
            return
        elif v1 == 6:
            print('data1: {:#x}'.format(self.data1))
            print('data2: {:#x}'.format(self.data2))
            print('input')
            print('')
            i = input('input>').encode()
            if len(i) > self.data2:
                i = i[:data2]
            self.result = self.writeMem(i, self.data1)
        elif v1 == 7:
            print('data1: {:#x}'.format(self.data1))
            print('data2: {:#x}'.format(self.data2))
            print('output')
            output = self.memory[self.data1:self.data1+self.data2]
            print('output: {}'.format(output))
            print('')
            self.result = self.data2
        elif v1 == 8:
            print('exit')
            self.fetchOK = 0
            self.prepareOK = 0
            self.executeOK = 0
            self.enable = 0
            return
        self.executeOK = 1
        self.passing3 = self.passing2
        self.cacheIdx3 = self.cacheIdx2
    
    def finallyCmd(self):
        if self.executeOK != 0:
            v1 = self.passing3
            if v1 == 2:
                print('cacheIdx3: {:#x}'.format(self.cacheIdx3))
                print('result: {:#x}'.format(self.result))
                print('write')
                print('')
                self.memory = self.memory[:self.begin + self.cacheIdx3] + bytes([self.result&0xff, (self.result&0xff00)>>8]) + self.memory[self.begin + self.cacheIdx3 + 2:]
            elif v1 != 0:
                print('GG at finally stage')
                exit(-1)
            else:
                v2 = self.cacheIdx3
                if v2 != -1 and v2 != 0xffff:
                    self.caches[v2] = self.result
                
    def info(self):
        print('begin: {}'.format(self.begin))
        print('end: {:#x}'.format(self.end))
        print('end2: {:#x}'.format(self.end2))
        print('enable: {}'.format(self.enable))
        print('caches: {}'.format(self.caches))
        print('pc: {:#x}'.format(self.pc))
        print('pre_opcode: {}'.format(self.pre_opcode))
        print('passing1: {}'.format(self.passing1))
        print('mode1: {}'.format(self.mode1))
        print('mode2: {}'.format(self.mode2))
        print('cacheIdx1: {:#x}'.format(self.cacheIdx1))
        print('rawdata1: {:#x}'.format(self.rawdata1))
        print('rawdata2: {:#x}'.format(self.rawdata2))
        print('fetchOK: {}'.format(self.fetchOK))
        print('opcode: {}'.format(self.opcode))
        print('passing2: {}'.format(self.passing2))
        print('cacheIdx2: {}'.format(self.cacheIdx2))
        print('data1: {:#x}'.format(self.data1))
        print('data2: {:#x}'.format(self.data2))
        print('prepareOK: {}'.format(self.prepareOK))
        print('passing3: {}'.format(self.passing3))
        print('cacheIdx3: {:#x}'.format(self.cacheIdx3))
        print('result: {:#x}'.format(self.result))
        print('executeOK: {}'.format(self.executeOK))
    
    def debug(self):
        print('@@ Debug: debug')
        print('memory[{:#x}]: {}'.format(0x4000, self.memory[0x4000:0x4008]))
    
    def run(self):
        round = 0
        while self.enable == 1:
            print('round {} =========='.format(round))
            round += 1
            # self.info()
            # self.debug()
            self.finallyCmd()
            if self.prepareOK == 1:
                self.executeCmd()
            if self.fetchOK == 1:
                self.prepareCmd()
            self.fetchCmd()

with open('./target', 'rb') as binary:
    vm = VM(binary.read())
    vm.run()
    
    