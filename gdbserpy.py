#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 29 22:51:57 2020

@author: zonyzhao
"""

import sys
import socket
import logging
import struct

GDB_SIGNAL_TRAP = 5

def checksum(data):
    checksum = 0
    for c in data:
        checksum += ord(c)
    return checksum & 0xff

cm33_1 = '$m<?xml version="1.0"?>\n<!-- Copyright (C) 2008 Free Software Foundation, Inc.\n\n     Copying and distribution of this file, with or without modification,\n     are permitted in any medium without royalty provided the copyright\n     notice and this notice are preserved.  -->\n\n<!DOCTYPE feature SYSTEM "gdb-target.dtd">\n<target version="1.0">\n  <architecture>arm</architecture>\n  <feature name="org.gnu.gdb.arm.m-profile">\n    <reg name="r0" bitsize="32" regnum="0" type="uint32" group="general"/>\n    <reg name="r1" bitsize="32" regnum="1" type="uint32" group="general"/>\n    <reg name="r2" bitsize="32" regnum="2" type="uint32" group="general"/>\n    <reg name="r3" bitsize="32" regnum="3" type="uint32" group="general"/>\n    <reg name="r4" bitsize="32" regnum="4" type="uint32" group="general"/>\n    <reg name="r5" bitsize="32" regnum="5" type="uint32" group="general"/>\n    <reg name="r6" bitsize="32" regnum="6" type="uint32" group="general"/>\n    <reg name="r7" bitsize="32" regnum="7" type="uint32" group="general"/>\n    <reg name="r8" bitsize="32" regnum="8" type="uint32" group="general"/>\n    <reg name="r9" bitsize="32" regnum="9" type="uint32" group="general"/>\n    <reg name="r10" bitsize="32" regnum="10" type="uint32" group="general"/>\n    <reg name="r11" bitsize="32" regnum="11" type="uint32" group="general"/>\n    <reg name="r12" bitsize="32" regnum="12" type="uint32" group="general"/>\n    <reg name="sp" bitsize="32" regnum="13" type="data_ptr" group="general"/>\n    <reg name="lr" bitsize="32" regnum="14" type="uint32" group="general"/>\n    <reg name="pc" bitsize="32" regnum="15" type="code_ptr" group="general"/>\n    <reg name="xpsr" bitsize="32" regnum="25" type="uint32" group="general"/>\n  </feature>\n  <feature name="org.gnu.gdb.arm.m-system">\n    <reg name="msp" bitsize="32" regnum="26" type="uint32" group="general"/>\n    <reg name="psp" bitsize="32" regnum="27" type="uint32" group="general"/>\n    <reg name="primask" bitsize="32" regnum="28" type="uint32" group="general"/>\n    <reg name="basepri" bitsize="32" regnum="29" type="uint32" group="general"/>\n    <reg name="faultmask" bitsize="32" regnum="30" type="uint32" group="general"/>\n    <reg name="control" bitsize="32" regnum="31" type="uint32" group="general"/>\n  </feature>\n  <feature name="org.gnu.gdb.arm.m-float">\n    <reg name="fpscr" bitsize="32" regnum="32" type="uint32" group="float"/>\n    <reg name="s0" bitsize="32" regnum="33" type="float" group="float"/>\n    <reg name="s1" bitsize="32" regnum="34" type="float" group="float"/>\n    <reg name="s2" bitsize="32" regnum="35" type="float" group="float"/>\n    <reg name="s3" bitsize="32" regnum="36" type="float" group="float"/>\n    <reg name="s4" bitsize="32" regnum="37" type="float" group="float"/>\n    <reg name="s5" bitsize="32" regnum="38" type="float" group="float"/>\n    <reg name="s6" bitsize="32" regnum="39" type="float" group="float"/>\n    <reg name="s7" bitsize="32" regnum="40" type="float" group="float"/>\n    <reg name="s8" bitsize="32" regnum="41" type="float" group="float"/>\n    <reg name="s9" bitsize="32" regnum="42" type="float" group="float"/>\n    <reg name="s10" bitsize="32" regnum="43" type="float" group="float"/>\n    <reg name="s11" bitsize="32" regnum="44" type="float" group="float"/>\n    <reg name="s12" bitsize="32" regnum="45" type="float" group="float"/>\n    <reg name="s13" bitsize="32" regnum="46" type="float" group="float"/>\n    <reg name="s14" bitsize="32" regnum="47" type="float" group="float"/>\n    <reg name="s15" bitsize="32" regnum="48" type="float" group="float"/>\n    <reg name="s16" bitsize="32" regnum="49" type="float" group="float"/>\n    <reg name="s17" bitsize="32" regnum="50" type="float" group="float"/>\n    <reg name="s18" bitsize="32" regnum="51" type="float" group="float"/>\n    <reg name="s19" bitsize="32" regnum="52" type="float" group="float"/>\n    <reg name="s20" bitsize="32" regnum="53" type="float" group="float"/>\n    <reg name="s21" bitsize="32" regnum="54" type="float" group="float"/>\n    <reg name="s22" bitsize="32" regnum="55" type="float" group="float"/>\n    <re#52'
cm33_2 = '$lg name="s23" bitsize="32" regnum="56" type="float" group="float"/>\n    <reg name="s24" bitsize="32" regnum="57" type="float" group="float"/>\n    <reg name="s25" bitsize="32" regnum="58" type="float" group="float"/>\n    <reg name="s26" bitsize="32" regnum="59" type="float" group="float"/>\n    <reg name="s27" bitsize="32" regnum="60" type="float" group="float"/>\n    <reg name="s28" bitsize="32" regnum="61" type="float" group="float"/>\n    <reg name="s29" bitsize="32" regnum="62" type="float" group="float"/>\n    <reg name="s30" bitsize="32" regnum="63" type="float" group="float"/>\n    <reg name="s31" bitsize="32" regnum="64" type="float" group="float"/>\n  </feature>\n</target>\n\n#97'
# Code a bit inspired from http://mspgcc.cvs.sourceforge.net/viewvc/mspgcc/msp430simu/gdbserver.py?revision=1.3&content-type=text%2Fplain
class GDBClientHandler(object):
    def __init__(self, clientsocket):
        self.clientsocket = clientsocket
        self.netin = clientsocket.makefile('r')
        self.netout = clientsocket.makefile('w')
        self.log = logging.getLogger('gdbclienthandler')
        self.last_pkt = None

    def close(self):
        '''End of story!'''
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()
        self.log.info('closed')

    def run(self):
        '''Some doc about the available commands here:
            * http://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html#id3081722
            * http://git.qemu.org/?p=qemu.git;a=blob_plain;f=gdbstub.c;h=2b7f22b2d2b8c70af89954294fa069ebf23a5c54;hb=HEAD +
             http://git.qemu.org/?p=qemu.git;a=blob_plain;f=target-i386/gdbstub.c;hb=HEAD'''
        self.log.info('client loop ready...')
        while self.receive() == 'Good':
            pkt = self.last_pkt
            self.log.debug('receive(%r)' % pkt)
            # Each packet should be acknowledged with a single character. '+' to indicate satisfactory receipt
            self.send_raw('+')

            def handle_q(subcmd):
                '''
                subcmd Supported: https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#qSupported
                Report the features supported by the RSP server. As a minimum, just the packet size can be reported.
                '''
                if subcmd.startswith('Supported'):
                    self.log.info('Received qSupported command')
                    self.send('PacketSize=4000;qXfer:memory-map:read-;QStartNoAckMode+;hwbreak+;qXfer:features:read+')
                elif subcmd.startswith('Attached'):
                    self.log.info('Received qAttached command')
                    # https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html
                    self.send('0')
                elif subcmd.startswith('C'):
                    #self.send('T%.2x;' % GetCpuThreadId())
                    self.send('T%.2x;' % 12345)
                elif subcmd.startswith('StartNoAckMode'):
                    self.send('OK')
                elif subcmd.startswith('Xfer'):
                    if 'xml:0' in subcmd:
                        self.send_raw(cm33_1)
                    elif 'xml:fef' in subcmd:
                        self.send_raw(cm33_2)
                elif subcmd.startswith('fThreadInfo'):
                    self.send('m0000dead')
                elif subcmd.startswith('sThreadInfo'):
                    self.send('l')
                else:
                    self.log.error('This subcommand %r is not implemented in q' % subcmd)
                    self.send('')

            def handle_h(subcmd):
                self.send('OK')

            def handle_qmark(subcmd):
                self.send('S%.2x' % GDB_SIGNAL_TRAP)

            def handle_g(subcmd):
                if subcmd == '':
                    # EAX, ECX, EDX, ESP, EBP, ESI, EDI, EIP, EFLAGS, CS, SS, DS, ES, FS, GS
                    # registers = [
                    #     GetEax(), GetEcx(), GetEdx(), GetEbx(), GetEsp(),
                    #     GetEbp(), GetEsi(), GetEdi(), GetEip(), GetEflags(),
                    #     GetCs(), GetSs(), GetDs(), GetEs(), GetFs(), GetGs()
                    # ]
                    s = '0000000000a1022088de012000000000020000000002000000a1022000000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a518bd0220406a0120277c0100f608020000000061'
                    self.send(s)
                else:
                    self.send(struct.pack('<I', 1234).hex())

            def handle_m(subcmd):
                addr, size = subcmd.split(',')
                addr = int(addr, 16)
                size = int(size, 16)
                self.log.info('Received a "read memory" command (@%#.8x : %d bytes)' % (addr, size))
                #self.send(ReadMemory(size, addr).encode('hex'))
                self.send(size*'12')

            def handle_s(subcmd):
                self.log.info('Received a "single step" command')
                StepInto()
                self.send('T%.2x' % GDB_SIGNAL_TRAP)

            def handle_v(subcmd):
                self.log.info('Received a "v" command: %s'%subcmd)
                self.send('')
                
                
            dispatchers = {
                'q' : handle_q,
                'Q' : handle_q,
                'H' : handle_h,
                '?' : handle_qmark,
                'g' : handle_g,
                'm' : handle_m,
                's' : handle_s,
                'v' : handle_v
            }

            cmd, subcmd = pkt[0], pkt[1 :]
            print(pkt)
            if cmd == 'k':
                break

            if cmd not in dispatchers:
                self.log.info('%r command not handled' % pkt)
                self.send('')
                continue
            
            print('***************')
            print(cmd, subcmd)
            dispatchers[cmd](subcmd)

        self.close()

    def receive(self):
        '''Receive a packet from a GDB client'''
        # XXX: handle the escaping stuff '}' & (n^0x20)
        csum = 0
        state = 'Finding SOP'
        packet = ''
        while True:
            c = self.netin.read(1)
            if c == '\x03':
                return 'Error: CTRL+C'
            
            if len(c) != 1:
                return 'Error: EOF'

            if state == 'Finding SOP':
                if c == '$':
                    state = 'Finding EOP'
            elif state == 'Finding EOP':
                if c == '#':
                    if csum != int(self.netin.read(2), 16):
                        raise Exception('invalid checksum')
                    self.last_pkt = packet
                    return 'Good'
                else:
                    packet += c
                    csum = (csum + ord(c)) & 0xff               
            else:
                raise Exception('should not be here')

    def send(self, msg):
        '''Send a packet to the GDB client'''
        self.log.debug('send(%r)' % msg)
        self.send_raw('$%s#%.2x' % (msg, checksum(msg)))

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()     

def main():
    logging.basicConfig(level = logging.DEBUG)
    for logger in 'gdbclienthandler runner main'.split(' '):
        logging.getLogger(logger).setLevel(level = logging.INFO)

    log = logging.getLogger('main')
    port = 31337
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    log.info('listening on :%d' % port)
    sock.listen(1)
    conn, addr = sock.accept()
    log.info('connected')
    
    try:
        GDBClientHandler(conn).run()
    except Exception() as e:
        print(e)
        sock.close()
    return 1

if __name__ == '__main__':
    main()