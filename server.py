# All requirements are part of the standard library

import time

# networking iface
import socket

# For handling arguments
import argparse
import json

# For logging, error handling and other threading
import logging
import threading
import traceback
import sys

# For CRC and SHA-256
import hashlib
import zlib

hex_val = lambda x: hex(x)[2:]

class ServerLogger:
    
    # TODO: Add hex-ing ability to threads... with datatype input
    
    def __init__(self, name, delay=0, formatting=None, level=logging.INFO) -> None:
        # name: logger name, logfile is called <name>.log
        # delay: delay to write to log file
        # formatting: specifies the format to print things into the logger, by default it applies str() on all the inputs
        #             useful if all outputs to a logger will be a mix of hex, hex_val (hex without the 0x), int and a mix of types
        #             a formmatting=[hex, hex_val, str] will make the input 25, 26, 27 print as "0x19\n1a\n27\n"
        # level: specifies what level the logger should log at, default at info
        
        self.handler = logging.FileHandler(name + ".log")
    
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level) # log events at level=level
        self.logger.addHandler(self.handler)
        
        self.delay = delay
        
        self.default_level = level
        
        self.formatter = formatting
        
    def async_log(self, data, level=logging.INFO) -> None:
        # threaded call to log
        
        t = threading.Thread(target=self.log, 
                             args = (data, level),
            )
        
        t.start()
        
    def log(self, data, level=None):
        
        if level==None: level=self.default_level
        
        time.sleep(self.delay)
        
        log_function = self.logger.info
        
        # change log function based on chosen level, if level not specified, use default_level
        if level==logging.INFO:
            log_function = self.logger.info
        elif level==logging.DEBUG: 
            log_function = self.logger.debug
        elif level==logging.ERROR:
            log_function = self.logger.error
        else:
            self.logger.exception("Logger.log() unsupported argument for type")
            
        if self.formatter==None:
            # If no formatter defined, force output to all be of type string
            log_function(
                "\n".join([str(i) for i in data]) + "\n"
            )
        else:
            # If no formatter defined, apply formatting function
            # e.g. hex_val converts int to hex without 0x at beginning
            log_function(
                "\n".join([self.formatter[i](data[i]) for i in range(len(data))]) + "\n"
            )
        
    def exception(self, type, value, tb):
        
        self.logger.exception(''.join(traceback.format_exception(type, value, tb)))
        
    def __call__(self, *args, **kwds) -> None:
        # shorthand. calling the object like a function makes it log using a thread.
        return self.async_log(*args, **kwds)
    
    # These two classes define the truthiness of a Logger such that a NoLogger() is False
    def __bool__(self):
        return True
    
    def __nonzero__(self):
        return True

class NoLogger(ServerLogger):

    def __init__(self) -> None:
        pass
    
    def async_log(self, *args, **kwds):
        pass
    
    def log(self, *args, **kwds):
        pass
    
    
    # These two classes define the truthiness of a Logger such that a NoLogger() is False
    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

class Key():
    # an object that stores a public_key, exponent pair
        
    def __init__(self, public_key, exponent) -> None:

        self.public_key = public_key
        self.exponent = exponent

class Server():
    # the main server with all the processing helper functions. 
    # the function run() lets the server start accepting packets.
    
    
    ## INIT FUNCTIONS
    
    def __init__(self, hostname, port, keys, bins, verification_logger, checksum_logger, error_logger=NoLogger(), debug_logger=NoLogger(), bufsize=1024) -> None:
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bufsize = bufsize
        
        self.hostname = hostname
        self.port = port
        
        self.verification_logger = verification_logger
        self.checksum_logger     = checksum_logger
        self.error_logger        = error_logger
        self.debug_logger        = debug_logger
        
        self.bins = self.build_binary_dict(bins)
        self.keys, self.chksums = self.build_keys_dict(keys)
        
        if error_logger:
            sys.excepthook = error_logger.exception
        
        # self.chksums maps a seq_num to a list[ (int) chksum value, (bool) checked, (bool) used to generate next in seq ]
        # that way we can handle misordered packets efficiently
        
    def build_binary_dict(self, binfiles):
        # Given {packet_id -> file path ...}
        # returns
        #         {packet_id -> binary file data}
        
        bins = {}
        
        for binary, filepath in binfiles.items():
            
            with open(filepath, mode='rb') as file: 
                
                bins[int(binary[2:], 16)] = file.read()
        
        return bins 
        
    def build_keys_dict(self, keyfiles):
        # Given {packet_id -> binary key file path ...}
        # returns
        #        keys: dict from packet_id to Key(public_key, exponent)
        #     chksums: dict from packet_id to dict of packet checksums
        
        chksums = {}
        keys = {}
        
        for id, filepath in keyfiles.items():
            
            id = int(id[2:], 16)
            data = None
            
            with open(filepath, mode='rb') as file: 
                data = file.read().hex()
                
            # dumping key.bin, F4 (0x010001) is in the beginning
            # so that's probably the exponent. Rest is public_key
            keys[id] = Key(exponent=int(data[:6], 16), public_key=int(data[6:], 16))
            chksums[id] = {0: [0, True, False]}
            
        return keys, chksums
        
    ## RUNTIME FUNCTIONS
        
    def run(self):
        
        self.socket.bind((self.hostname, self.port))
        
        while True:
            
            if self.error_logger:
            
                try:
                    
                    self.recieve_packet()
                    
                except Exception as e:
                    
                    self.error_logger.exception(*sys.exc_info())
                    
            else:
                
                self.recieve_packet()
                
    def recieve_packet(self):
                
        # TODO: if you want to add filtering based on addresses/map addresses to 
        #       id's, this can happen here
        
        data, address = self.socket.recvfrom(self.bufsize)
        
        self.validate_packet(data)
            
    def validate_packet(self, data):
        
        packet = data.hex()
        
        # decode packet structure
        # (4 bytes) pkt id | (4 bytes) pkt seq num | (2 bytes) xor_key | (2 bytes) # of chksum | (? bytes) DWORDS^xor_key |  (64 bytes) signature
        
        id      = int(packet[ : 8], 16) # 4 byte packet id
        seq_num = int(packet[8:16], 16) # 4 byte packet seq num
        
        # 2 byte XOR key repeated to get a size of 4 bytes
        key = int(packet[16:20]+packet[16:20], 16)
        
        # 2 bytes num of chksums
        num_chksum = int(packet[20:24], 16)
        
        # last 64 bytes are the RSA signature
        signature = int(packet[-128:], 16)
        
        chksum = self.chksums[id]
        
        seq_ptr = seq_num
        
        # xor'd DWORDS start at idx 24, use this as a sliding window for chksum verification
        # move a window size of 8 and apply our 8 bit key
        for chksum_idx in range(24, 24 + 8*num_chksum, 8):
            
            chksum, seq_ptr = self.calc_checksum(seq_ptr, chksum, id)
            
            self.chksums[id] = chksum
            
            xor_packet = int(packet[chksum_idx:chksum_idx+8], 16) ^ key
            
            # tell the current seq_ptr that it was used and that the previous seq_ptr it is no longer needed
            try:
                chksum[seq_ptr][2] = True
                chksum[seq_ptr-1][1] = True
            except: pass
                
            if chksum[seq_ptr][0] != xor_packet:
                
                self.checksum_logger((id, seq_num, seq_ptr-1, xor_packet, chksum[seq_ptr][0]))
            
            # if the current or previous seq pointers were used for testing and generating the next pointer, then 
            # remove it from memory
            try:
                if chksum[seq_ptr][1] and chksum[seq_ptr][2]:
                    del chksum[seq_ptr]
                if chksum[seq_ptr-1][1] and chksum[seq_ptr-1][2]:
                    del chksum[seq_ptr-1]
            except: pass

        # Spawn process that checks sha-256
        t = threading.Thread(target=self.check_hash, 
                             args = (id, seq_num, data, signature, ),
            )
        
        t.start()
        
            
    def check_hash(self, id, seq_num, data, signature):
        
        local_hash = (hashlib.sha256(data[0:len(data)-64])).hexdigest()

        public_key = self.keys[id].public_key
        exponent = self.keys[id].exponent
        
        hash = hex(pow(signature, exponent, public_key))[63:]

        if hash != local_hash:
            self.verification_logger((id, seq_num, hash, local_hash))
            
    def calc_checksum(self, seq_num, chksum, id):
        
        # seq_num = (seq_num + 1) % 0xFFFFFFFF
        seq_num += 1
        
        # if not already computed (due to shuffling)
        if seq_num not in chksum:
            
            # if previous seq_num computed (if not then packet misordered)
            if seq_num-1 in chksum: # or (0xFFFFFFFF + seq_num) - 1
                
                # calculate next checksum
                chksum[seq_num] = [((zlib.crc32(self.bins[id], chksum[seq_num-1][0]) & 0xFFFFFFFF)), False, False]
            
            else:
                
                # calculate all checksums until current one, caching them...
                m = 0
                for i in chksum.keys():
                    if i > m and i < seq_num+1:
                        m = i
                
                for x in range(m+1, seq_num+1):
                    chksum[x] = [((zlib.crc32(self.bins[id], chksum[x-1][0]) & 0xFFFFFFFF)), False, False]
        
        return chksum, seq_num

if __name__ == "__main__":        
    
    # Parser Arguments
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--hostname", help="hostname", type=str, default="127.0.0.1", dest="hostname")
    
    parser.add_argument("-p", "--port", help="port to receive packets on", type=int, default=1337, dest="port")
    
    parser.add_argument("-k", "--keys", help="a dictionary of {packet_id: key_file_path} mappings", type=str, default="localhost", dest="keys")
    
    parser.add_argument("-b", "--binaries", help="a dictionary of {packet_id: binary_path} mappings", type=str, default="localhost", dest="binaries")
    
    parser.add_argument("-d", "--delay", help="delay (in seconds) for writing to log file", type=int, default=0, dest="delay")
    
    parser.add_argument("--bufsize", help="size of the buffer to recieve packets in", type=int, default=1024, dest="bufsize")
    
    args = parser.parse_args()
    
    # Convert dict args from str to dict
    args.keys = json.loads( args.keys )
    args.binaries = json.loads( args.binaries )
    
    # Setup Loggers
    verification_logger = ServerLogger("verification_failures", delay=args.delay, formatting=[hex, str, str, str])
    checksum_logger     = ServerLogger("checksum_failures",     delay=args.delay, formatting=[hex, str, str, hex_val, hex_val])
    
    error_logger        = ServerLogger("errors",                delay=args.delay, level=logging.ERROR)
    debug_logger        = ServerLogger("debug",                 delay=args.delay, level=logging.DEBUG)
    
    # Setup server
    server = Server(args.hostname, args.port, args.keys, args.binaries,
                    verification_logger=verification_logger,
                    checksum_logger=checksum_logger,
                    error_logger=error_logger,
                    debug_logger=debug_logger,
                    bufsize=args.bufsize)
    
    # Launch server
    server.run()
                

# run this using
# python server.py --keys '{"0x42": "key.bin"}' --binaries '{"0x42": "cat.jpg"}' -d '0' -p '1337'