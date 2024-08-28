import base64
from Crypto.Cipher import ARC4
import hashlib
import os
import struct

def printb(bytea):
    if type(bytea) == str:
        bytea = str.encode(bytea)
    elif type(bytea) == int:
        bytea = bytes(bytea)
    s = bytea.hex().upper()
    print(' '.join([s[i:i+2] for i in range(0, len(s), 2)]))

ROS_PLATFORM_KEY_PC = "C4pWJwWIKGUxcHd69eGl2AOwH2zrmzZAoQeHfQFcMelybd32QFw9s10px6k0o75XZeB5YsI9Q9TdeuRgdbvKsxc="
ROS_PLATFORM_KEY_PS3 = "C4AaRpadRR2hApFvyl6fJDHShJIa/K76qSPt+2wTcox6C4Yn2X82ubbT79Rg/Ci2bTedR/1PzOaYMWM0TLT82m0="

ROS_PLATFORMS = {
    'pc': ROS_PLATFORM_KEY_PC,
    'ps3': ROS_PLATFORM_KEY_PS3
}

def swap_endian(d):
    return struct.pack('<I', struct.unpack('>I', d)[0])

class rosEncryptorResult():
    def __init__(self, result: bytes):
        self.result = result

    def string(self, ignore_errors: bool = False) -> str:
        return self.result.decode("utf-8", errors = ("ignore" if ignore_errors else ""))
    
    def bytes(self) -> bytes:
        return self.result
    
    def __str__(self):
        try:
            string = self.result.decode("utf-8")
            return string
        except:
            s = self.result.hex().upper()
            return ' '.join([s[i:i+2] for i in range(0, len(s), 2)])
            

class rosEncryptor():
    def __init__(self, platform: str):
        self.platform = platform
        if not platform in ROS_PLATFORMS:
            raise Exception("No such platform: %s!" % (platform))

        self.platform_key = base64.b64decode(ROS_PLATFORMS[platform])

        self.rc4_key = self.platform_key[1:1+len(bytearray(32))]                    #bytearray(32)
        self.xor_key_encrypted = self.platform_key[33:33+len(bytearray(16))]        #bytearray(16)
        self.hash_key_encrypted = self.platform_key[49:49+len(bytearray(16))]       #bytearray(16)

        self.rc4 = ARC4.new(bytes(self.rc4_key))
        self.xor_key = self.rc4.encrypt(bytes(self.xor_key_encrypted))
        self.hash_key = self.rc4.encrypt(bytes(self.hash_key_encrypted))

        self.session_key = None

    def set_sessionkey_base64(self, sessionKey: str):
        self.session_key = base64.b64decode(sessionKey)
    
    def set_sessionkey(self, sessionKey: bytearray):
        self.session_key = sessionKey
    
    def set_sessionkey_insecure(self):
        self.session_key = bytearray([int(str.encode(x), 16) for x in [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' ]])
    
    def remove_sessionkey(self, sessionKey: bytearray):
        self.session_key = None
    
    def decrypt_cl(self, data: bytes, has_security: bool = False) -> rosEncryptorResult:
        rc4_key = bytearray(16)

        for i in range(len(rc4_key)):
            rc4_key[i] = self.xor_key[i]  
            rc4_key[i] ^= data[i]

            if has_security:
                rc4_key[i] ^= self.session_key[i]

        rc4 = ARC4.new(bytes(rc4_key))

        decoded = bytearray(len(data) - 16 - 20) # data size - rc4 key size - sha1 size at the end
        decoded = rc4.encrypt(data[16:16+len(decoded)])

        return rosEncryptorResult(decoded)
    
    def decrypt_sv(self, data: bytes, has_security: bool = False) -> rosEncryptorResult:
        rc4_key = bytearray(16)

        for i in range(len(rc4_key)):
            rc4_key[i] = data[i] ^ self.xor_key[i]

            if has_security:
                rc4_key[i] ^= self.session_key[i]

        rc4 = ARC4.new(bytes(rc4_key))

        blockSizeData = data[16:20]
        blockSize = rc4.encrypt(blockSizeData)

        # Swap endianess, turn into int and add SHA1 size = each block size
        blockSize = int.from_bytes(swap_endian(blockSize), 'little') + 20 
        
        result = bytearray()
        start = 20

        while start < len(data):
            
            end = min(len(data), start + blockSize) # calculate the end of this block

            # yes, i do not care about sha1 hash checking. i am not rockstar

            end -= 20 # remove the size of the SHA1 hash from the end

            thisLen = end - start

            if thisLen < 0:
                break

            result.extend(rc4.encrypt(data[start: start + thisLen])) # decrypt block and add to result

            start += blockSize

        return rosEncryptorResult(result)
    
    def encrypt_cl(self, data: str, has_security: bool = False):
        buff = bytearray()

        rc4_key = bytearray(os.urandom(16))

        rc4 = ARC4.new(bytes(rc4_key))

        for i in range(len(rc4_key)):
            rc4_key[i] ^= self.xor_key[i]  

            if has_security:
                rc4_key[i] ^= self.session_key[i]

        buff.extend(rc4_key)

        data = str.encode(data)

        data = rc4.encrypt(data)

        buff.extend(data)

        sha1 = hashlib.sha1()
        sha1.update(buff)
        sha1.update(self.hash_key)

        buff.extend(sha1.digest())

        return buff
    
    def encrypt_sv(self, data: str, has_security: bool = False):
        buff = bytearray()
    
        rc4_key = bytearray(os.urandom(16))
    
        rc4 = ARC4.new(bytes(rc4_key))
    
        for i in range(len(rc4_key)):
            rc4_key[i] ^= self.xor_key[i]  
    
            if has_security:
                rc4_key[i] ^= self.session_key[i]
    
        buff.extend(rc4_key)
        
        blockSize = 1024
    
        blockSizeData = struct.pack('<I', blockSize)
        blockSizeData = swap_endian(blockSizeData)
        blockSizeData = rc4.encrypt(blockSizeData)
    
        buff.extend(blockSizeData)
    
        data = str.encode(data)
    
        done = 0
    
        while (done < len(data)):
            remaining = len(data) - done
            thisSize = min(remaining, blockSize)
    
            inData = data[done: done + thisSize]
    
            done += thisSize
    
            inData = rc4.encrypt(inData)
    
            if has_security:
                pass #hmac
            else:
                sha1 = hashlib.sha1()
                sha1.update(inData)
                sha1.update(self.hash_key)
    
                outHash = sha1.digest()
    
            buff.extend(inData)
            buff.extend(outHash)
    
        if has_security:
            pass #hmac
        
        return buff

#
#encryptor = rosEncryptor('pc')
#encryptor.set_sessionkey_base64('GlD00Bvn0rU+7OErX5iN2A==')
#in_file = open("paths\\prod.ros.rockstargames.com\\http\\cloud\\11\\cloudservices\\titles\\gta5\\pcros\\0x1a098062.json\\responsebody", "rb")
#data = in_file.read()
#in_file.close()
#print(encryptor.decrypt_sv(data, True))
