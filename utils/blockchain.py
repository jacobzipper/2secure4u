import bcrypt
from Crypto.Cipher import AES
from Crypto import Random

START_HASH = bcrypt.hashpw("2SECURE4UPROTOCOL", bcrypt.gensalt())
DATA_PAD = 64

class Block:
    def __init__(self, data):
        self.prev = None
        self.next = None
        self.data = data

class TFSUBlock(Block):
    def __init__(self, prevhash, data, dhscrypt = None, dhsdec = None):
        data = data + (chr(1) * (DATA_PAD - len(data)))
        self.dhsdec = dhsdec
        curhash = self.newHash(prevhash, data)
        encdat = self.encData(data, dhscrypt)
        dat = (curhash, encdat) # Hash, encrypted data
        Block.__init__(self, dat)

    def __str__(self):
        if (self.dhsdec == None):
            return str(self.data[1])
        else:
            return str(self.dhsdec.decrypt(self.data[1]))

    def newHash(self, prevhash, data):
        return bcrypt.hashpw(prevhash + data, bcrypt.gensalt())

    def encData(self, data, dhscrypt):
        if dhscrypt == None: # Not encrypted
            return data
        else:
            return dhscrypt.encrypt(data)

class Blockchain:
    def __init__(self, dhs = None):
        self.head = None
        self.tail = None
        self.size = 0
        if dhs == None:
            self.dhscrypt = None
            self.dhsdec = None
        else:
            key = str(bytearray.fromhex('{:0192x}'.format(dhs)))
            if len(key) > 32:
                key = key[:32]
            else:
                key.zfill(32)
            iv = Random.new().read(AES.block_size)
            self.dhscrypt = AES.new(key, AES.MODE_CBC, iv)
            self.dhsdec = AES.new(key, AES.MODE_CBC, iv)

    def __str__(self):
        ret = [None] * self.size
        cur = self.head
        for i in xrange(self.size):
            ret[i] = str(cur)
            cur = cur.next
        return '->'.join(ret)


    def add(self, data):
        if self.head == None:
            new_node = TFSUBlock(START_HASH, data, self.dhscrypt, self.dhsdec)
            self.head = self.tail = new_node
        else:
            new_node = TFSUBlock(self.tail.data[0], data, self.dhscrypt, self.dhsdec)
            new_node.prev = self.tail
            new_node.next = None
            self.tail.next = new_node
            self.tail = new_node
        self.size += 1

    def popHead(self):
        ret = self.head
        if ret == None:
            return ret
        elif self.tail == ret:
            self.head = None
            self.tail = None
            self.size -= 1
            return ret
        self.head = ret.next
        self.head.prev = None
        self.size -= 1
        return ret

    def popTail(self):
        ret = self.tail
        if ret == None:
            return ret
        elif self.head == ret:
            self.head = None
            self.tail = None
            self.size -= 1
            return ret
        self.tail = ret.prev
        self.tail.next = None
        self.size -= 1
        return ret
