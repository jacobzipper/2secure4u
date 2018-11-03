from blockchain import Blockchain

BLOCK_SIZE = 64

def fileToBlockchain(f, dhs = None): # f is the filename, dhs is the diffie hellman secret (default none)
    fBytes = open(f, 'rb')
    fBlockchain = Blockchain(dhs)
    cur = fBytes.read(64)
    while True:
        fBlockchain.add(cur)
        cur = fBytes.read(64)
        if len(cur) == 0:
            break
    return fBlockchain

def fileToBlockchainStream(f, dhs = None): # f is the filename, dhs is the diffie hellman secret (default none)
    fBytes = open(f, 'rb')
    fBlockchain = Blockchain(dhs)
    cur = fBytes.read(64)
    while True:
        fBlockchain.add(cur)
        if fBlockchain.size > 1:
            yield fBlockchain.popHead()
        cur = fBytes.read(64)
        if len(cur) == 0:
            yield fBlockchain.popHead()
            break
