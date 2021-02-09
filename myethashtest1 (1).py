#!/usr/bin/python3

import sys
from collections import OrderedDict
from eth_typing import Hash32
from eth_utils import big_endian_to_int

import rlp
from Crypto.Hash import keccak
from rlp.sedes import BigEndianInt, big_endian_int, Binary, binary
from rlp import encode
from eth_utils import to_bytes, to_hex
from web3 import IPCProvider, Web3


_BYTES = 4                        # bytes in word 
DATASET_BYTES_INIT = 2**30        # bytes in dataset at genesis 
DATASET_BYTES_GROWTH = 2**23      # dataset growth per epoch 
CACHE_BYTES_INIT = 2**24          # bytes in cache at genesis 
CACHE_BYTES_GROWTH = 2**17        # cache growth per epoch 
CACHE_MULTIPLIER=1024             # Size of the DAG relative to the cache 
EPOCH_LENGTH = 30000              # blocks per epoch 
MIX_BYTES = 128                   # width of mix 
HASH_BYTES = 64                   # hash length in bytes 
DATASET_PARENTS = 256             # number of parents of each dataset element 
CACHE_ROUNDS = 3                  # number of rounds in cache production 
ACCESSES = 64                     # number of accesses in hashimoto loop


address = Binary.fixed_length(20, allow_empty=True)
hash32 = Binary.fixed_length(32)
uint256 = BigEndianInt(256)
trie_root = Binary.fixed_length(32, allow_empty=True)

class MiningBlockHeader(rlp.Serializable):
    fields = [
        ('parent_hash', hash32),
        ('uncles_hash', hash32),
        ('coinbase', address),
        ('state_root', trie_root),
        ('transaction_root', trie_root),
        ('receipt_root', trie_root),
        ('bloom', uint256),
        ('difficulty', big_endian_int),
        ('block_number', big_endian_int),
        ('gas_limit', big_endian_int),
        ('gas_used', big_endian_int),
        ('timestamp', big_endian_int),
        ('extra_data', binary),
        #('mix_hash', binary), we have removed these 2 fields because we want a mining block header only
        #('nonce', Binary(8, allow_empty=True)
    ]

provider = Web3.IPCProvider('/home/chronic/TMP_Stuff/geth.ipc')
w3 = Web3(provider)
print(w3.isConnected())

blockNumber = int(sys.argv[1], 10)

myHeader = MiningBlockHeader(
    parent_hash = to_bytes(int(w3.eth.getBlock(blockNumber).parentHash.hex(), 16)),
    uncles_hash = to_bytes(int(w3.eth.getBlock(blockNumber).sha3Uncles.hex(), 16)),
    coinbase = to_bytes(int(w3.eth.getBlock(blockNumber).miner, 16)),
    state_root = to_bytes(int(w3.eth.getBlock(blockNumber).stateRoot.hex(), 16)),
    transaction_root = to_bytes(int(w3.eth.getBlock(blockNumber).transactionsRoot.hex(), 16)),
    receipt_root = to_bytes(int(w3.eth.getBlock(blockNumber).receiptsRoot.hex(), 16)),
    bloom = int(w3.eth.getBlock(blockNumber).logsBloom.hex(), 16),
    difficulty = w3.eth.getBlock(blockNumber).difficulty,
    block_number = w3.eth.getBlock(blockNumber).number,
    gas_limit = w3.eth.getBlock(blockNumber).gasLimit,
    gas_used = w3.eth.getBlock(blockNumber).gasUsed,
    timestamp = w3.eth.getBlock(blockNumber).timestamp,
    extra_data = to_bytes(int(w3.eth.getBlock(blockNumber).extraData.hex(), 16)),
    #mix_hash = to_bytes(int(w3.eth.getBlock(blockNumber).mixHash.hex(), 16)),
    #nonce = to_bytes(int(w3.eth.getBlock(blockNumber).nonce.hex(), 16)),
)

from pyethash import hashimoto_light, mkcache_bytes

# Type annotation here is to ensure we don't accidentally use strings instead of bytes.
cache_by_epoch: 'OrderedDict[int, bytearray]' = OrderedDict() #here we cache by epoch order
CACHE_MAX_ITEMS = 10 #and limit the items to 10

def get_cache(block_number: int) -> bytes:
        epoch_index = block_number // EPOCH_LENGTH #this is where we get the block number
        # Get the cache if already generated, marking it as recently used
        if epoch_index in cache_by_epoch:
            c = cache_by_epoch.pop(epoch_index)  # pop and append at end
            cache_by_epoch[epoch_index] = c
            return c
    # Generate the cache if it was not already in memory
    # Simulate requesting mkcache by block number: multiply index by epoch length
        c = mkcache_bytes(epoch_index * EPOCH_LENGTH)
        cache_by_epoch[epoch_index] = c #stores the cash bytes generated
        return c
    # Limit memory usage for cache
        if len(cache_by_epoch) > CACHE_MAX_ITEMS: #this is related to the lenght 
            cache_by_epoch.popitem(last=False)  # remove last recently accessed
            #ref line88
            return c
#now we will write the check proof of work funtion. We need here to check if the data of the blocks is according to the requirements
def check_pow(block_number: int,
              mining_hash: Hash32,
              mix_hash: Hash32,
              nonce: bytes,
              difficulty: int) -> None:
        cache = get_cache(block_number) #we get cache by block number
                
        mining_output = hashimoto_light(block_number, 
                                        cache, 
                                        mining_hash, 
                                        big_endian_to_int(nonce)) # MISTAKE not int_to_big_endian but the other way around
           
        #big_endian_to_int(nonce)
        #int_to_big_endian(nonce)) #this is the hashimoto light mining output. It takes block_number, cache, mining_hash, int_to_big_endian(nonce) and hash it

        print("MIX Digest: ", mining_output[b'mix digest'])
        print("MIX HASH:   ", w3.eth.getBlock(block_number).mixHash.hex())

        print("RESULT:    ", mining_output[b'result'])
        print("CONDITION: ", (2**256) // difficulty)

        if mining_output[b'mix digest'] != mining_hash: #this is to say that if the mining digest is not equal to the mix hash, then...
            return False 
        elif int_to_big_endian(mining_output[b'result']) <= (2**256 // difficulty): #to convert the result int integer and check if it meets the condition of being less or equal to 2^256 divided by the difficulty
            return False
        else:
            return True #if it returns true, then all good! We could do more checks but this is enough for now. For additional checks see here https://github.com/ethereum/py-evm/blob/d553bd405bbf41a1da0c227a614baba7b43e9449/eth/consensus/pow.py

#the next section's objective is tomake sure that data is formated correctly and make sure we can get the proper hash and that the data is accurately fromated

block_number = blockNumber
myHash = "0x" + keccak.new(data=rlp.encode(myHeader), digest_bits=256).hexdigest()
mining_hash = to_bytes(int(myHash, 16))

mix_hash = to_bytes(int(w3.eth.getBlock(block_number).mixHash.hex(), 16))

nonce = to_bytes(int(w3.eth.getBlock(block_number).nonce.hex(), 16))

difficulty = myHeader.difficulty

check_pow(block_number, mining_hash, mix_hash, nonce, difficulty)
