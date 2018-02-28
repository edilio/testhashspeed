#!/usr/bin/env python

import hashlib, struct, time, sys, timeit

import coinhash

from construct import *


def main():
    global ntime
    ntime = int(time.time())

    timestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    nonce = 0
    pubkey = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    value = 5000000000

    input_script = create_input_script(timestamp)
    output_script = create_output_script(pubkey)
    # hash merkle root is the double sha256 hash of the transaction(s)
    tx = create_transaction(input_script, output_script, value)
    global hash_merkle_root
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    global block_header1
    block_header1 = create_block_header(hash_merkle_root, ntime, 0x1e0ffff0, nonce)

    global block_header2
    block_header2 = create_block_header(hash_merkle_root, ntime, 0x1d00ffff, nonce)

    print(timeit.timeit("hash1()", number=100000, setup="from __main__ import hash1"))
    print(timeit.timeit("hash2()", number=100000, setup="from __main__ import hash2"))


def hash1():
    generate_hashes_from_block(block_header1)


def hash2():
    generate_hashes_from_block(block_header2)


def create_input_script(psz_timestamp):
    psz_prefix = ""
    # use OP_PUSHDATA1 if required
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'

    script_prefix = '04ffff001d0104' + psz_prefix + chr(len(psz_timestamp)).encode('hex')
    print (script_prefix + psz_timestamp.encode('hex'))
    return (script_prefix + psz_timestamp.encode('hex')).decode('hex')


def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return (script_len + pubkey + OP_CHECKSIG).decode('hex')


def create_transaction(input_script, output_script, value):
    transaction = Struct("transaction",
                         Bytes("version", 4),
                         Byte("num_inputs"),
                         StaticField("prev_output", 32),
                         UBInt32('prev_out_idx'),
                         Byte('input_script_len'),
                         Bytes('input_script', len(input_script)),
                         UBInt32('sequence'),
                         Byte('num_outputs'),
                         Bytes('out_value', 8),
                         Byte('output_script_len'),
                         Bytes('output_script', 0x43),
                         UBInt32('locktime'))

    tx = transaction.parse('\x00' * (127 + len(input_script)))
    tx.version = struct.pack('<I', 1)
    tx.num_inputs = 1
    tx.prev_output = struct.pack('<qqqq', 0, 0, 0, 0)
    tx.prev_out_idx = 0xFFFFFFFF
    tx.input_script_len = len(input_script)
    tx.input_script = input_script
    tx.sequence = 0xFFFFFFFF
    tx.num_outputs = 1
    tx.out_value = struct.pack('<q', value)  # 0x000005f5e100)#012a05f200) #50 coins
    tx.output_script_len = 0x43
    tx.output_script = output_script
    tx.locktime = 0
    return transaction.build(tx)


def create_block_header(hash_merkle_root, time, bits, nonce):
    block_header = Struct("block_header",
                          Bytes("version", 4),
                          Bytes("hash_prev_block", 32),
                          Bytes("hash_merkle_root", 32),
                          Bytes("time", 4),
                          Bytes("bits", 4),
                          Bytes("nonce", 4))

    genesisblock = block_header.parse('\x00' * 80)
    genesisblock.version = struct.pack('<I', 1)
    genesisblock.hash_prev_block = struct.pack('<qqqq', 0, 0, 0, 0)
    genesisblock.hash_merkle_root = hash_merkle_root
    genesisblock.time = struct.pack('<I', time)
    genesisblock.bits = struct.pack('<I', bits)
    genesisblock.nonce = struct.pack('<I', nonce)
    return block_header.build(genesisblock)


def generate_hashes_from_block(data_block):
    header_hash = coinhash.NeoscryptHash(data_block)[::-1]
    return header_hash


if __name__ == "__main__":
    main()


