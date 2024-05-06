from validator import valid_txn, dsha256

def merkle_root(tx_hashes):
    if len(tx_hashes) == 0:
        return None
    elif len(tx_hashes) == 1:
        return tx_hashes[0]

    new_tx_hashes = []
    for i in range(0, len(tx_hashes), 2):
        if i < len(tx_hashes) - 1:
            message = tx_hashes[i] + tx_hashes[i + 1]
            new_tx_hashes.append(dsha256(message))
            
        else:
            message = tx_hashes[i] + tx_hashes[i]
            new_tx_hashes.append(dsha256(message))

    # print(new_tx_hashes)
    return merkle_root(new_tx_hashes)

def gen_blk_hash(b_version, prev_b_hash, b_merkle_root, time_hex, bits, nonce):
    nonce_hex = nonce.to_bytes(4, byteorder='little').hex()
    block_header = b_version + prev_b_hash + b_merkle_root + time_hex + bits + nonce_hex
    block_hash = dsha256(block_header)

    blk_hash_little = bytes.fromhex(block_hash)[::-1].hex()

    return blk_hash_little

total_wu = 0
total_fee = 0
# for transaction, fee, fee_wu, wu, txid, wtxid in valid_txn:
#     total += wu

# print(total)

sorted_valid_txn = sorted(valid_txn, key=lambda x: x[2], reverse=True)

high_fee_txn = []
wtxids = []
wtxids.append("00"*32)
txids = []

for i in range(len(sorted_valid_txn)):
    transaction, fee, fee_wu, wu, txid, wtxid = sorted_valid_txn[i]
    if total_wu + wu < 3999430:
        total_wu += wu
        total_fee += fee
        high_fee_txn.append(sorted_valid_txn[i])
        if len(wtxid) > 0:
            wtxids.append(wtxid)

        txids.append(txid)
    else:
        break

wtn_root_hash = merkle_root(wtxids)
temp = wtn_root_hash + "00" * 32
wtn_commitment = dsha256(temp)

#coinbase transaction
# 132 * 4 + 36 = 564
version = "01000000"
inputs = "01" + "00" * 32 + "ffffffff" + "00" + "00000000"
witness = "01" + "20" + "00" * 32
# total_fee += 312545559
# print(total_fee)
total_fee_hex = total_fee.to_bytes(8, byteorder='little').hex()
outputs = "02" + total_fee_hex + "19" + "76a914cb4f45b4ecfe54b25106a919237cf34ce193c1b988ac" + "0000000000000000" + "26" + "6a24" + "aa21a9ed" + wtn_commitment
locktime = "00000000"

coinbase_txn = version + inputs + outputs + locktime
coinbase_txid = dsha256(coinbase_txn)

txids.insert(0, coinbase_txid)

# block 
b_version = "20800000"
prev_b_hash = "0000aeff00000000000000000000000000000000000000000000000000000000"
b_merkle_root = merkle_root(txids)
time = 1714938506
time_hex = time.to_bytes(4, byteorder='little').hex()
bits = "1f00ffff"

target = "0000ffff00000000000000000000000000000000000000000000000000000000"
target_decimal = int(target, 16)

nonce = 0
flag = 0

while nonce < 4294967296:
    blk_hash_little = gen_blk_hash(b_version, prev_b_hash, b_merkle_root, time_hex, bits, nonce)
    blk_hash_little_dec = int(blk_hash_little, 16)

    if blk_hash_little_dec < target_decimal:
        # print(nonce)
        flag =1 
        # print(blk_hash_little)
        break

    nonce += 1
    
if flag == 0:
    print('no nonce found')

nonce_hex = nonce.to_bytes(4, byteorder='little').hex()
block_header = b_version + prev_b_hash + b_merkle_root + time_hex + bits + nonce_hex
ser_coin_txn = version + "0001" + inputs + outputs + witness + locktime

with open('output.txt', 'w') as file:
    file.write(block_header + '\n')
    file.write(ser_coin_txn + '\n')
    for txid in txids:
        txid_rev = bytes.fromhex(txid)[::-1].hex()
        file.write(txid_rev + '\n')
    