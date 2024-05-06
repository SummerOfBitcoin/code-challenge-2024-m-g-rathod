from load_data import json_data_list
import re
import hashlib
import ecdsa
from ecdsa.util import sigdecode_der
import base58
import bech32
from Crypto.Hash import RIPEMD160

cnt = 0
new_opcodes = set()
t = []
txn_p2sh_wpkh = set()
txn_p2sh_wsh = set()

temp = set()
txn_p2pkh =set()
txn_p2wpkh = set()
txn_p2sh = set()
txn_p2wsh = set()
txn_p2tr = set()
invalid_txn = set()
valid_txn = []

mismatch_pkh_transaction = []
invalid_sign_txn = []
invalid_wallet_addr_txn = []
mismatch_wpkh_transaction = []

new_sighash_types = set()
diff_sighash_txn = set()

opcodes = {
    "OP_0": "00",
    "OP_NOP": "61",
    "OP_VERIFY": "69",
    "OP_RETURN": "6a",
    "OP_IFDUP": "73",
    "OP_DROP": "75",
    "OP_DUP": "76",
    "OP_2DROP": "6d",
    "OP_2DUP": "6e",
    "OP_3DUP": "6f",
    "OP_SIZE": "82",
    "OP_AND": "84",
    "OP_OR": "85",
    "OP_XOR": "86",
    "OP_EQUAL": "87",
    "OP_EQUALVERIFY": "88",
    "OP_RIPEMD160": "a6",
    "OP_SHA256": "a8",
    "OP_HASH160": "a9",
    "OP_HASH256": "aa",
    "OP_CHECKSIG": "ac",
    "OP_CHECKSIGVERIFY": "ad",
    "OP_CHECKMULTISIG": "ae",
    "OP_CHECKMULTISIGVERIFY": "af",   
    "OP_2": "52",
    "OP_3": "53",
    "OP_4": "54",
    "OP_5": "55",
    "OP_6": "56",
    "OP_7": "57",
    "OP_8": "58",
    "OP_9": "59",
    "OP_10": "5a",
    "OP_11": "5b",
    "OP_12": "5c",
    "OP_13": "5d",
    "OP_14": "5e",
    "OP_15": "5f",
    "OP_16": "60",
    "OP_PUSHNUM_1": "51",
    "OP_PUSHNUM_2": "52",
    "OP_PUSHNUM_3": "53",
    "OP_PUSHNUM_4": "54",
    "OP_PUSHNUM_5": "55",
    "OP_PUSHNUM_6": "56",
    "OP_PUSHNUM_7": "57",
    "OP_PUSHNUM_8": "58",
    "OP_PUSHNUM_9": "59",
    "OP_PUSHNUM_10": "5a",
    "OP_PUSHNUM_11": "5b",
    "OP_PUSHNUM_12": "5c",
    "OP_PUSHNUM_13": "5d",
    "OP_PUSHNUM_14": "5e",
    "OP_PUSHNUM_15": "5f",
    "OP_PUSHNUM_16": "60",
    "OP_PUSHBYTES_1": "01",
    "OP_PUSHBYTES_2": "02",
    "OP_PUSHBYTES_3": "03",
    "OP_PUSHBYTES_4": "04",
    "OP_PUSHBYTES_20": "14",
    "OP_PUSHBYTES_22": "16",
    "OP_PUSHBYTES_31": "1f",
    "OP_PUSHBYTES_32": "20",
    "OP_PUSHBYTES_33": "21",
    "OP_PUSHBYTES_34": "22",
    "OP_PUSHBYTES_65": "41",
    "OP_PUSHBYTES_70": "46",
    "OP_PUSHBYTES_71": "47",
    "OP_PUSHBYTES_72": "48",
    "OP_PUSHBYTES_73": "49",
    "OP_PUSHBYTES_74": "4a",
    "OP_PUSHBYTES_75": "4b",
    "OP_PUSHDATA1": "4c",
    "OP_PUSHDATA2": "4d",
    "OP_PUSHDATA4": "4e",
    "OP_IF": "63",
    "OP_NOTIF": "64",
    "OP_ELSE": "67",
    "OP_ENDIF": "68",
    "OP_SWAP": "7c",
    "OP_CLTV": "b1",
    "OP_CSV": "b2",
    "OP_GREATERTHAN": "a0"

}

def dsha256(message):
    byte_value = bytes.fromhex(message)
    first_hash = hashlib.sha256(byte_value).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    return second_hash.hex()

def ripemd160(message):
    bytes_data = bytes.fromhex(message)
    h = RIPEMD160.new(bytes_data)
    return h.hexdigest()

def sha256(hex_string):
    byte_string = bytes.fromhex(hex_string)
    sha256_hash = hashlib.sha256(byte_string).hexdigest()
    return sha256_hash

def verify_signature(public_key_hex, transaction_hash_hex, signature_der_hex):
    # Convert the public key, transaction hash, and signature to binary
    public_key = bytes.fromhex(public_key_hex)
    transaction_hash = bytes.fromhex(transaction_hash_hex)
    signature_der = bytes.fromhex(signature_der_hex)

    # Create a verification key object
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)

    # Verify the signature
    return vk.verify_digest(signature=signature_der, digest=transaction_hash, sigdecode=sigdecode_der)

def gen_legacy_mssg(transaction, current_input, sighash):
    '''
        message = 
        version[4bytes little_endian] + 
        input_count[compact_size] + 
        inputs (txn_id[little_endian] + txn_index[4bytes little_endian] + scriptsigsize[compact_size] + 
                scriptsig[scriptpubkey] + sequence[4bytes little_endian]) + 
        output_count[compact_size] + 
        outputs (amount[8bytes little_endian] + scriptpubkey_size[compact_size] + scriptpubkey) + 
        locktime[4bytes little_endian] + 
        sighash[4bytes little_endian]
    '''
    curr_ip_list = []
    curr_ip_list.append(current_input)
    message = ""

    version = transaction['version']
    hex_version = version.to_bytes(4, byteorder='little').hex()
    message += hex_version

    temp_list = None
    if sighash == "01000000":
        temp_list = transaction['vin']
    elif sighash == "81000000":
        temp_list = curr_ip_list

    ip_count = len(temp_list)
    hex_ip_count = ""
    if ip_count <= 252:
        hex_ip_count += ip_count.to_bytes(1, byteorder='little').hex()
    elif 253 <= ip_count <= 65535:
        hex_ip_count += "fd"
        hex_ip_count += ip_count.to_bytes(2, byteorder='little').hex()
    elif 65536 <= ip_count <= 4294967295:
        hex_ip_count += "fe"
        hex_ip_count += ip_count.to_bytes(4, byteorder='little').hex()
    else:
        hex_ip_count += "ff"
        hex_ip_count += ip_count.to_bytes(8, byteorder='little').hex()
    message += hex_ip_count

    for ip in temp_list:
        txn_id = ip['txid']
        le_txid_bytes = bytes.fromhex(txn_id)[::-1]
        le_txid_hex = le_txid_bytes.hex()
        message += le_txid_hex

        vout = ip['vout']
        vout_hex = vout.to_bytes(4, byteorder='little').hex()
        message += vout_hex

        scriptsig = ''

        if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
            l1 = ip['scriptsig_asm'].split(' ')
            scriptsig = l1[len(l1) - 1]
        else:
            scriptsig = ip['prevout']['scriptpubkey']

        scriptsigsize = len(scriptsig) // 2
        scriptsigsize_hex = ""
        if scriptsigsize <= 252:
            scriptsigsize_hex += scriptsigsize.to_bytes(1, byteorder='little').hex()
        elif 253 <= scriptsigsize <= 65535:
            scriptsigsize_hex += "fd"
            scriptsigsize_hex += scriptsigsize.to_bytes(2, byteorder='little').hex()
        elif 65536 <= scriptsigsize <= 4294967295:
            scriptsigsize_hex += "fe"
            scriptsigsize_hex += scriptsigsize.to_bytes(4, byteorder='little').hex()
        else:
            scriptsigsize_hex += "ff"
            scriptsigsize_hex += scriptsigsize.to_bytes(8, byteorder='little').hex()
        message += scriptsigsize_hex

        message += scriptsig

        sequence = ip['sequence']
        sequence_hex = sequence.to_bytes(4, byteorder='little').hex()
        message += sequence_hex

    op_count = len(transaction['vout'])
    hex_op_count = ""
    if op_count <= 252:
        hex_op_count += op_count.to_bytes(1, byteorder='little').hex()
    elif 253 <= op_count <= 65535:
        hex_op_count += "fd"
        hex_op_count += op_count.to_bytes(2, byteorder='little').hex()
    elif 65536 <= op_count <= 4294967295:
        hex_op_count += "fe"
        hex_op_count += op_count.to_bytes(4, byteorder='little').hex()
    else:
        hex_op_count += "ff"
        hex_op_count += op_count.to_bytes(8, byteorder='little').hex()
    message += hex_op_count

    for op in transaction['vout']:
        amount = op['value']
        amount_hex = amount.to_bytes(8, byteorder='little').hex()
        message += amount_hex

        scriptpubkeysize = len(op['scriptpubkey']) // 2
        scriptpubkeysize_hex = ""
        if scriptpubkeysize <= 252:
            scriptpubkeysize_hex += scriptpubkeysize.to_bytes(1, byteorder='little').hex()
        elif 253 <= scriptpubkeysize <= 65535:
            scriptpubkeysize_hex += "fd"
            scriptpubkeysize_hex += scriptpubkeysize.to_bytes(2, byteorder='little').hex()
        elif 65536 <= scriptpubkeysize <= 4294967295:
            scriptpubkeysize_hex += "fe"
            scriptpubkeysize_hex += scriptpubkeysize.to_bytes(4, byteorder='little').hex()
        else:
            scriptpubkeysize_hex += "ff"
            scriptpubkeysize_hex += scriptpubkeysize.to_bytes(8, byteorder='little').hex()
        message += scriptpubkeysize_hex

        message += op['scriptpubkey']

    locktime = transaction['locktime']
    locktime_hex = locktime.to_bytes(4, byteorder='little').hex()
    message += locktime_hex

    message += sighash
    
    txn_hash = dsha256(message)
    return txn_hash

def gen_segwit_mssg(transaction, curr_input, sighash, segwit_message, ip_index):
    '''
        preimage =  version + 
                    hash256(inputs) [inputs = txid1 + vout1 + txid2 + vout2 + ........] + 
                    hash256(sequences) + 
                    input [curr_txid + curr_ip_vout] + 
                    scriptcode + 
                    amount [ 8-byte little endian ] + 
                    sequence [curr_ip_sequence] + 
                    hash256(outputs) [amount1 + scriptpubkeysize1 + scriptpubkey1 + .........] + 
                    loctime [4-byte little endian] + 
                    sighash_type

    '''
    if segwit_message == {} or sighash != segwit_message['sighash']:
        segwit_message['sighash'] = sighash
        
        hex_version = transaction['version'].to_bytes(4, byteorder='little').hex()
        segwit_message['version'] = hex_version

        if sighash == "81000000" or sighash == "83000000" or sighash == "82000000":
            segwit_message['hashed_inputs'] = "00" * 32
            segwit_message['hashed_seqs'] = "00" * 32

        else:
            serialized_ip = ""
            serialized_seqs = ""
            
            for ip in transaction['vin']:

                txn_id = ip['txid']
                le_txid_bytes = bytes.fromhex(txn_id)[::-1]
                le_txid_hex = le_txid_bytes.hex()
                vout_hex = ip['vout'].to_bytes(4, byteorder='little').hex()
                serialized_ip += le_txid_hex + vout_hex

                seq = ip['sequence']
                seq_hex = seq.to_bytes(4, byteorder='little').hex()
                serialized_seqs += seq_hex

            segwit_message['hashed_inputs'] = dsha256(serialized_ip)
            segwit_message['hashed_seqs'] = dsha256(serialized_seqs)

        op_list = []

        if sighash == "82000000":
            segwit_message['hashed_ops'] = "00" * 32
        elif sighash == "83000000":
            if len(transaction['vin']) <= len(transaction['vout']):
                op_list.append(transaction['vout'][ip_index])
        else:
            op_list = transaction['vout']

        serialized_ops = ""
        if len(op_list) > 0:
            for op in op_list:
                amount = op['value']
                amount_hex = amount.to_bytes(8, byteorder='little').hex()
                serialized_ops += amount_hex

                scriptpubkeysize = len(op['scriptpubkey']) // 2
                scriptpubkeysize_hex = ""
                if scriptpubkeysize <= 252:
                    scriptpubkeysize_hex += scriptpubkeysize.to_bytes(1, byteorder='little').hex()
                elif 253 <= scriptpubkeysize <= 65535:
                    scriptpubkeysize_hex += "fd"
                    scriptpubkeysize_hex += scriptpubkeysize.to_bytes(2, byteorder='little').hex()
                elif 65536 <= scriptpubkeysize <= 4294967295:
                    scriptpubkeysize_hex += "fe"
                    scriptpubkeysize_hex += scriptpubkeysize.to_bytes(4, byteorder='little').hex()
                else:
                    scriptpubkeysize_hex += "ff"
                    scriptpubkeysize_hex += scriptpubkeysize.to_bytes(8, byteorder='little').hex()
                serialized_ops += scriptpubkeysize_hex

                serialized_ops += op['scriptpubkey']

        if sighash != "83000000" and sighash != "82000000":
            segwit_message['hashed_ops'] = dsha256(serialized_ops)
        elif sighash == "83000000":
            if len(transaction['vin']) > len(transaction['vout']):
                segwit_message['hashed_ops'] = "00" * 32
            else:
                segwit_message['hashed_ops'] = dsha256(serialized_ops)

        locktime = transaction['locktime']          
        locktime_hex = locktime.to_bytes(4, byteorder='little').hex()
        segwit_message['locktime'] = locktime_hex

    message = ""             

    message += segwit_message['version'] + segwit_message['hashed_inputs'] + segwit_message['hashed_seqs']

    txn_id = curr_input['txid']
    le_txid_bytes = bytes.fromhex(txn_id)[::-1]
    le_txid_hex = le_txid_bytes.hex()
    vout_hex = curr_input['vout'].to_bytes(4, byteorder='little').hex()

    message += le_txid_hex + vout_hex

    scriptcode = ""
    # scriptcode

    # if p2wpkh
    if curr_input['prevout']['scriptpubkey_type'].find('p2wpkh') != -1:
        scriptpubkey_asm_list = curr_input['prevout']['scriptpubkey_asm'].split(' ')
        scriptcode += "1976a914"
        scriptcode += scriptpubkey_asm_list[2]
        scriptcode += "88ac"
    
    
    if curr_input['prevout']['scriptpubkey_type'].find('p2sh') != -1:
        redeem_script_list = curr_input['inner_redeemscript_asm'].split(' ')

        # if p2wpkh nested in p2sh
        if len(redeem_script_list[len(redeem_script_list) - 1]) == 40:
            scriptcode += "1976a914"
            scriptcode += redeem_script_list[2]
            scriptcode += "88ac"

        #if p2wsh nested in p2sh
    if (curr_input['prevout']['scriptpubkey_type'].find('p2sh') != -1 and len(redeem_script_list[len(redeem_script_list) - 1]) == 64) or curr_input['prevout']['scriptpubkey_type'].find('p2wsh') != -1:
        ser_redeem_script = curr_input['witness'][len(curr_input['witness']) - 1]
        ser_red_script_size = len(ser_redeem_script) // 2
        if ser_red_script_size <= 252:
            scriptcode += ser_red_script_size.to_bytes(1, byteorder='little').hex()
        elif 253 <= ser_red_script_size <= 65535:
            scriptcode += "fd"
            scriptcode += ser_red_script_size.to_bytes(2, byteorder='little').hex()
        elif 65536 <= ser_red_script_size <= 4294967295:
            scriptcode += "fe"
            scriptcode += ser_red_script_size.to_bytes(4, byteorder='little').hex()
        else:
            scriptcode += "ff"
            scriptcode += ser_red_script_size.to_bytes(8, byteorder='little').hex()

        scriptcode += ser_redeem_script

    message += scriptcode

    amt = curr_input['prevout']['value']
    amt_hex = amt.to_bytes(8, byteorder='little').hex()
    message += amt_hex

    sequence = curr_input['sequence']
    seq_hex = sequence.to_bytes(4, byteorder='little').hex()
    message += seq_hex

    message += segwit_message['hashed_ops']

    message += segwit_message['locktime']

    message += sighash
    
    return dsha256(message)

def validate_script(script_list, stack, transaction, filename, ip):
    ptr = 0
    ctr_if = 0
    ctr = 0
    transaction_hash = None
    last_sighash_type = None
    while ptr < len(script_list):
        item = script_list[ptr]
        if item.find('OP') != -1:

            # if item.find('OP_CSV') != -1:
            #     txn_p2wsh.add(filename)                        

            if item.find('PUSHNUM') != -1:
                l = re.findall(r'\d+', item)
                number = int(l[0]) if l else None
                number_hex = number.to_bytes(1, byteorder='big').hex()
                stack.append(number_hex)

            elif item.find('PUSHBYTES') != -1:
                ptr += 1
                continue
                        
            else:

                if item == "OP_DROP" :
                    if len(stack ) <= 0:
                        txn_p2wsh.add((filename, 'op_drop'))
                        return False
                    top = stack.pop()

                elif item == "OP_IF":
                    ctr_if += 1
                    if len(stack) <= 0:
                        txn_p2wsh.add((filename, 'op_if empty stack fault'))
                        return False
                    top = stack.pop()
                    if top == 0:
                                
                        ptr2 = ptr + 1
                        while ptr2 < len(script_list):
                            if script_list[ptr2] == "OP_IF" or script_list[ptr2] == "OP_NOTIF":
                                ctr_if += 1
                                ctr += 1

                            elif script_list[ptr2] == "OP_ELSE":
                                if ctr == 0:
                                    break
                                else:
                                    ctr -= 1

                            elif script_list[ptr2] == "OP_ENDIF":
                                ctr_if -= 1

                            ptr2 += 1

                        ptr = ptr2 + 1
                        continue

                elif item == "OP_NOTIF":
                    ctr_if += 1
                    if len(stack) <= 0:
                        txn_p2wsh.add((filename, 'op_notif empty stack fault'))
                        return False
                    top = stack.pop()
                    if top != 0:
                                
                        ptr2 = ptr + 1
                        while ptr2 < len(script_list):
                            if script_list[ptr2] == "OP_IF" or script_list[ptr2] == "OP_NOTIF":
                                ctr_if += 1
                                ctr += 1

                            elif script_list[ptr2] == "OP_ELSE":
                                if ctr == 0:
                                    break
                                else:
                                    ctr -= 1

                            elif script_list[ptr2] == "OP_ENDIF":
                                ctr_if -= 1

                            ptr2 += 1

                        ptr = ptr2 + 1
                        continue

                elif item == "OP_ELSE":
                    ptr2 = ptr + 1

                    while ptr2 < len(script_list):

                        if script_list[ptr2] == "OP_IF" or script_list[ptr2] == "OP_NOTIF":
                            ctr_if += 1

                        if script_list[ptr2] == "OP_ENDIF":
                            ctr_if -= 1
                            if ctr_if == 0:
                                break

                        ptr2 += 1

                    ptr = ptr2 + 1
                    continue

                elif item == "OP_ENDIF":
                    
                    if ctr_if <= 0:
                        txn_p2wsh.add((filename, 'op_endif less if fault'))
                        return False
                    
                    ctr_if -= 1

                elif item == "OP_SHA256":
                    if len(stack) <= 0:
                        txn_p2wsh.add((filename, 'op_sha256 empty stack fault'))
                        return False
                    top = stack.pop()
                    top_hash = sha256(top)
                    stack.append(top_hash)

                elif item == "OP_SIZE":
                    if len(stack) <= 0:
                        txn_p2wsh.add((filename, 'op_size empty stack fault'))
                        return False
                    top = stack.pop()
                    top_len = len(top)
                    top_len_bytes = top_len // 2
                    stack.append(top)
                    stack.append(hex(top_len_bytes)[2:])

                elif item == "OP_CLTV":
                    if len(stack) == 0:
                        txn_p2wsh.add((filename, 'op_cltv empty stack fault'))
                        return False

                    top = stack.pop()
                    top_decimal = int(top, 16)

                    if top_decimal < 0 or ip['sequence'] == 4294967295:
                        txn_p2wsh.add((filename, 'op_cltv sequence == ffffffff'))
                        return False

                    else:
                        if (transaction['locktime'] < 500000000 and top_decimal < 500000000) or (transaction['locktime'] > 500000000 and top_decimal > 500000000):
                            if top_decimal > transaction['locktime']:
                                txn_p2wsh.add((filename, 'op_cltv stack ele greater than locktime'))
                                return False

                            else:
                                stack.append(top)

                        else:
                            txn_p2wsh.add((filename, 'op_cltv mismatch locktime type fault '))
                            return False
                        
                elif item == "OP_CSV":
                    if len(stack) == 0:
                        txn_p2wsh.add((filename, 'op_csv empty stack fault'))
                        return False

                    top = stack.pop()
                    top_decimal = None

                    if type(top) == str:
                        top_decimal = int(top, 16)
                    elif type(top) == int:
                        top_decimal = top

                    if top_decimal < 0:
                        txn_p2wsh.add((filename, 'op_csv stack ele less than 0 fault'))
                        return False

                    x = top_decimal >> 31
                    bit = x & 1
                    rel = top_decimal >> 21
                    rel_bit = rel & 1

                    if bit == 0:
                        x1 = ip['sequence'] >> 31
                        bit1 = x1 & 1
                        rel2 = ip['sequence'] >> 21
                        seq_bit22 = rel2 & 1

                        if transaction['version'] < 2 or bit1 == 1 or rel_bit != seq_bit22:
                            txn_p2wsh.add((filename, 'op_csv version fault or 32nd bit of txn seq == 1 or 22nd bit mismatch'))
                            return False

                        top_val = top_decimal & (0x0000ffff)
                        seq_val = ip['sequence'] & (0x0000ffff)

                        if top_val > seq_val:
                            txn_p2wsh.add((filename, 'op_csv stack ele greater than seq val'))
                            return False

                    stack.append(top)

                elif item == "OP_CHECKSIGVERIFY":
                    if len(stack) <= 1:
                        txn_p2wsh.add((filename, 'op_checksigver empty stack fault'))
                        return False
                    public_key = stack.pop()
                    sign = stack.pop()

                    sighash = sign[len(sign) - 2:]
                    sighash += "000000"

                    signature_der = sign[:len(sign) - 2]

                    if transaction_hash == None or sighash != last_sighash_type:
                        last_sighash_type = sighash

                        if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1 and 'witness' not in ip: 
                            transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

                        else:
                            transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)

                        # elif ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
                        #     transaction_hash = gen_legacy_mssg(transaction, ip, sighash)
                    try:
                        verify_signature(public_key, transaction_hash, signature_der)
                    except ecdsa.BadSignatureError:
                        txn_p2wsh.add((filename, 'op_checksigverify sign fault'))
                        return False
                    
                elif item == "OP_CHECKSIG":
                    if len(stack) <= 1:
                        txn_p2wsh.add((filename, 'op_checksig empty stack fault'))
                        return False
                    public_key = stack.pop()
                    sign = stack.pop()

                    sighash = sign[len(sign) - 2:]
                    sighash += "000000"

                    signature_der = sign[:len(sign) - 2]

                    if transaction_hash == None or sighash != last_sighash_type:
                        last_sighash_type = sighash
                        # if ip['prevout']['scriptpubkey_type'].find('p2wsh') != -1:
                        if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1 and 'witness' not in ip: 
                            transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

                        else:
                            transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)
                        # elif ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
                        #     transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

                    try:
                        verify_signature(public_key, transaction_hash, signature_der)
                        stack.append(1)
                    except ecdsa.BadSignatureError:
                        stack.append(0)

                elif item == 'OP_CHECKMULTISIG':
                    n = stack.pop()

                    if type(n) == str:
                        n = int(n, 16)

                    temp_n = n
                    public_key_list = []
                    signatures_list = []
                    verified_pubkeys = []

                    while temp_n > 0:
                        public_key_list.append(stack.pop())
                        temp_n -= 1

                    m = stack.pop()

                    if type(m) == str:
                        m = int(m, 16)

                    temp_m = m

                    while temp_m > 0:
                        signatures_list.append(stack.pop())
                        temp_m -= 1

                    for sign in signatures_list:
                        for public_key in public_key_list:

                            if public_key in verified_pubkeys:
                                continue
                            else:
                                sighash = sign[len(sign) - 2:]
                                sighash += "000000"

                                signature_der = sign[:len(sign) - 2]

                                if transaction_hash == None or sighash != last_sighash_type:
                                    last_sighash_type = sighash
                                    # if ip['prevout']['scriptpubkey_type'].find('p2wsh') != -1:
                                    if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1 and 'witness' not in ip: 
                                        transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

                                    else:
                                        transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)

                                    # elif ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
                                    #     transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

                                try:
                                    verify_signature(public_key, transaction_hash, signature_der)
                                    verified_pubkeys.append(public_key)
                                    break
                                except ecdsa.BadSignatureError:
                                    continue
                    
                    if len(verified_pubkeys) >= m:
                        stack.append(1)
                    else:
                        stack.append(0)

                elif item == 'OP_SWAP':
                    if len(stack) <= 1:
                        txn_p2wsh.add((filename, 'op_swap empty stack fault'))
                        return False
                    top1 = stack.pop()
                    top2 = stack.pop()

                    stack.append(top1)
                    stack.append(top2)

                elif item == 'OP_EQUALVERIFY':
                    if len(stack) <= 1:
                        txn_p2wsh.add((filename, 'op_eqver empty stack fault'))
                        return False
                    top1 = stack.pop()
                    top2 = stack.pop()

                    if top1 != top2:
                        txn_p2wsh.add((filename, 'op_eqver ele unequal'))
                        return False

                elif item == 'OP_EQUAL':
                    if len(stack) <= 1:
                        txn_p2wsh.add((filename, 'op_eq empty stack fault'))
                        return False
                    top1 = stack.pop()
                    top2 = stack.pop()

                    if top1 != top2:
                        stack.append(0)
                    else:
                        stack.append(1)

                elif item == 'OP_GREATERTHAN':
                    if len(stack) <= 1:
                        txn_p2wsh.add((filename, 'op_greaterthan empty stack fault'))
                        return False
                    top1 = stack.pop()
                    top2 = stack.pop()

                    if type(top1) == str:
                        top1 = int(top1, 16)

                    if type(top2) == str:
                        top2 = int(top2, 16)

                    if type(top1) == int and type(top2) == int:
                        if top2 > top1:
                            stack.append(1)

                        else:
                            stack.append(0)

                    else:
                        txn_p2wsh.add((filename, 'op_greaterthan stack eles type not int'))
                        return False

                elif item == 'OP_HASH160':
                    if len(stack) <= 0:
                        txn_p2wsh.add((filename, 'op_hash160 empty stack fault'))
                        return False
                    top = stack.pop()

                    sha_top = sha256(top)
                    hash160 = ripemd160(sha_top)
                    stack.append(hash160)

                elif item == 'OP_IFDUP':
                    if len(stack) <= 0:
                        txn_p2wsh.add((filename, 'op_ifdup empty stack fault'))
                        return False
                    top = stack.pop()

                    if top != 0:
                        stack.append(top)
                            
                    stack.append(top)   

                elif item == 'OP_DUP':
                    if len(stack) <= 0:
                        txn_p2wsh.add((filename, 'op_dup empty stack fault'))
                        return False
                    top = stack.pop()
                    stack.append(top)
                    stack.append(top)

                elif item == 'OP_ROT':
                    if len(stack) < 3:
                        txn_p2sh_wsh.add((filename, 'op_rot empty stack fault'))
                        return False
                    
                    x3 = stack.pop()
                    x2 = stack.pop()
                    x1 = stack.pop()

                    stack.append( x2)
                    stack.append(x3)
                    stack.append(x1)

                elif item == 'OP_OVER':
                    if len(stack) < 2:
                        txn_p2sh_wsh.add((filename, 'op_over empty stack fault'))
                        return False
                    
                    x2 = stack.pop()
                    x1 = stack.pop()

                    stack.append(x1)
                    stack.append(x2)
                    stack.append(x1)

        else:
            stack.append(item)

        ptr += 1

    # if there are more if's then endif's invalid!!
    top = None
    if len(stack) > 0:
        top = stack.pop()
        stack.append(top)

    if ctr_if > 0 or len(stack) == 0 or len(stack) > 1 or (len(stack) == 1 and top != 1):
        return False
    
    return True

cnt = 0
txid = ""
wtxid = ""
for i in range(len(json_data_list)):
    filename = json_data_list[i][0]
    transaction = json_data_list[i][1]

    # check if input_value is less than output_value
    input_value = 0
    output_value = 0
    transaction_hash = None
    last_sighash_type = None

    segwit_message = {}
    
    flag = 0

    version = transaction['version'].to_bytes(4, byteorder='little').hex()
    locktime = transaction['locktime'].to_bytes(4, byteorder='little').hex()

    inputs = ""
    ip_len = len(transaction['vin'])
    
    if ip_len <= 252:
        inputs += ip_len.to_bytes(1, byteorder='little').hex()
    elif 253 <= ip_len <= 65535:
        inputs += "fd"
        inputs += ip_len.to_bytes(2, byteorder='little').hex()
    elif 65536 <= ip_len <= 4294967295:
        inputs += "fe"
        inputs += ip_len.to_bytes(4, byteorder='little').hex()
    else:
        inputs += "ff"
        inputs += ip_len.to_bytes(8, byteorder='little').hex()

    outputs = ""
    op_len = len(transaction['vout'])
    if op_len <= 252:
        outputs += op_len.to_bytes(1, byteorder='little').hex()
    elif 253 <= op_len <= 65535:
        inputs += "fd"
        outputs += op_len.to_bytes(2, byteorder='little').hex()
    elif 65536 <= op_len <= 4294967295:
        outputs += "fe"
        outputs += op_len.to_bytes(4, byteorder='little').hex()
    else:
        outputs += "ff"
        outputs += op_len.to_bytes(8, byteorder='little').hex()

    witness = ""

    for index, ip in enumerate(transaction['vin']):
        stack = []
        temp = ['OP_PUSHNUM_1', 'OP_PUSHNUM_2', 'OP_PUSHNUM_3']
        input_value += ip['prevout']['value']

        little_txid = bytes.fromhex(ip['txid'])[::-1].hex()
        vout = ip['vout'].to_bytes(4, byteorder='little').hex()
        inputs += little_txid + vout

        if len(ip['scriptsig']) > 0:
            scriptsig_len = len(ip['scriptsig']) // 2
            if scriptsig_len <= 252:
                inputs += scriptsig_len.to_bytes(1, byteorder='little').hex()
            elif 253 <= scriptsig_len <= 65535:
                inputs += "fd"
                inputs += scriptsig_len.to_bytes(2, byteorder='little').hex()
            elif 65536 <= scriptsig_len <= 4294967295:
                inputs += "fe"
                inputs += scriptsig_len.to_bytes(4, byteorder='little').hex()
            else:
                inputs += "ff"
                inputs += scriptsig_len.to_bytes(8, byteorder='little').hex()

            inputs += ip['scriptsig']
        else:
            inputs += "00"

        inputs += ip['sequence'].to_bytes(4, byteorder='little').hex()

        if 'witness' in ip:
            witness_stack_len = len(ip['witness'])
            if witness_stack_len <= 252:
                witness += witness_stack_len.to_bytes(1, byteorder='little').hex()
            elif 253 <= witness_stack_len <= 65535:
                witness += "fd"
                witness += witness_stack_len.to_bytes(2, byteorder='little').hex()
            elif 65536 <= witness_stack_len <= 4294967295:
                inputs += "fe"
                inputs += witness_stack_len.to_bytes(4, byteorder='little').hex()
            else:
                inputs += "ff"
                inputs += witness_stack_len.to_bytes(8, byteorder='little').hex()

            for item in ip['witness']:
                if item == "":
                    witness += "00"
                else:
                    item_len = len(item) // 2
                    if item_len <= 252:
                        witness += item_len.to_bytes(1, byteorder='little').hex()
                    elif 253 <= item_len <= 65535:
                        witness += "fd"
                        witness += item_len.to_bytes(2, byteorder='little').hex()
                    elif 65536 <= item_len <= 4294967295:
                        inputs += "fe"
                        inputs += item_len.to_bytes(4, byteorder='little').hex()
                    else:
                        inputs += "ff"
                        inputs += item_len.to_bytes(8, byteorder='little').hex()

                    witness += item

        #check if scriptpubkey_asm gives the same scriptpubkey in the input
        asm_list = ip['prevout']['scriptpubkey_asm'].split(" ")
        
        s = ""
        for i in asm_list:
    
            if i.find("OP") != -1 and i in opcodes:
                s += opcodes[i]
            elif i.find("OP") != -1 and i not in opcodes:
                new_opcodes.append(i)
            else:
                s += i
            
        if s != ip['prevout']['scriptpubkey']:
            invalid_txn.add(filename)
            flag = 1
            break

        # #check if scriptsig present and if yes then scriptsig_asm gives the same scriptsig
        # if ip['scriptsig'] != '' and ip['scriptsig_asm'] != '':
        #     temp = ""
        #     script_sig_list = ip['scriptsig_asm'].split(' ')
        #     for i in range(len(script_sig_list)):
                
        #         if script_sig_list[i].find("PUSHDATA") != -1:
        #             temp += opcodes[script_sig_list[i]]
        #             data = script_sig_list[i+1]
        #             len_bytes_decimal = len(data) // 2
        #             len_hex = hex(len_bytes_decimal)
        #             temp += len_hex
        #         elif script_sig_list[i].find("OP") != -1 and script_sig_list[i] in opcodes:
        #             temp += opcodes[script_sig_list[i]]
        #         elif script_sig_list[i].find("OP") != -1 and script_sig_list[i] not in opcodes:
        #             newOpcodes_scriptSig.add(script_sig_list[i])
        #         else:
        #             temp += script_sig_list[i]
            
        #     if temp != ip['scriptsig']:
        #         mismatch_scriptsig_asm_txn.append(filename)
        #         break
        
        if ip['prevout']['scriptpubkey_type'].find("p2pkh") != -1:            
            # total_p2pkh.append(filename)

            # check whether the public key in scriptsig is equal to public key hash in scriptpubkey
            script_sig_list = ip['scriptsig_asm'].split(' ')
            public_key = script_sig_list[len(script_sig_list) - 1]
            scriptpubkey_pkh = asm_list[3]

            sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
            ripemd160_hash = ripemd160(sha256_hash)
            scriptsig_pkh = ripemd160_hash

            if scriptsig_pkh != scriptpubkey_pkh:
                invalid_txn.add(filename)
                flag = 1
                break

            # # verify the signature
            signature_der = script_sig_list[1][:len(script_sig_list[1]) - 2]

            # step1: create the message (transaction hash)
            sighash = script_sig_list[1][len(script_sig_list[1]) - 2:]
            sighash += "000000"
            
            if  transaction_hash == None or sighash != last_sighash_type:
                transaction_hash = gen_legacy_mssg(transaction, ip, sighash)
                last_sighash_type = sighash

            # # step2: verify
            try:
                verify_signature(public_key, transaction_hash, signature_der)
            except ecdsa.BadSignatureError:
                invalid_txn.add(filename)
                flag = 1
                break

        # # #     # # check if the scriptpubkey_pkh gives the same scriptpubkey_addr on base58check encoding
            pkh = "00"
            pkh += scriptpubkey_pkh
            pkh_byte = bytes.fromhex(pkh)

            base58check_encoded = base58.b58encode_check(pkh_byte)
            result = base58check_encoded.decode()

            if result != ip["prevout"]["scriptpubkey_address"]:
                invalid_txn.add(transaction)
                flag = 1
                break

        elif ip['prevout']['scriptpubkey_type'].find("p2wpkh") != -1:
            
            public_key = ip['witness'][1]
            scriptpubkey_pkh = asm_list[2]

            sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
            ripemd160_hash = ripemd160(sha256_hash)
            segwit_pkh = ripemd160_hash

            if segwit_pkh != scriptpubkey_pkh:
                mismatch_wpkh_transaction.append(transaction)
                break

            signature_der = ip['witness'][0][:len(ip['witness'][0]) - 2]
            sighash = ip['witness'][0][len(ip['witness'][0]) - 2:]
            sighash += "000000"

            txn_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)

            # # verify signature
            try:
                verify_signature(public_key, txn_hash, signature_der)
            except ecdsa.BadSignatureError:
                invalid_txn.add(filename)
                flag = 1
                break

            data_bytes = bytes.fromhex(scriptpubkey_pkh)
            segwit_address = bech32.encode("bc", 0, data_bytes)
            if segwit_address != ip['prevout']['scriptpubkey_address']:
                invalid_txn.add(filename)
                flag = 1
                break

        #### --------------------------- P2SH --------------------------------- ####

        elif ip['prevout']['scriptpubkey_type'].find("p2sh") != -1:
            
            # stack = []
            # t9 = ['OP_PUSHNUM_1', 'OP_PUSHNUM_2', 'OP_PUSHNUM_3', 'OP_PUSHBYTES_33']

            # check whether serialized inner redeem script gives the correct OP_HASH160
            scriptsig_asm_list = ip['scriptsig_asm'].split(' ')
            ser_redeem_script = scriptsig_asm_list[len(scriptsig_asm_list) - 1]
            sha256_hash = hashlib.sha256(bytes.fromhex(ser_redeem_script)).hexdigest()
            ripemd160_hash = ripemd160(sha256_hash)
            redeem_script_hash = ripemd160_hash

            if redeem_script_hash != asm_list[2]:
                invalid_txn.add(filename)
                flag = 1
                break

            redeem_script_asm_list = ip['inner_redeemscript_asm'].split(' ')

            if 'witness' not in ip:
                # txn_p2sh.add(filename)
                # for item in redeem_script_asm_list:
                #     if item.find('OP') != -1:
                #         if item not in temp:
                #             new_opcodes.add(item)

                # pass
                
                for i in range(len(scriptsig_asm_list) - 2):
                    item = scriptsig_asm_list[i]

                    if item.find('OP') != -1:
                        if item.find('PUSH') != -1:
                            continue

                    else:
                        stack.append(item)

                if validate_script(redeem_script_asm_list, stack, transaction, filename, ip) == False:
                    invalid_txn.add(filename)
                    flag = 1
                    break
                    
            if 'witness' in ip:
                
                ### --------------- P2SH - P2WPKH ------------------ ###
                if len(redeem_script_asm_list[len(redeem_script_asm_list) - 1]) == 40: #p2wpkh in p2sh
                    
                    signature_der = ip['witness'][0][:len(ip['witness'][0]) - 2]
                    sighash = ip['witness'][0][len(ip['witness'][0]) - 2:]
                    sighash += "000000"
                    
                    # #verify the signature in witness
                    transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)
                    public_key = ip['witness'][1]

                    try:
                        verify_signature(public_key, transaction_hash, signature_der)
                    except ecdsa.BadSignatureError:
                        invalid_txn.add(filename)
                        flag = 1
                        break

                ### --------------- P2SH - P2WSH ------------------ ###

                elif len(redeem_script_asm_list[len(redeem_script_asm_list) - 1]) == 64:
                    
                    # check if the SHA256 witness script hash is equal to the 32 bytes witness program (in redeem script) 
                    # txn_p2sh_wsh.add(filename)
                    ser_witness_script = ip['witness'][len(ip['witness']) - 1]
                    witness_script_hash = hashlib.sha256(bytes.fromhex(ser_witness_script)).digest().hex()
                    if witness_script_hash != redeem_script_asm_list[len(redeem_script_asm_list) - 1]:
                        break
                    
                    witness_script_list = ip['inner_witnessscript_asm'].split(' ')

                    for n in range(len(ip['witness']) - 1):
                        if ip['witness'][n] != "":
                            stack.append(ip['witness'][n])

                    if validate_script(witness_script_list, stack, transaction, filename, ip) == False:
                        invalid_txn.add(filename)
                        flag = 1
                        break

        #### --------------------------- P2WSH --------------------------------- ####

        elif ip['prevout']['scriptpubkey_type'].find("p2wsh") != -1:
            
        #     temp_temp = ['OP_PUSHNUM_1', 'OP_PUSHNUM_2', 'OP_PUSHNUM_3', 'OP_PUSHBYTES_33']
            inner_wit_script_asm = ip['inner_witnessscript_asm'].split(' ')

            # for item in inner_wit_script_asm:
            #     if item.find('OP') != -1:
            #         if item == 'OP_CHECKMULTISIG':
            #             txn_p2wsh.add(filename)
            #             break

            # check whether the inner witness script asm translates to the first item on the witness stack
            witness_script = ""
            for item in inner_wit_script_asm:
                if item.find("OP") != -1:
                    witness_script += opcodes[item]
                else:
                    witness_script += item
            if witness_script != ip['witness'][len(ip['witness']) - 1]:
                invalid_txn.add(filename)
                flag = 1
                break                        

            # check whether the SHA256 of witness script is same as the scriptpubkey
            witness_script = ip['witness'][len(ip['witness']) - 1]
            wit_script_hash = sha256(witness_script)
            if wit_script_hash != asm_list[len(asm_list) - 1]:
                invalid_txn.add(filename)
                flag = 1
                break

            # push the witness on the stack
            for itr in range(len(ip['witness']) - 1):
                if len(ip['witness'][itr]) > 0:
                    stack.append(ip['witness'][itr])

            # # # print(filename)
            if validate_script(inner_wit_script_asm, stack, transaction, filename, ip) == False:
                # print("Invalid Transaction")
                invalid_txn.add(filename)
                flag = 1
                break
        
        elif ip['prevout']['scriptpubkey_type'].find("p2tr") != -1:
            flag = 1
            break
    
    for op in transaction['vout']:
        output_value += op['value']
        outputs += op['value'].to_bytes(8, byteorder='little').hex()
        scriptpubkey_len = len(op['scriptpubkey'] ) // 2

        if scriptpubkey_len <= 252:
            outputs += scriptpubkey_len.to_bytes(1, byteorder='little').hex()
        elif 253 <= scriptpubkey_len <= 65535:
            inputs += "fd"
            outputs += scriptpubkey_len.to_bytes(2, byteorder='little').hex()
        elif 65536 <= scriptpubkey_len <= 4294967295:
            outputs += "fe"
            outputs += scriptpubkey_len.to_bytes(4, byteorder='little').hex()
        else:
            outputs += "ff"
            outputs += scriptpubkey_len.to_bytes(8, byteorder='little').hex()
        outputs += op['scriptpubkey']
        
    if flag == 0:
        wu = 0
        wu += ((len(version) // 2) + (len(inputs) // 2) + (len(outputs) // 2) + (len(locktime) // 2)) * 4
        if witness != "":
            wu += ((len(witness) // 2) + 2) * 1

        temp = ""
        temp += version + inputs + outputs + locktime
        txid = dsha256(temp)

        temp = ""
        if witness != "":
            temp += version + "0001" + inputs + outputs + witness + locktime
            wtxid = dsha256(temp)
        
        fee = input_value - output_value
        fee_wu = fee // wu
        valid_txn.append((transaction, fee, fee_wu, wu, txid, wtxid))

    # if output_value > input_value:
    #     cnt += 1

