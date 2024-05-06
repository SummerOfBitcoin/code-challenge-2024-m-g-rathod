# import hashlib
# import ecdsa
# from ecdsa.util import sigdecode_der
# import binascii
# import base58
# import re
# import bech32

# def dsha256(message):
#     byte_value = bytes.fromhex(message)
#     first_hash = hashlib.sha256(byte_value).digest()
#     second_hash = hashlib.sha256(first_hash).digest()
#     return second_hash.hex()

# def gen_legacy_mssg(transaction, current_input, sighash):
#     '''
#         message =
#         version[4bytes little_endian] +
#         input_count[compact_size] +
#         inputs (txn_id[little_endian] + txn_index[4bytes little_endian] + scriptsigsize[compact_size] +
#                 scriptsig[scriptpubkey] + sequence[4bytes little_endian]) +
#         output_count[compact_size] +
#         outputs (amount[8bytes little_endian] + scriptpubkey_size[compact_size] + scriptpubkey) +
#         locktime[4bytes little_endian] +
#         sighash[4bytes little_endian]
#     '''
#     curr_ip_list = []
#     curr_ip_list.append(current_input)
#     message = ""

#     version = transaction['version']
#     hex_version = version.to_bytes(4, byteorder='little').hex()
#     message += hex_version

#     temp_list = None
#     if sighash == "01000000":
#         temp_list = transaction['vin']
#     elif sighash == "81000000":
#         temp_list = curr_ip_list

#     ip_count = len(temp_list)
#     hex_ip_count = ""
#     if ip_count <= 252:
#         hex_ip_count += ip_count.to_bytes(1, byteorder='little').hex()
#     elif 253 <= ip_count <= 65535:
#         hex_ip_count += "fd"
#         hex_ip_count += ip_count.to_bytes(2, byteorder='little').hex()
#     elif 65536 <= ip_count <= 4294967295:
#         hex_ip_count += "fe"
#         hex_ip_count += ip_count.to_bytes(4, byteorder='little').hex()
#     else:
#         hex_ip_count += "ff"
#         hex_ip_count += ip_count.to_bytes(8, byteorder='little').hex()
#     message += hex_ip_count

#     for ip in temp_list:
#         txn_id = ip['txid']
#         le_txid_bytes = bytes.fromhex(txn_id)[::-1]
#         le_txid_hex = le_txid_bytes.hex()
#         message += le_txid_hex

#         vout = ip['vout']
#         vout_hex = vout.to_bytes(4, byteorder='little').hex()
#         message += vout_hex

#         scriptsig = ''

#         if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
#             l1 = ip['scriptsig_asm'].split(' ')
#             scriptsig = l1[len(l1) - 1]
#         else:
#             scriptsig = ip['prevout']['scriptpubkey']

#         scriptsigsize = len(scriptsig) // 2
#         scriptsigsize_hex = ""
#         if scriptsigsize <= 252:
#             scriptsigsize_hex += scriptsigsize.to_bytes(1, byteorder='little').hex()
#         elif 253 <= scriptsigsize <= 65535:
#             scriptsigsize_hex += "fd"
#             scriptsigsize_hex += scriptsigsize.to_bytes(2, byteorder='little').hex()
#         elif 65536 <= scriptsigsize <= 4294967295:
#             scriptsigsize_hex += "fe"
#             scriptsigsize_hex += scriptsigsize.to_bytes(4, byteorder='little').hex()
#         else:
#             scriptsigsize_hex += "ff"
#             scriptsigsize_hex += scriptsigsize.to_bytes(8, byteorder='little').hex()
#         message += scriptsigsize_hex

#         message += scriptsig

#         sequence = ip['sequence']
#         sequence_hex = sequence.to_bytes(4, byteorder='little').hex()
#         message += sequence_hex

#     op_count = len(transaction['vout'])
#     hex_op_count = ""
#     if op_count <= 252:
#         hex_op_count += op_count.to_bytes(1, byteorder='little').hex()
#     elif 253 <= op_count <= 65535:
#         hex_op_count += "fd"
#         hex_op_count += op_count.to_bytes(2, byteorder='little').hex()
#     elif 65536 <= op_count <= 4294967295:
#         hex_op_count += "fe"
#         hex_op_count += op_count.to_bytes(4, byteorder='little').hex()
#     else:
#         hex_op_count += "ff"
#         hex_op_count += op_count.to_bytes(8, byteorder='little').hex()
#     message += hex_op_count

#     for op in transaction['vout']:
#         amount = op['value']
#         amount_hex = amount.to_bytes(8, byteorder='little').hex()
#         message += amount_hex

#         scriptpubkeysize = len(op['scriptpubkey']) // 2
#         scriptpubkeysize_hex = ""
#         if scriptpubkeysize <= 252:
#             scriptpubkeysize_hex += scriptpubkeysize.to_bytes(1, byteorder='little').hex()
#         elif 253 <= scriptpubkeysize <= 65535:
#             scriptpubkeysize_hex += "fd"
#             scriptpubkeysize_hex += scriptpubkeysize.to_bytes(2, byteorder='little').hex()
#         elif 65536 <= scriptpubkeysize <= 4294967295:
#             scriptpubkeysize_hex += "fe"
#             scriptpubkeysize_hex += scriptpubkeysize.to_bytes(4, byteorder='little').hex()
#         else:
#             scriptpubkeysize_hex += "ff"
#             scriptpubkeysize_hex += scriptpubkeysize.to_bytes(8, byteorder='little').hex()
#         message += scriptpubkeysize_hex

#         message += op['scriptpubkey']

#     locktime = transaction['locktime']
#     locktime_hex = locktime.to_bytes(4, byteorder='little').hex()
#     message += locktime_hex

#     message += sighash
#     # print(message)
#     txn_hash = dsha256(message)
#     return txn_hash

# def gen_segwit_mssg(transaction, curr_input, sighash, segwit_message, ip_index):
#     '''
#         preimage =  version + 
#                     hash256(inputs) [inputs = txid1 + vout1 + txid2 + vout2 + ........] + 
#                     hash256(sequences) + 
#                     input [curr_txid + curr_ip_vout] + 
#                     scriptcode + 
#                     amount [ 8-byte little endian ] + 
#                     sequence [curr_ip_sequence] + 
#                     hash256(outputs) [amount1 + scriptpubkeysize1 + scriptpubkey1 + .........] + 
#                     loctime [4-byte little endian] + 
#                     sighash_type

#     '''
#     if segwit_message == {} or sighash != segwit_message['sighash']:
#         segwit_message['sighash'] = sighash
        
#         hex_version = transaction['version'].to_bytes(4, byteorder='little').hex()
#         segwit_message['version'] = hex_version

#         if sighash == "81000000" or sighash == "83000000" or sighash == "82000000":
#             segwit_message['hashed_inputs'] = "00" * 32
#             segwit_message['hashed_seqs'] = "00" * 32

#         else:
#             serialized_ip = ""
#             serialized_seqs = ""
            
#             for ip in transaction['vin']:

#                 txn_id = ip['txid']
#                 le_txid_bytes = bytes.fromhex(txn_id)[::-1]
#                 le_txid_hex = le_txid_bytes.hex()
#                 vout_hex = ip['vout'].to_bytes(4, byteorder='little').hex()
#                 serialized_ip += le_txid_hex + vout_hex

#                 seq = ip['sequence']
#                 seq_hex = seq.to_bytes(4, byteorder='little').hex()
#                 serialized_seqs += seq_hex

#             segwit_message['hashed_inputs'] = dsha256(serialized_ip)
#             segwit_message['hashed_seqs'] = dsha256(serialized_seqs)

#         op_list = []

#         if sighash == "82000000":
#             segwit_message['hashed_ops'] = "00" * 32
#         elif sighash == "83000000":
#             if len(transaction['vin']) <= len(transaction['vout']):
#                 op_list.append(transaction['vout'][ip_index])
#         else:
#             op_list = transaction['vout']

#         serialized_ops = ""
#         if len(op_list) > 0:
#             for op in op_list:
#                 amount = op['value']
#                 amount_hex = amount.to_bytes(8, byteorder='little').hex()
#                 serialized_ops += amount_hex

#                 scriptpubkeysize = len(op['scriptpubkey']) // 2
#                 scriptpubkeysize_hex = ""
#                 if scriptpubkeysize <= 252:
#                     scriptpubkeysize_hex += scriptpubkeysize.to_bytes(1, byteorder='little').hex()
#                 elif 253 <= scriptpubkeysize <= 65535:
#                     scriptpubkeysize_hex += "fd"
#                     scriptpubkeysize_hex += scriptpubkeysize.to_bytes(2, byteorder='little').hex()
#                 elif 65536 <= scriptpubkeysize <= 4294967295:
#                     scriptpubkeysize_hex += "fe"
#                     scriptpubkeysize_hex += scriptpubkeysize.to_bytes(4, byteorder='little').hex()
#                 else:
#                     scriptpubkeysize_hex += "ff"
#                     scriptpubkeysize_hex += scriptpubkeysize.to_bytes(8, byteorder='little').hex()
#                 serialized_ops += scriptpubkeysize_hex

#                 serialized_ops += op['scriptpubkey']

#         if sighash != "83000000" and sighash != "82000000":
#             segwit_message['hashed_ops'] = dsha256(serialized_ops)
#         elif sighash == "83000000":
#             if len(transaction['vin']) > len(transaction['vout']):
#                 segwit_message['hashed_ops'] = "00" * 32
#             else:
#                 segwit_message['hashed_ops'] = dsha256(serialized_ops)

#         locktime = transaction['locktime']          
#         locktime_hex = locktime.to_bytes(4, byteorder='little').hex()
#         segwit_message['locktime'] = locktime_hex

#     message = ""             

#     message += segwit_message['version'] + segwit_message['hashed_inputs'] + segwit_message['hashed_seqs']

#     txn_id = curr_input['txid']
#     le_txid_bytes = bytes.fromhex(txn_id)[::-1]
#     le_txid_hex = le_txid_bytes.hex()
#     vout_hex = curr_input['vout'].to_bytes(4, byteorder='little').hex()

#     message += le_txid_hex + vout_hex

#     scriptcode = ""
#     # scriptcode

#     # if p2wpkh
#     if curr_input['prevout']['scriptpubkey_type'].find('p2wpkh') != -1:
#         scriptpubkey_asm_list = curr_input['prevout']['scriptpubkey_asm'].split(' ')
#         scriptcode += "1976a914"
#         scriptcode += scriptpubkey_asm_list[2]
#         scriptcode += "88ac"
    
    
#     if curr_input['prevout']['scriptpubkey_type'].find('p2sh') != -1:
#         redeem_script_list = curr_input['inner_redeemscript_asm'].split(' ')

#         # if p2wpkh nested in p2sh
#         if len(redeem_script_list[len(redeem_script_list) - 1]) == 40:
#             scriptcode += "1976a914"
#             scriptcode += redeem_script_list[2]
#             scriptcode += "88ac"

#         #if p2wsh nested in p2sh
#     if (curr_input['prevout']['scriptpubkey_type'].find('p2sh') != -1 and len(redeem_script_list[len(redeem_script_list) - 1]) == 64) or curr_input['prevout']['scriptpubkey_type'].find('p2wsh') != -1:
#         ser_redeem_script = curr_input['witness'][len(curr_input['witness']) - 1]
#         ser_red_script_size = len(ser_redeem_script) // 2
#         if ser_red_script_size <= 252:
#             scriptcode += ser_red_script_size.to_bytes(1, byteorder='little').hex()
#         elif 253 <= ser_red_script_size <= 65535:
#             scriptcode += "fd"
#             scriptcode += ser_red_script_size.to_bytes(2, byteorder='little').hex()
#         elif 65536 <= ser_red_script_size <= 4294967295:
#             scriptcode += "fe"
#             scriptcode += ser_red_script_size.to_bytes(4, byteorder='little').hex()
#         else:
#             scriptcode += "ff"
#             scriptcode += ser_red_script_size.to_bytes(8, byteorder='little').hex()

#         scriptcode += ser_redeem_script

#     message += scriptcode

#     amt = curr_input['prevout']['value']
#     amt_hex = amt.to_bytes(8, byteorder='little').hex()
#     message += amt_hex

#     sequence = curr_input['sequence']
#     seq_hex = sequence.to_bytes(4, byteorder='little').hex()
#     message += seq_hex

#     message += segwit_message['hashed_ops']

#     message += segwit_message['locktime']

#     message += sighash
    
#     return dsha256(message)

# def verify_signature(public_key_hex, transaction_hash_hex, signature_der_hex):
#     # Convert the public key, transaction hash, and signature to binary
#     public_key = bytes.fromhex(public_key_hex)
#     transaction_hash = bytes.fromhex(transaction_hash_hex)
#     signature_der = bytes.fromhex(signature_der_hex)

#     # Create a verification key object
#     vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)

#     # Verify the signature
#     return vk.verify_digest(signature=signature_der, digest=transaction_hash, sigdecode=sigdecode_der)

# def ripemd160(message):
#     bytes_data = bytes.fromhex(message)
#     ripemd160_hash = hashlib.new('ripemd160', bytes_data).digest()
#     ripemd160_hex = ripemd160_hash.hex()
#     return ripemd160_hex

# def sha256(hex_string):
#     byte_string = bytes.fromhex(hex_string)
#     sha256_hash = hashlib.sha256(byte_string).hexdigest()
#     return sha256_hash

# txn_p2wsh = set()
# txn_p2sh_wsh = set()

# def validate_script(script_list, stack, transaction, filename, ip):
#     ptr = 0
#     ctr_if = 0
#     ctr = 0
#     transaction_hash = None
#     last_sighash_type = None
#     while ptr < len(script_list):
#         item = script_list[ptr]
#         print(item)
#         if item.find('OP') != -1:

#             # if item.find('OP_CSV') != -1:
#             #     txn_p2wsh.add(filename)                        

#             if item.find('PUSHNUM') != -1:
#                 l = re.findall(r'\d+', item)
#                 number = int(l[0]) if l else None
#                 number_hex = number.to_bytes(1, byteorder='big').hex()
#                 stack.append(number_hex)

#             elif item.find('PUSH') != -1:
#                 ptr += 1
#                 print(stack)
#                 continue
                        
#             else:

#                 if item == "OP_DROP" :
#                     if len(stack ) <= 0:
#                         txn_p2wsh.add((filename, 'op_drop'))
#                         return False
#                     top = stack.pop()

#                 elif item == "OP_IF":
#                     ctr_if += 1
#                     if len(stack) <= 0:
#                         txn_p2wsh.add((filename, 'op_if empty stack fault'))
#                         return False
#                     top = stack.pop()
#                     if top == 0:
                                
#                         ptr2 = ptr + 1
#                         while ptr2 < len(script_list):
#                             if script_list[ptr2] == "OP_IF" or script_list[ptr2] == "OP_NOTIF":
#                                 ctr_if += 1
#                                 ctr += 1

#                             elif script_list[ptr2] == "OP_ELSE":
#                                 if ctr == 0:
#                                     break
#                                 else:
#                                     ctr -= 1

#                             elif script_list[ptr2] == "OP_ENDIF":
#                                 ctr_if -= 1

#                             ptr2 += 1

#                         ptr = ptr2 + 1
#                         print(stack)
#                         continue

#                 elif item == "OP_NOTIF":
#                     ctr_if += 1
#                     if len(stack) <= 0:
#                         txn_p2wsh.add((filename, 'op_notif empty stack fault'))
#                         return False
#                     top = stack.pop()
#                     if top != 0:
                                
#                         ptr2 = ptr + 1
#                         while ptr2 < len(script_list):
#                             if script_list[ptr2] == "OP_IF" or script_list[ptr2] == "OP_NOTIF":
#                                 ctr_if += 1
#                                 ctr += 1

#                             elif script_list[ptr2] == "OP_ELSE":
#                                 if ctr == 0:
#                                     break
#                                 else:
#                                     ctr -= 1

#                             elif script_list[ptr2] == "OP_ENDIF":
#                                 ctr_if -= 1

#                             ptr2 += 1

#                         ptr = ptr2 + 1
#                         print(stack)
#                         continue

#                 elif item == "OP_ELSE":
#                     ptr2 = ptr + 1

#                     while ptr2 < len(script_list):

#                         if script_list[ptr2] == "OP_IF" or script_list[ptr2] == "OP_NOTIF":
#                             ctr_if += 1

#                         if script_list[ptr2] == "OP_ENDIF":
#                             ctr_if -= 1
#                             if ctr_if == 0:
#                                 break

#                         ptr2 += 1

#                     ptr = ptr2 + 1
#                     print(stack)
#                     continue

#                 elif item == "OP_ENDIF":
                    
#                     if ctr_if <= 0:
#                         txn_p2wsh.add((filename, 'op_endif less if fault'))
#                         return False
                    
#                     ctr_if -= 1

#                 elif item == "OP_SHA256":
#                     if len(stack) <= 0:
#                         txn_p2wsh.add((filename, 'op_sha256 empty stack fault'))
#                         return False
#                     top = stack.pop()
#                     top_hash = sha256(top)
#                     stack.append(top_hash)

#                 elif item == "OP_SIZE":
#                     if len(stack) <= 0:
#                         txn_p2wsh.add((filename, 'op_size empty stack fault'))
#                         return False
#                     top = stack.pop()
#                     top_len = len(top)
#                     top_len_bytes = top_len // 2
#                     stack.append(top)
#                     stack.append(hex(top_len_bytes)[2:])

#                 elif item == "OP_CLTV":
#                     if len(stack) == 0:
#                         txn_p2wsh.add((filename, 'op_cltv empty stack fault'))
#                         return False

#                     top = stack.pop()
#                     top_decimal = int(top, 16)

#                     if top_decimal < 0 or ip['sequence'] == 4294967295:
#                         txn_p2wsh.add((filename, 'op_cltv sequence == ffffffff'))
#                         return False

#                     else:
#                         if (transaction['locktime'] < 500000000 and top_decimal < 500000000) or (transaction['locktime'] > 500000000 and top_decimal > 500000000):
#                             if top_decimal > transaction['locktime']:
#                                 txn_p2wsh.add((filename, 'op_cltv stack ele greater than locktime'))
#                                 return False

#                             else:
#                                 stack.append(top)

#                         else:
#                             txn_p2wsh.add((filename, 'op_cltv mismatch locktime type fault '))
#                             return False
                        
#                 elif item == "OP_CSV":
#                     if len(stack) == 0:
#                         txn_p2wsh.add((filename, 'op_csv empty stack fault'))
#                         return False

#                     top = stack.pop()
#                     top_decimal = None

#                     if type(top) == str:
#                         top_decimal = int(top, 16)
#                     elif type(top) == int:
#                         top_decimal = top

#                     if top_decimal < 0:
#                         txn_p2wsh.add((filename, 'op_csv stack ele less than 0 fault'))
#                         return False

#                     x = top_decimal >> 31
#                     bit = x & 1
#                     rel = top_decimal >> 21
#                     rel_bit = rel & 1

#                     if bit == 0:
#                         x1 = ip['sequence'] >> 31
#                         bit1 = x1 & 1
#                         rel2 = ip['sequence'] >> 21
#                         seq_bit22 = rel2 & 1

#                         if transaction['version'] < 2 or bit1 == 1 or rel_bit != seq_bit22:
#                             txn_p2wsh.add((filename, 'op_csv version fault or 32nd bit of txn seq == 1 or 22nd bit mismatch'))
#                             return False

#                         top_val = top_decimal & (0x0000ffff)
#                         seq_val = ip['sequence'] & (0x0000ffff)

#                         if top_val > seq_val:
#                             txn_p2wsh.add((filename, 'op_csv stack ele greater than seq val'))
#                             return False

#                     stack.append(top)

#                 elif item == "OP_CHECKSIGVERIFY":
#                     if len(stack) <= 1:
#                         txn_p2wsh.add((filename, 'op_checksigver empty stack fault'))
#                         return False
#                     public_key = stack.pop()
#                     sign = stack.pop()

#                     sighash = sign[len(sign) - 2:]
#                     sighash += "000000"

#                     signature_der = sign[:len(sign) - 2]

#                     if transaction_hash == None or sighash != last_sighash_type:
#                         last_sighash_type = sighash

#                         if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1 and 'witness' not in ip: 
#                             transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

#                         else:
#                             transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)

#                         print(transaction_hash)

#                         # elif ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
#                         #     transaction_hash = gen_legacy_mssg(transaction, ip, sighash)
#                     try:
#                         verify_signature(public_key, transaction_hash, signature_der)
#                     except ecdsa.BadSignatureError:
#                         txn_p2wsh.add((filename, 'op_checksigverify sign fault'))
#                         return False
                    
#                 elif item == "OP_CHECKSIG":
#                     if len(stack) <= 1:
#                         txn_p2wsh.add((filename, 'op_checksig empty stack fault'))
#                         return False
#                     public_key = stack.pop()
#                     sign = stack.pop()

#                     sighash = sign[len(sign) - 2:]
#                     sighash += "000000"

#                     signature_der = sign[:len(sign) - 2]

#                     if transaction_hash == None or sighash != last_sighash_type:
#                         last_sighash_type = sighash
#                         # if ip['prevout']['scriptpubkey_type'].find('p2wsh') != -1:
#                         if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1 and 'witness' not in ip: 
#                             transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

#                         else:
#                             transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)
#                         # elif ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
#                         #     transaction_hash = gen_legacy_mssg(transaction, ip, sighash)
#                         print(transaction_hash)
#                     try:
#                         verify_signature(public_key, transaction_hash, signature_der)
#                         stack.append(1)
#                     except ecdsa.BadSignatureError:
#                         stack.append(0)

#                 elif item == 'OP_CHECKMULTISIG':
#                     n = stack.pop()

#                     if type(n) == str:
#                         n = int(n, 16)

#                     temp_n = n
#                     public_key_list = []
#                     signatures_list = []
#                     verified_pubkeys = []

#                     while temp_n > 0:
#                         public_key_list.append(stack.pop())
#                         temp_n -= 1

#                     m = stack.pop()

#                     if type(m) == str:
#                         m = int(m, 16)

#                     temp_m = m

#                     while temp_m > 0:
#                         signatures_list.append(stack.pop())
#                         temp_m -= 1
                    
#                     # print(signatures_list)
#                     # print(public_key_list)
#                     for sign in signatures_list:
#                         for public_key in public_key_list:

#                             if public_key in verified_pubkeys:
#                                 continue
#                             else:
#                                 sighash = sign[len(sign) - 2:]
#                                 sighash += "000000"

#                                 signature_der = sign[:len(sign) - 2]

#                                 if transaction_hash == None or sighash != last_sighash_type:
#                                     last_sighash_type = sighash
#                                     # if ip['prevout']['scriptpubkey_type'].find('p2wsh') != -1:
#                                     if ip['prevout']['scriptpubkey_type'].find('p2sh') != -1 and 'witness' not in ip: 
#                                         transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

#                                     else:
#                                         transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)
#                                     print(transaction_hash)
#                                     # elif ip['prevout']['scriptpubkey_type'].find('p2sh') != -1:
#                                     #     transaction_hash = gen_legacy_mssg(transaction, ip, sighash)

#                                 try:
#                                     verify_signature(public_key, transaction_hash, signature_der)
#                                     verified_pubkeys.append(public_key)
#                                     break
#                                 except ecdsa.BadSignatureError:
#                                     continue
#                     # print(verified_pubkeys)
#                     if len(verified_pubkeys) >= m:
#                         stack.append(1)
#                     else:
#                         stack.append(0)

#                 elif item == 'OP_SWAP':
#                     if len(stack) <= 1:
#                         txn_p2wsh.add((filename, 'op_swap empty stack fault'))
#                         return False
#                     top1 = stack.pop()
#                     top2 = stack.pop()

#                     stack.append(top1)
#                     stack.append(top2)

#                 elif item == 'OP_EQUALVERIFY':
#                     if len(stack) <= 1:
#                         txn_p2wsh.add((filename, 'op_eqver empty stack fault'))
#                         return False
#                     top1 = stack.pop()
#                     top2 = stack.pop()

#                     if top1 != top2:
#                         txn_p2wsh.add((filename, 'op_eqver ele unequal'))
#                         return False

#                 elif item == 'OP_EQUAL':
#                     if len(stack) <= 1:
#                         txn_p2wsh.add((filename, 'op_eq empty stack fault'))
#                         return False
#                     top1 = stack.pop()
#                     top2 = stack.pop()

#                     if top1 != top2:
#                         stack.append(0)
#                     else:
#                         stack.append(1)

#                 elif item == 'OP_GREATERTHAN':
#                     if len(stack) <= 1:
#                         txn_p2wsh.add((filename, 'op_greaterthan empty stack fault'))
#                         return False
#                     top1 = stack.pop()
#                     top2 = stack.pop()

#                     if type(top1) == str:
#                         top1 = int(top1, 16)

#                     if type(top2) == str:
#                         top2 = int(top2, 16)

#                     if type(top1) == int and type(top2) == int:
#                         if top2 > top1:
#                             stack.append(1)

#                         else:
#                             stack.append(0)

#                     else:
#                         txn_p2wsh.add((filename, 'op_greaterthan stack eles type not int'))
#                         return False

#                 elif item == 'OP_HASH160':
#                     if len(stack) <= 0:
#                         txn_p2wsh.add((filename, 'op_hash160 empty stack fault'))
#                         return False
#                     top = stack.pop()

#                     sha_top = sha256(top)
#                     hash160 = ripemd160(sha_top)
#                     stack.append(hash160)

#                 elif item == 'OP_IFDUP':
#                     if len(stack) <= 0:
#                         txn_p2wsh.add((filename, 'op_ifdup empty stack fault'))
#                         return False
#                     top = stack.pop()

#                     if top != 0:
#                         stack.append(top)
                            
#                     stack.append(top)   

#                 elif item == 'OP_DUP':
#                     if len(stack) <= 0:
#                         txn_p2wsh.add((filename, 'op_dup empty stack fault'))
#                         return False
#                     top = stack.pop()
#                     stack.append(top)
#                     stack.append(top)

#                 elif item == 'OP_ROT':
#                     if len(stack) < 3:
#                         txn_p2sh_wsh.add((filename, 'op_rot empty stack fault'))
#                         return False
                    
#                     x3 = stack.pop()
#                     x2 = stack.pop()
#                     x1 = stack.pop()

#                     stack.append( x2)
#                     stack.append(x3)
#                     stack.append(x1)

#                 elif item == 'OP_OVER':
#                     if len(stack) < 2:
#                         txn_p2sh_wsh.add((filename, 'op_over empty stack fault'))
#                         return False
                    
#                     x2 = stack.pop()
#                     x1 = stack.pop()

#                     stack.append(x1)
#                     stack.append(x2)
#                     stack.append(x1)

#         else:
#             stack.append(item)
#         print(stack)
#         ptr += 1

#     # if there are more if's then endif's invalid!!
#     top = None
#     if len(stack) > 0:
#         top = stack.pop()
#         stack.append(top)

#     if ctr_if > 0 or len(stack) == 0 or len(stack) > 1 or (len(stack) == 1 and top != 1):
#         return False
    
#     return True

# transaction = {
#   "version": 2,
#   "locktime": 833158,
#   "vin": [
#     {
#       "txid": "e5d10a9e6956c9e8d79594f5acb20223f51b9cf4a1ed78c9517e4184ca68a9b3",
#       "vout": 184,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 16511
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "3044022052e054510e0d6db8c2d1195b5be113dfdf4d8d99c9e264b4dfd4a101d6d532fc022050b618e2e5f347ec6ec4c005bf589dcd8c4b04c812efec29225dd3a05813832001",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "5af87b760cad8ed080fc6cf2ba70040e31c89af5b746a968d4e783806a3ebf49",
#       "vout": 47,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 35920
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "30440220557b674e096640c7361e2ea9028dc56fb906f281203e01029370aefc485e36b7022015dcc281395064fec31588f4c963a01c273ba528380f53fcc6b421d4a35191f201",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "65f2cac5fce95ac6d8566e21533e6382fbc5425b2fb878f614d39812e45af804",
#       "vout": 391,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 35511
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "30440220086c2c1e5a406fa92ab5d75afc76b3fdea9f40395f1be929495d6f5def79b5b1022071b9597c42305751ba8d0e10da3d986e9adee40b9a4b7ae32551dc833fd2380001",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "7f540c947af7a13d0e1ae01b43722467041dc85d8f8cede9b3d863778575f7ab",
#       "vout": 94,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 52807
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "304402203cf6e30e4f16d6aea678e5e601eec1b574b5e8831e571383e9bb6fafabccdc9a022070e0054c25fb4228e646b2fb1b9e846b594ce507b25aaa9422c4aa7c38a8c0c201",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "3e13dbb523dd719f24acf3cb7096b1d4faf2af21b63159f886b436ebc03d7c94",
#       "vout": 109,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 29503
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "3044022037075fe91bc846075bbbb4c0dfde3078e9efe3e09c1e4f6fcbe47ae972051dd102204dd7491fa46ce222fa1bb78cb8de7a3442778e33e24626aa3e8517d76ff7cd3101",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "15b802f54d14e13bc601d425688a26cb9692eed925f4bbe58a756787e7281195",
#       "vout": 81,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 27147
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "304402204971480e51b2f6cac9b04ff7db4595af38dc3a6e0becca4778e3091725d79000022031ca7b26f93b9b3399d8a30f15bfbfa92899ad0d2e93aaf49c3890b94dc5c38c01",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "ab6e5f10908b40c99afaa5a45a1d4b2f0fc48810c8c58c1620038537cf17a681",
#       "vout": 117,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 44241
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "3044022041405923b9e2a65514648cf96502771199d87c90c4221efb5f8d9ea81022a33502205c3662bf481a72e132eaa97bc9cf7c690e955b95fef8ab127fb55d9dbd4b257a01",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "bb5226c1c3c7ca22d6c7ce46011e060eb56929d09d257eb3a0b3198e8e88ea02",
#       "vout": 104,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 157783
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "304402206979855a0c716679182dcd4535250e62add1da39cfbf69a757f91379cd3728a7022021b99e1aa7b7e4a9481ef7a4b7e6d220362b921d4706e0e08d57c738e85db24201",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "bb5226c1c3c7ca22d6c7ce46011e060eb56929d09d257eb3a0b3198e8e88ea02",
#       "vout": 161,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 47244
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "304402204b60627e70a35673868cb9c8ec9163a61bbb2361e555a7aef25d64b03fee338002204f98c3fb752aadaa1b68e9892b3572b59a266806ab456505bfd04b1ac659558801",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     },
#     {
#       "txid": "482b9b787e3928e72654957be82c2e4eced9f40288703644f880918697e31596",
#       "vout": 193,
#       "prevout": {
#         "scriptpubkey": "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87",
#         "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL",
#         "scriptpubkey_type": "p2sh",
#         "scriptpubkey_address": "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo",
#         "value": 35004
#       },
#       "scriptsig": "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "scriptsig_asm": "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "witness": [
#         "",
#         "304402205d05aabfbd4efb0d505d6e59cd05b5011a3c844057046d314e5c6a8895fea2bd02205e101abb5cb5d7d47274d6a1362e9b0b44491801e24252343e58cbab2ff76d4801",
#         "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268"
#       ],
#       "is_coinbase": False,
#       "sequence": 51840,
#       "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960",
#       "inner_witnessscript_asm": "OP_PUSHBYTES_33 02eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffa OP_CHECKSIGVERIFY OP_PUSHBYTES_33 038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844 OP_CHECKSIG OP_IFDUP OP_NOTIF OP_PUSHBYTES_3 80ca00 OP_CSV OP_ENDIF"
#     }
#   ],
#   "vout": [
#     {
#       "scriptpubkey": "a91414a7c89e76b8d39ccdc4d31c08febfb5afdd5fd187",
#       "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 14a7c89e76b8d39ccdc4d31c08febfb5afdd5fd1 OP_EQUAL",
#       "scriptpubkey_type": "p2sh",
#       "scriptpubkey_address": "33aESCCpyAkuU4CCdGi1NkbgkokLMY2SKF",
#       "value": 468659
#     }
#   ]
# }
# segwit_message = {}

# invalid_txn = set()
# transaction_hash = None
# last_sighash_type = None

# for index,ip in enumerate(transaction['vin']):
#     asm_list = ip['prevout']['scriptpubkey_asm'].split(" ")
#     if ip['prevout']['scriptpubkey_type'].find("p2sh") != -1:
#         stack = []
#         redeem_script_asm_list = ip['inner_redeemscript_asm'].split(' ')
#         scriptsig_asm_list = ip['scriptsig_asm'].split(' ')

#         if 'witness' not in ip:
#                     # if len(scriptsig_asm_list) != 7:
#                     #     txn_p2sh.add(filename)
#                     # txn_p2sh.add(filename)
#                     # for item in redeem_script_asm_list:
#                     #     if item.find('OP') != -1:
#                     #         if item not in temp:
#                     #             new_opcodes.add(item)

#                     # pass
                    
#                     for i in range(len(scriptsig_asm_list) - 2):
#                         item = scriptsig_asm_list[i]

#                         if item.find('OP') != -1:
#                             if item.find('PUSH') != -1:
#                                 continue

#                         else:
#                             stack.append(item)

#         elif 'witness' in ip:
#             if len(redeem_script_asm_list[len(redeem_script_asm_list) - 1]) == 40: #p2wpkh in p2sh
                    
#                     signature_der = ip['witness'][0][:len(ip['witness'][0]) - 2]
#                     sighash = ip['witness'][0][len(ip['witness'][0]) - 2:]
#                     sighash += "000000"
                    
#                     # #verify the signature in witness
#                     transaction_hash = gen_segwit_mssg(transaction, ip, sighash, segwit_message, index)
#                     public_key = ip['witness'][1]

#                     try:
#                         verify_signature(public_key, transaction_hash, signature_der)
#                     except ecdsa.BadSignatureError:
#                         # invalid_txn.add(filename)
#                         print("invalid sign")
#                         break

#                 ### --------------- P2SH - P2WSH ------------------ ###

#             elif len(redeem_script_asm_list[len(redeem_script_asm_list) - 1]) == 64:
                    
#                     # check if the SHA256 witness script hash is equal to the 32 bytes witness program (in redeem script) 
#                     # txn_p2sh_wsh.add(filename)
#                     ser_witness_script = ip['witness'][len(ip['witness']) - 1]
#                     witness_script_hash = hashlib.sha256(bytes.fromhex(ser_witness_script)).digest().hex()
#                     if witness_script_hash != redeem_script_asm_list[len(redeem_script_asm_list) - 1]:
#                         break
                    
#                     witness_script_list = ip['inner_witnessscript_asm'].split(' ')

#                     for n in range(len(ip['witness']) - 1):
#                         if ip['witness'][n] != "":
#                             stack.append(ip['witness'][n])

#                     if validate_script(witness_script_list, stack, transaction, 'djfdhg', ip) == False:
#                         # invalid_txn.add(filename)
#                         print('invalid script')
#                         break

#         if validate_script(redeem_script_asm_list, stack, transaction, 'ajdjgh', ip) == False:
#             print("Invalid Transaction")
#             print(txn_p2wsh)
#             break
#         else:
#             print("valid")

#     if ip['prevout']['scriptpubkey_type'].find("p2pkh") != -1:            
#             # total_p2pkh.append(filename)

#             # check whether the public key in scriptsig is equal to public key hash in scriptpubkey
#             script_sig_list = ip['scriptsig_asm'].split(' ')
#             public_key = script_sig_list[len(script_sig_list) - 1]
#             scriptpubkey_pkh = asm_list[3]

#             sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).digest()
#             ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
#             scriptsig_pkh = ripemd160_hash.hex()

#             if scriptsig_pkh != scriptpubkey_pkh:
#                 # mismatch_pkh_transaction.append(transaction)
#                 print('invalid pkh')
#                 break

#             # # verify the signature
#             signature_der = script_sig_list[1][:len(script_sig_list[1]) - 2]

#             # step1: create the message (transaction hash)
#             sighash = script_sig_list[1][len(script_sig_list[1]) - 2:]
#             sighash += "000000"
            
#             if  transaction_hash == None or sighash != last_sighash_type:
#                 transaction_hash = gen_legacy_mssg(transaction, ip, sighash)
#                 last_sighash_type = sighash

#             print(transaction_hash)
#             # # step2: verify
#             try:
#                 verify_signature(public_key, transaction_hash, signature_der)
#                 print('valid sign')
#             except ecdsa.BadSignatureError:
#                 # invalid_txn.add(filename)
#                 print('invalid sign')
#                 break

#         # # #     # # check if the scriptpubkey_pkh gives the same scriptpubkey_addr on base58check encoding
#             pkh = "00"
#             pkh += scriptpubkey_pkh
#             pkh_byte = bytes.fromhex(pkh)

#             base58check_encoded = base58.b58encode_check(pkh_byte)
#             result = base58check_encoded.decode()

#             if result != ip["prevout"]["scriptpubkey_address"]:
#                 # invalid_txn.append(transaction)
#                 print('invalid address')
#                 break
#             else:
#                 print('valid addr')

# import hashlib

# def dsha256(message):
#     byte_value = bytes.fromhex(message)
#     first_hash = hashlib.sha256(byte_value).digest()
#     second_hash = hashlib.sha256(first_hash).digest()
#     return second_hash.hex()

# def merkle_root(tx_hashes):
#     if len(tx_hashes) == 0:
#         return None
#     elif len(tx_hashes) == 1:
#         return tx_hashes[0]

#     new_tx_hashes = []
#     for i in range(0, len(tx_hashes), 2):
#         if i < len(tx_hashes) - 1:
#             message = tx_hashes[i] + tx_hashes[i + 1]
#             new_tx_hashes.append(dsha256(message))
            
#         else:
#             message = tx_hashes[i] + tx_hashes[i]
#             new_tx_hashes.append(dsha256(message))

#     print(new_tx_hashes)
#     return merkle_root(new_tx_hashes)


# l1 = [
#     "0000000000000000000000000000000000000000000000000000000000000000",
#     "a28e549dc50610430bf7e224effd50db0662356780c934af0f1a9eb346d50087",
#     "87cbcb26ef9618f1363c0b0ae62c3ab6de1daf67fa6404c416a4d36059ab4bc5",
#     "85770dfeb29679fdb24e7ca87ca7d162962f6247269282f155f99e0061e31de5"
# ]

# print(merkle_root(l1))
from Crypto.Hash import RIPEMD160
data_bytes = bytes.fromhex('a28e549dc50610430bf7e224effd50db0662356780c934af0f1a9eb346d50087')
h = RIPEMD160.new(data_bytes)
print(h.hexdigest())




