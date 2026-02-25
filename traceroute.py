#!/usr/bin/env python3
"""
ICMP Traceroute Crafter – summary output, full payload size respect, no 500 hardcode
- Fixed size mode uses exactly what user enters (e.g. 700 → shows /700)
- Dynamic mode caps at MAX_PAYLOAD=2000
- Only shows match status, no payload content printed
"""
import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw
import time
import sys
import random
import string

MIN_PAYLOAD_DYNAMIC = 48
MAX_PAYLOAD = 2000          # Increased – no arbitrary 500 limit
PAYLOAD_GROW_PER_HOP = 44

def get_default_src_ip():
    try:
        return scapy.get_if_addr(scapy.conf.iface)
    except:
        return "127.0.0.1"

def prompt_field(name, bits, def_hex, def_bin, def_dec):
    ex = f" (ex: hex={def_hex}, bin={def_bin}, dec={def_dec})"
    msg = f"{name} ({bits} bits) [default: hex={def_hex} | bin={def_bin} | dec={def_dec}]{ex}\n→ "
    return input(msg).strip()

def parse_numeric(s, bits, default, field_name):
    if not s: return default
    s = s.replace(" ", "").lower()
    try: return int(s)
    except: pass
    try:
        if s.startswith("0x"): return int(s[2:], 16)
        return int(s, 16)
    except: pass
    try: return int(s, 2)
    except:
        print(f"Invalid {field_name} → using {default}")
        return default

def print_icmp_reference():
    print("\nCommon ICMP:")
    print(" 8/0 → Echo Request")
    print("11/0 → Time Exceeded")
    print(" 3/* → Destination Unreachable\n")

def generate_payload(length, ptype_num, pattern_arg=None):
    if length <= 0: return b''
    if ptype_num == 1:
        return bytes(random.randint(0, 1) for _ in range(length))
    elif ptype_num == 2:
        return bytes(random.randint(0, 255) for _ in range(length))
    elif ptype_num == 3:
        b = pattern_arg if isinstance(pattern_arg, int) else random.randint(0, 255)
        return bytes([b]) * length
    elif ptype_num == 4:
        payload = bytearray()
        val = random.randint(0, 255)
        for _ in range(length):
            payload.append(val % 256)
            op = random.choice(['+1','+3','*2','//2','nop'])
            if op == '+1': val += 1
            elif op == '+3': val += 3
            elif op == '*2': val = (val * 2) & 0xFFFF
            elif op == '//2' and val: val //= 2
        return bytes(payload)
    elif ptype_num == 5:
        pool = (string.ascii_letters + string.digits + string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(length))
    elif ptype_num == 6:
        opt1 = bytes(random.randint(0, 1) for _ in range(length))
        bit_str = ''.join(f'{b:08b}' for b in opt1)
        if random.random() < 0.3:
            pos = random.randint(0, len(bit_str) - 80)
            flip = random.choice(['0','1'])
            run = random.randint(16, 64)
            bit_str = bit_str[:pos] + flip * run + bit_str[pos+run:]
        payload = bytearray()
        for i in range(0, len(bit_str), 8):
            chunk = bit_str[i:i+8].ljust(8, '0')
            payload.append(int(chunk, 2))
        return bytes(payload)
    elif ptype_num == 7:
        pairs = [(0x55,0xAA),(0xA5,0x5A),(0xFF,0x00),(0xF0,0x0F),
                 (0xCC,0x33),(0xAA,0x55),(0x5A,0xA5),(0x00,0xFF)]
        p = random.choice(pairs)
        payload = bytearray()
        for j in range(length):
            payload.append(p[j % 2])
        return bytes(payload)
    return b''

def ask_padding():
    ans = input("\nAdd padding IP→ICMP? (y/n) [default n]: ").strip().lower()
    if ans not in ['y','yes']: return None
    try: cnt = max(1, min(80, int(input("Count (default 4): ") or 4)))
    except: cnt = 4
    val = input("Byte hex (default 00): ").strip() or "00"
    try: b = int(val, 16) & 0xFF
    except: b = 0
    print(f"  → {cnt} × 0x{b:02x}")
    return bytes([b]) * cnt

def main():
    print("=== ICMP Traceroute Crafter – full size respect ===\n")

    # IP Layer
    print("IP Layer:")
    version = parse_numeric(prompt_field("Version",4,"4","0100","4"),4,4,"Version")
    ihl     = parse_numeric(prompt_field("IHL",4,"5","0101","5"),4,5,"IHL")
    dscp    = parse_numeric(prompt_field("DSCP",6,"00","000000","0"),6,0,"DSCP")
    ecn     = parse_numeric(prompt_field("ECN",2,"00","00","0"),2,0,"ECN")
    ttl_start = parse_numeric(prompt_field("Starting TTL",8,"01","00000001","1"),8,1,"TTL")
    proto   = parse_numeric(prompt_field("Proto",8,"01","00000001","1"),8,1,"Proto")
    ip_id_base = parse_numeric(prompt_field("IP ID base",16,"0000","0000000000000000","0"),16,0,"ID")
    src     = input(f"Source IP [default {get_default_src_ip()}]: ").strip() or get_default_src_ip()
    dst     = input("Destination IP [default 8.8.8.8]: ").strip() or "8.8.8.8"

    # ICMP Layer
    print("\nICMP Layer:")
    print_icmp_reference()
    itype = parse_numeric(prompt_field("Type",8,"08","00001000","8"),8,8,"Type")
    icode = parse_numeric(prompt_field("Code",8,"00","00000000","0"),8,0,"Code")
    iid   = parse_numeric(prompt_field("Identifier",16,"0001","0000000000000001","1"),16,1,"ID")
    seqb  = parse_numeric(prompt_field("Seq base",16,"0001","0000000000000001","1"),16,1,"Seq")

    # Checksum decision
    chksum_str = input("\nDesired checksum hex (empty = auto): ").strip()
    use_custom = bool(chksum_str)
    desired = None
    prefer_odd = True
    fixed_payload_len = None

    if use_custom:
        try:
            desired = int(chksum_str.replace("0x",""), 16) & 0xFFFF
            print(f" → Custom checksum: {hex(desired)}")
            parity = input("Preferred parity when adjusting (odd/even) [default odd]: ").strip().lower()
            prefer_odd = not parity.startswith('e')
        except:
            print("Invalid checksum → auto mode")
            use_custom = False

    # Payload type
    print("\nPayload type (1–7):")
    print("1. random 0/1 bytes   2. full random   3. repeating byte")
    print("4. arithmetic seq     5. mixed chars   6. bit stream")
    print("7. repeating hex pair")
    try:
        ptype = int(input("→ "))
        if not 1 <= ptype <= 7: ptype = 5
    except:
        ptype = 5
    pattern_byte = None
    if ptype == 3:
        p = input("Pattern byte hex (default AA): ").strip() or "AA"
        try: pattern_byte = int(p, 16) & 0xFF
        except: pattern_byte = 0xAA

    # Size logic – fixed mode uses exactly user value
    if use_custom:
        print(f" → Dynamic size (start ~{MIN_PAYLOAD_DYNAMIC} B + growth + adjustment, max {MAX_PAYLOAD} B)")
    else:
        try:
            fixed_payload_len = int(input(f"\nFixed payload size (bytes) [default 420]: ") or 420)
            fixed_payload_len = max(32, fixed_payload_len)   # no upper cap – user decides
            print(f" → Fixed size: {fixed_payload_len} bytes")
        except:
            fixed_payload_len = 420
            print(" → Using default 420 bytes")

    padding = ask_padding()

    max_hops      = int(input("\nMax hops [default 30]: ") or 30)
    probes_per_hop= int(input("Probes per hop [default 3]: ") or 3)
    timeout       = float(input("Timeout (s) [default 2.0]: ") or 2.0)
    interval      = float(input("Interval (s) [default 0.6]: ") or 0.6)

    print(f"\nTracing {dst}  max {max_hops} hops  {probes_per_hop} probes/hop\n")

    reached_dst = False

    for hop in range(1, max_hops + 1):
        ttl = ttl_start + hop - 1
        print(f"Hop {hop:2d}  ", end="", flush=True)

        for probe in range(1, probes_per_hop + 1):
            seq = (seqb + (hop-1)*probes_per_hop + probe - 1) % 65536

            # Set current payload length
            if use_custom:
                payload_len = MIN_PAYLOAD_DYNAMIC + (hop - 1) * PAYLOAD_GROW_PER_HOP
                payload_len = min(payload_len, MAX_PAYLOAD)
            else:
                payload_len = fixed_payload_len

            icmp_base = ICMP(type=itype, code=icode, id=iid, seq=seq, chksum=0)
            payload = generate_payload(payload_len, ptype, pattern_byte)

            icmp = icmp_base / payload
            cur_sum = checksum(bytes(icmp))

            reason = ""
            display_size = payload_len

            if use_custom and cur_sum != desired:
                found = False
                # Try last 2 bytes adjustment
                if len(payload) >= 2:
                    last2 = int.from_bytes(payload[-2:], 'big')
                    delta = (cur_sum - desired) % 65536
                    new_last = (last2 - delta) % 65536
                    payload = payload[:-2] + new_last.to_bytes(2, 'big')
                    if checksum(bytes(icmp_base / payload)) == desired:
                        found = True
                        reason = "adj"

                # If still not, try length adjustment with parity
                if not found:
                    cl = len(payload)
                    for d in range(2, 201, 2):
                        for sign in [1, -1]:
                            nl = cl + sign * d
                            if nl < 40: continue
                            if (nl % 2 == 1) == prefer_odd:
                                payload = generate_payload(nl, ptype, pattern_byte)
                                if checksum(bytes(icmp_base / payload)) == desired:
                                    found = True
                                    display_size = nl
                                    reason = f"adj:{nl}"
                                    break
                        if found: break

            icmp = icmp_base / payload
            icmp.chksum = desired if use_custom else None

            tos = (dscp << 2) | ecn
            ip = IP(version=version, ihl=ihl, tos=tos, ttl=ttl, proto=proto,
                    src=src, dst=dst, id=(ip_id_base + seq) % 65536)

            pkt = ip
            if padding: pkt /= Raw(padding)
            pkt /= icmp

            ans, _ = scapy.sr(pkt, timeout=timeout, verbose=0)

            if ans:
                r = ans[0][1]
                rtt_ms = (r.time - ans[0][0].sent_time) * 1000
                who = r.src

                chksum_ok = r.haslayer(ICMP) and checksum(bytes(r[ICMP])) == 0
                payload_match = False
                recv_len = 0

                if r.haslayer(ICMP) and r[ICMP].haslayer(Raw):
                    recv_pl = bytes(r[ICMP].payload)
                    recv_len = len(recv_pl)
                    sent_pl = bytes(pkt[ICMP].payload)
                    payload_match = (sent_pl == recv_pl)

                print(f"{who} {rtt_ms:5.1f}ms", end="")
                print(f" {'✓' if chksum_ok else '✗'}chks", end="")
                if reason:
                    print(f" {reason}", end="")
                print(f" {'✓' if payload_match else f'{recv_len}/{display_size}'}", end="")

                if itype == 8 and r.haslayer(ICMP) and r[ICMP].type == 0:
                    print(" ←dst", end="")
                    reached_dst = True
            else:
                print("*", end="")

            print("  ", end="", flush=True)
            time.sleep(interval)

        print()

        if reached_dst:
            break

    if not reached_dst:
        print("\n→ Destination not reached.")

    print("\nDone.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
