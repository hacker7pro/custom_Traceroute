#!/usr/bin/env python3
"""
ICMP Traceroute Crafter – with full IP fragmentation control + custom IP options + IP checksum control
"""
import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw, IPOption
import time
import sys
import random
import string

MIN_PAYLOAD_DYNAMIC = 48
MAX_PAYLOAD = 2000
PAYLOAD_GROW_PER_HOP = 44

def get_default_src_ip():
    try:
        return scapy.get_if_addr(scapy.conf.iface)
    except:
        return "127.0.0.1"

def prompt_field(name, bits, def_val):
    max_val = (1 << bits) - 1
    min_val = 0

    def_hex = f"{def_val:X}".upper()
    def_bin = f"{def_val:0{bits}b}"
    def_dec = str(def_val)

    min_hex = f"{min_val:X}".upper()
    min_bin = f"{min_val:0{bits}b}"
    min_dec = str(min_val)

    max_hex = f"{max_val:X}".upper()
    max_bin = f"{max_val:0{bits}b}"
    max_dec = str(max_val)

    range_info = f" (min hex={min_hex}, bin={min_bin}, dec={min_dec}) (max hex={max_hex}, bin={max_bin}, dec={max_dec})"
    default_info = f"[default: hex={def_hex} | bin={def_bin} | dec={def_dec}]"

    msg = f"{name} ({bits} bits) {default_info}{range_info}\n→ "
    return input(msg).strip()

def parse_any_numeric(s, bits, default, field_name):
    if not s:
        return default
    s = s.replace(" ", "").lower()
    max_val = (1 << bits) - 1
    try:
        val = int(s)
        if 0 <= val <= max_val: return val
    except: pass
    try:
        if s.startswith("0x"): val = int(s[2:], 16)
        elif s.endswith("h"): val = int(s[:-1], 16)
        elif all(c in "0123456789abcdef" for c in s): val = int(s, 16)
        else: raise ValueError
        if 0 <= val <= max_val: return val
    except: pass
    try:
        if s.startswith("0b"): val = int(s[2:], 2)
        elif s.startswith("b"): val = int(s[1:], 2)
        elif all(c in "01" for c in s): val = int(s, 2)
        else: raise ValueError
        if 0 <= val <= max_val: return val
    except: pass
    print(f"Invalid {field_name} (0–{max_val}). Using default {default}.")
    return default

def print_icmp_reference():
    print("\nCommon ICMP:")
    print(" 8/0 → Echo Request")
    print("11/0 → Time Exceeded")
    print(" 3/* → Destination Unreachable\n")

def generate_payload(length, ptype_num, pattern_arg=None):
    if length <= 0: return b''
    if ptype_num == 1: return bytes(random.randint(0, 1) for _ in range(length))
    if ptype_num == 2: return bytes(random.randint(0, 255) for _ in range(length))
    if ptype_num == 3:
        b = pattern_arg if isinstance(pattern_arg, int) else random.randint(0, 255)
        return bytes([b]) * length
    if ptype_num == 4:
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
    if ptype_num == 5:
        pool = (string.ascii_letters + string.digits + string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(length))
    if ptype_num == 6:
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
    if ptype_num == 7:
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
    print(f" → {cnt} × 0x{b:02x}")
    return bytes([b]) * cnt

def parse_hex_bytes(prompt_text):
    print(prompt_text)
    hex_input = input("→ ").strip()
    try:
        hex_clean = hex_input.replace(" ", "").lower()
        bytes_data = bytes.fromhex(hex_clean)
        print(f" → Parsed {len(bytes_data)} bytes from hex")
        return bytes_data
    except ValueError:
        print("Invalid hex → using no options / empty payload fallback")
        return b''

def main():
    print("=== ICMP Traceroute Crafter – full fragmentation control + custom IP options ===\n")

    print("IP Layer:")
    version = parse_any_numeric(prompt_field("Version", 4, 4), 4, 4, "Version")
    ihl = parse_any_numeric(prompt_field("IHL", 4, 5), 4, 5, "IHL")
    print(f" → Header length will be {ihl * 4} bytes (IHL={ihl})")
    dscp = parse_any_numeric(prompt_field("DSCP", 6, 0), 6, 0, "DSCP")
    ecn = parse_any_numeric(prompt_field("ECN", 2, 0), 2, 0, "ECN")

    ip_options = b''
    add_options = input("\nAdd custom IP Options? (y/n) [default n]: ").strip().lower()
    if add_options in ['y', 'yes']:
        print("Enter IP options as hex (spaces allowed, e.g. '01 03 0a bb')")
        print("→ Min: 0 bytes (no options)   Max: usually 40 bytes (IHL≤15 → total header ≤60 B)")
        ip_options = parse_hex_bytes("Custom IP options hex")
        if ip_options:
            print(f" → Using {len(ip_options)} bytes of custom options")

    print("\nIP Fragmentation control:")
    reserved_input = input("Reserved bit (evil bit / bit 0) – set to 1? (y/n) [default n]: ").strip().lower()
    reserved = 1 if reserved_input in ['y','yes','1','true'] else 0
    df_input = input("Don't Fragment (DF) bit – set to 1? (y/n) [default n]: ").strip().lower()
    df = 1 if df_input in ['y','yes','1','true'] else 0
    mf_input = input("More Fragments (MF) bit – set to 1? (y/n) [default n]: ").strip().lower()
    mf = 1 if mf_input in ['y','yes','1','true'] else 0
    offset_str = input("Fragment Offset (in 8-byte units) [default 0]: ").strip() or "0"
    frag_offset = parse_any_numeric(offset_str, 13, 0, "Fragment Offset")
    frag_offset = (frag_offset // 8) * 8
    if frag_offset > 65520:
        print("Warning: Fragment offset too large → clamped to 65520")
        frag_offset = 65520

    ttl_start = parse_any_numeric(prompt_field("Starting TTL", 8, 64), 8, 64, "TTL")
    proto = parse_any_numeric(prompt_field("Proto", 8, 1), 8, 1, "Proto")
    ip_id_base = parse_any_numeric(prompt_field("IP ID base", 16, 0), 16, 0, "ID")
    src = input(f"Source IP [default {get_default_src_ip()}]: ").strip() or get_default_src_ip()
    dst = input("Destination IP [default 8.8.8.8]: ").strip() or "8.8.8.8"

    # ────────────────────────────────────────────────
    # Desired ICMP checksum
    # ────────────────────────────────────────────────
    chksum_str = input("\nDesired ICMP checksum hex (empty = auto): ").strip()
    use_custom = bool(chksum_str)
    desired = None
    prefer_odd = True

    if use_custom:
        try:
            desired = int(chksum_str.replace("0x",""), 16) & 0xFFFF
            print(f" → Custom ICMP checksum: {hex(desired)}")
            parity = input("Preferred parity when adjusting (odd/even) [default odd]: ").strip().lower()
            prefer_odd = not parity.startswith('e')
        except:
            print("Invalid checksum → auto mode")
            use_custom = False

    # ────────────────────────────────────────────────
    # IP checksum adjustment – new two-step prompt style
    # ────────────────────────────────────────────────
    ip_chksum_mode = "auto"
    ip_chksum_extra = 0

    if not use_custom:
        mode_choice = input("\nIP checksum calculation: default or default + extra bytes? (default/extra): ").strip().lower()
        if mode_choice in ["extra", "e"]:
            try:
                extra_str = input("Extra bytes for IP checksum calculation (0-100): ").strip()
                extra_val = int(extra_str)
                if 0 <= extra_val <= 100:
                    ip_chksum_extra = extra_val
                    ip_chksum_mode = "extra"
                    print(f"  → IP checksum calculation: default + {extra_val} extra bytes")
                else:
                    print("Value out of range → using default (no adjustment)")
            except:
                print("Invalid number → using default (no adjustment)")
        else:
            print("  → Using default IP checksum (no adjustment)")
    # ────────────────────────────────────────────────

    print("\nICMP Layer:")
    print_icmp_reference()
    itype = parse_any_numeric(prompt_field("Type", 8, 8), 8, 8, "Type")
    icode = parse_any_numeric(prompt_field("Code", 8, 0), 8, 0, "Code")
    iid = parse_any_numeric(prompt_field("Identifier", 16, 1), 16, 1, "ID")
    seqb = parse_any_numeric(prompt_field("Seq base", 16, 1), 16, 1, "Seq")

    print("\nPayload type (1–8):")
    print("1. random 0/1 bytes     2. full random      3. repeating byte")
    print("4. arithmetic seq       5. mixed chars      6. bit stream")
    print("7. repeating hex pair   8. custom hex payload")
    try:
        ptype = int(input("→ "))
        if not 1 <= ptype <= 8: ptype = 5
    except:
        ptype = 5

    pattern_byte = None
    custom_hex_payload = None

    if ptype == 3:
        p = input("Pattern byte hex (default AA): ").strip() or "AA"
        try: pattern_byte = int(p, 16) & 0xFF
        except: pattern_byte = 0xAA
    elif ptype == 8:
        print("\nEnter custom payload as hex (spaces or continuous, e.g. 'deadbeef' or 'de ad be ef')")
        hex_input = input("→ ").strip()
        try:
            hex_clean = hex_input.replace(" ", "").lower()
            custom_hex_payload = bytes.fromhex(hex_clean)
            print(f" → Custom payload accepted, length = {len(custom_hex_payload)} bytes")
        except ValueError:
            print("Invalid hex string → falling back to default random payload (type 5)")
            ptype = 5

    fixed_payload_len = None
    if ptype == 8 and custom_hex_payload is not None:
        print(" → Using exact length from custom hex payload")
    elif use_custom:
        print(f" → Dynamic size (start ~{MIN_PAYLOAD_DYNAMIC} B + growth + adjustment, max {MAX_PAYLOAD} B)")
    else:
        try:
            fixed_payload_len = int(input(f"\nFixed payload size (bytes) [default 420]: ") or 420)
            fixed_payload_len = max(32, fixed_payload_len)
            print(f" → Fixed size: {fixed_payload_len} bytes")
        except:
            fixed_payload_len = 420
            print(" → Using default 420 bytes")

    padding = ask_padding()
    max_hops = int(input("\nMax hops [default 30]: ") or 30)
    probes_per_hop = int(input("Probes per hop [default 3]: ") or 3)
    timeout = float(input("Timeout (s) [default 2.0]: ") or 2.0)
    interval = float(input("Interval (s) [default 0.6]: ") or 0.6)

    flags_bin = f"{reserved}{df}{mf}"
    print(f"\nTracing {dst} max {max_hops} hops {probes_per_hop} probes/hop")
    print(f"IP Flags: Reserved={reserved}, DF={df}, MF={mf} (binary: {flags_bin})")
    print(f"Fragment Offset: {frag_offset} (0x{frag_offset:04x})")
    if ip_options:
        print(f"Custom IP options: {len(ip_options)} bytes")
    print("")

    reached_dst = False
    for hop in range(1, max_hops + 1):
        ttl = ttl_start + hop - 1
        print(f"Hop {hop:2d} ", end="", flush=True)
        for probe in range(1, probes_per_hop + 1):
            seq = (seqb + (hop-1)*probes_per_hop + probe - 1) % 65536

            if ptype == 8 and custom_hex_payload is not None:
                payload = custom_hex_payload
                payload_len = len(payload)
                display_size = payload_len
            else:
                payload_len = MIN_PAYLOAD_DYNAMIC + (hop - 1) * PAYLOAD_GROW_PER_HOP if use_custom else fixed_payload_len
                payload_len = min(payload_len, MAX_PAYLOAD) if use_custom else payload_len
                payload = generate_payload(payload_len, ptype, pattern_byte)
                display_size = payload_len

            icmp_base = ICMP(type=itype, code=icode, id=iid, seq=seq, chksum=0)

            cur_sum = checksum(bytes(icmp_base / payload))
            reason = ""
            if use_custom and cur_sum != desired:
                found = False
                if len(payload) >= 2:
                    last2 = int.from_bytes(payload[-2:], 'big')
                    delta = (cur_sum - desired) % 65536
                    new_last = (last2 - delta) % 65536
                    payload = payload[:-2] + new_last.to_bytes(2, 'big')
                    if checksum(bytes(icmp_base / payload)) == desired:
                        found = True
                        reason = "adj"
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

            flags = (reserved << 2) | (df << 1) | mf
            tos = (dscp << 2) | ecn

            ip = IP(
                version=version,
                ihl=ihl,
                tos=tos,
                flags=flags,
                frag=frag_offset // 8,
                ttl=ttl,
                proto=proto,
                src=src,
                dst=dst,
                id=(ip_id_base + seq) % 65536,
                options=IPOption(ip_options) if ip_options else []
            )

            pkt = ip
            if padding: pkt /= Raw(padding)
            pkt /= icmp

            # Apply IP checksum adjustment when requested
            if not use_custom and ip_chksum_mode == "extra" and ip_chksum_extra > 0:
                del ip.chksum               # force recompute
                correct_chksum = ip.chksum
                new_chksum = (correct_chksum + ip_chksum_extra) & 0xFFFF
                ip.chksum = new_chksum
                reason += f" (IP chksum +{ip_chksum_extra})"

            try:
                ans, _ = scapy.sr(pkt, timeout=timeout, verbose=0)
            except Exception as e:
                print(f"Send error: {e}")
                continue

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
            print(" ", end="", flush=True)
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
