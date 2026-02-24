#!/usr/bin/env python3
"""
ICMP Traceroute Crafter – dynamic payload size + response checking
- Starts with small payload, gradually increases up to ~500 bytes
- Tries to force custom checksum when requested
- Shows hop-by-hop replies like classic traceroute
"""
import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw
import time
import sys
import random
import string

MAX_PAYLOAD = 500
MIN_PAYLOAD = 16           # sensible minimum for most systems
PAYLOAD_STEP = 64          # increase by this much each "round"

def get_default_src_ip():
    try:
        return scapy.get_if_addr(scapy.conf.iface)
    except:
        return "127.0.0.1"

def prompt_field(name, bits, def_hex, def_bin, def_dec):
    example = f" (ex: hex={def_hex}, bin={def_bin}, dec={def_dec})"
    msg = f"{name} ({bits} bits) [default: hex={def_hex} | bin={def_bin} | dec={def_dec}]{example}\n→ "
    return input(msg).strip()

def parse_numeric(s, bits, default, field_name):
    if not s:
        return default
    s_clean = s.replace(" ", "").lower()
    try: return int(s_clean)
    except: pass
    try:
        if s_clean.startswith("0x"):
            return int(s_clean[2:], 16)
        return int(s_clean, 16)
    except: pass
    try: return int(s_clean, 2)
    except:
        print(f" Invalid {field_name} → using default {default}")
        return default

def print_icmp_reference():
    print("\nCommon ICMP types for traceroute:")
    print("  8/0 → Echo Request       (most common)")
    print(" 11/0 → Time Exceeded     (usual traceroute reply)")
    print("  3/* → Destination Unreachable\n")

def generate_payload(length, ptype):
    if length <= 0: return b''
    if ptype == 'numeric':
        pool = string.digits.encode()
    elif ptype == 'alphabetic':
        pool = string.ascii_letters.encode()
    else:
        pool = (string.ascii_letters + string.digits + string.punctuation).encode()
    return bytes(random.choice(pool) for _ in range(length))

def ask_for_padding():
    add = input("\nAdd padding between IP & ICMP? (y/n, default n): ").strip().lower()
    if add not in ['y','yes']:
        print(" → No padding")
        return None
    try:
        pad_len = max(1, min(100, int(input("Padding bytes (default 4): ") or 4)))
    except:
        pad_len = 4
    pad_val = input("Padding byte hex (default 00): ").strip() or "00"
    try:
        pad_byte = int(pad_val, 16) & 0xFF
    except:
        pad_byte = 0
    print(f" → {pad_len} bytes of 0x{pad_byte:02x}")
    return bytes([pad_byte]) * pad_len

def main():
    print("=== ICMP Traceroute Crafter – dynamic payload + response check ===\n")

    # ── IP Layer ────────────────────────────────────────
    print("IP Layer:")
    version = parse_numeric(prompt_field("Version",4,"4","0100","4"),4,4,"Version")
    ihl     = parse_numeric(prompt_field("IHL",4,"5","0101","5"),4,5,"IHL")
    dscp    = parse_numeric(prompt_field("DSCP",6,"00","000000","0"),6,0,"DSCP")
    ecn     = parse_numeric(prompt_field("ECN",2,"00","00","0"),2,0,"ECN")
    ttl_base= parse_numeric(prompt_field("Starting TTL",8,"01","00000001","1"),8,1,"TTL")
    proto   = parse_numeric(prompt_field("Protocol",8,"01","00000001","1"),8,1,"Protocol")
    ip_id   = parse_numeric(prompt_field("IP ID base",16,"0000","0000000000000000","0"),16,0,"ID")
    src     = input(f"Source IP [default {get_default_src_ip()}]: ").strip() or get_default_src_ip()
    dst     = input("Destination IP [default 8.8.8.8]: ").strip() or "8.8.8.8"

    # ── ICMP Layer ──────────────────────────────────────
    print("\nICMP Layer:")
    print_icmp_reference()
    icmp_type   = parse_numeric(prompt_field("Type",8,"08","00001000","8"),8,8,"Type")
    icmp_code   = parse_numeric(prompt_field("Code",8,"00","00000000","0"),8,0,"Code")
    identifier  = parse_numeric(prompt_field("Identifier",16,"0001","0000000000000001","1"),16,1,"ID")
    seq_base    = parse_numeric(prompt_field("Sequence base",16,"0001","0000000000000001","1"),16,1,"Seq")

    chksum_in = input("Desired checksum hex (empty = auto): ").strip()
    desired_chksum = None
    if chksum_in:
        try:
            desired_chksum = int(chksum_in.replace("0x",""), 16) & 0xFFFF
            print(f" → Trying to use custom checksum: {hex(desired_chksum)} (warning: very hard to achieve)")
        except:
            print(" Invalid checksum → using auto")

    # Payload style
    ptype = input("\nPayload type (numeric / alphabetic / mixed) [default mixed]: ").strip().lower()
    if ptype not in ['numeric','alphabetic','mixed']: ptype = 'mixed'

    inter_padding = ask_for_padding()

    # Traceroute-like parameters
    max_hops     = int(input("Max hops [default 30]: ") or 30)
    tries_per_hop= int(input("Probes per hop [default 3]: ") or 3)
    timeout      = float(input("Response timeout (s) [default 2]: ") or 2)
    base_interval= float(input("Interval between probes (s) [default 0.5]: ") or 0.5)

    print(f"\nTracing to {dst}  max hops={max_hops}  probes/hop={tries_per_hop}\n")

    reached_final = False

    for hop in range(1, max_hops + 1):
        print(f" Hop {hop:2d} ", end="", flush=True)

        ttl = ttl_base + hop - 1

        for probe in range(1, tries_per_hop + 1):
            seq = (seq_base + (hop-1)*tries_per_hop + probe - 1) % 65536

            # Dynamic payload size – increases slowly
            payload_len = MIN_PAYLOAD + (hop-1) * PAYLOAD_STEP
            payload_len = min(payload_len, MAX_PAYLOAD)

            payload = generate_payload(payload_len, ptype)

            icmp_base = ICMP(type=icmp_type, code=icmp_code, id=identifier, seq=seq, chksum=0)
            icmp = icmp_base / payload

            # Custom checksum attempt (rarely succeeds)
            if desired_chksum is not None:
                current = checksum(bytes(icmp))
                if current != desired_chksum:
                    print(f" (chksum {hex(current)} ≠ {hex(desired_chksum)})", end="")

            icmp.chksum = desired_chksum if desired_chksum is not None else None  # None = auto

            tos = (dscp << 2) | ecn
            ip = IP(version=version, ihl=ihl, tos=tos, ttl=ttl, proto=proto,
                    src=src, dst=dst, id=(ip_id + seq) % 65536)

            pkt = ip
            if inter_padding:
                pkt /= Raw(inter_padding)
            pkt /= icmp

            # Send & receive
            ans, _ = scapy.sr(pkt, timeout=timeout, verbose=0)

            if ans:
                resp = ans[0][1]
                rtt = (resp.time - ans[0][0].sent_time) * 1000  # ms
                who = resp.src

                # ── Response validation ───────────────────────────────
                resp_icmp = resp.getlayer(ICMP)
                checksum_ok = False
                payload_match = False

                if resp_icmp:
                    resp_bytes = bytes(resp_icmp)
                    checksum_ok = checksum(resp_bytes) == 0

                sent_pl = bytes(pkt[ICMP].payload)
                recv_pl = b''
                if resp.haslayer(ICMP) and resp[ICMP].haslayer(Raw):
                    recv_pl = bytes(resp[ICMP].payload)

                payload_match = (sent_pl == recv_pl)

                # ── Print result ──────────────────────────────────────
                print(f" {who}  {rtt:5.1f} ms", end="")
                if checksum_ok:
                    print("  ✓chksum", end="")
                else:
                    print("  ✗chksum", end="")

                if payload_match:
                    print("  ✓payload", end="")
                else:
                    print(f"  payload {len(recv_pl)}/{len(sent_pl)}", end="")

                print("", flush=True)

                # If we got echo reply → probably destination
                if icmp_type == 8 and resp_icmp and resp_icmp.type == 0:
                    reached_final = True
                    print(f"   ! Destination reached ({who})")
                    break

            else:
                print("  *", end=" ", flush=True)

            time.sleep(base_interval)

        if reached_final:
            break

        print()  # new line after all probes of this hop

    if not reached_final:
        print("\n Destination not reached within max hops.")

    print("\nFinished.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
