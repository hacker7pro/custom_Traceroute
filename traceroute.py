#!/usr/bin/env python3
"""
ICMP Traceroute Crafter v2
– crafter-style prompts (hex/bin/dec) for every field
– exact send options (count, interval, timeout)
– full IP fragmentation + custom IP options
– manual IP checksum control (auto / custom / extra-bytes)
– manual ICMP checksum control (auto / custom / extra-bytes)
– padding support
– raw hex mode
– all 8 payload types
"""

import random, string, time, sys
import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw, IPOption
from scapy.layers.l2 import Ether

# ── constants ─────────────────────────────────────────────────────────────────
MIN_PAYLOAD_DYNAMIC   = 48
MAX_PAYLOAD           = 2000
PAYLOAD_GROW_PER_HOP  = 44

# ── helpers (crafter-style) ───────────────────────────────────────────────────

def src_ip():
    try:    return scapy.get_if_addr(scapy.conf.iface)
    except: return "127.0.0.1"

def prompt(name, bits, def_hex, def_bin, def_dec, lo=None, hi=None, note=None):
    lo_s = f" (min h={hex(lo)[2:].zfill(bits//4)} d={lo})" if lo is not None else ""
    hi_s = f" (max h={hex(hi)[2:].zfill(bits//4)} d={hi})" if hi is not None else ""
    nt_s = f" ({note})" if note else ""
    return input(
        f"{name} ({bits}b) [h={def_hex}|b={def_bin}|d={def_dec}]{lo_s}{hi_s}{nt_s}\n→ "
    ).strip()

def parse_num(s, default, name, lo=None, hi=None):
    if not s: return default
    s = s.strip().replace(" ", "").lower()
    for base in (10, 16, 2):
        try:
            v = (int(s.replace("0x",""), 16)
                 if base == 16 else int(s, base))
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                print(f"  Note: {name}={v} outside range → using anyway")
            return v
        except ValueError:
            pass
    print(f"  Invalid {name} → using {default}"); return default

def hex_to_bytes(s):
    clean = s.replace(" ","").replace("0x","")
    if not clean or not all(c in "0123456789abcdefABCDEF" for c in clean):
        return None
    try:    return bytes.fromhex(clean)
    except: return None

# ── IP checksum (manual) ──────────────────────────────────────────────────────

def ip_chksum_calc(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts=b''):
    h = bytearray()
    h += bytes([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, 0, 0]) + src + dst + opts
    s = 0
    for i in range(0, len(h), 2):
        w = (h[i]<<8) + (h[i+1] if i+1<len(h) else 0)
        s = (s+w & 0xffff) + ((s+w) >> 16)
    return ~s & 0xffff

def build_ip_hdr(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts, ck):
    h = bytearray([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, (ck>>8)&0xff, ck&0xff])
    h += src + dst + opts
    return bytes(h)

def resolve_mac(dst, src):
    lmac = scapy.get_if_hwaddr(scapy.conf.iface)
    _, _, nh = scapy.conf.route.route(dst)
    ip = dst if nh in ("0.0.0.0", src) else nh
    print(f"  Resolving MAC for {ip} ...")
    try:
        mac = scapy.getmacbyip(ip)
        if mac: print(f"  MAC: {mac}"); return lmac, mac
    except Exception as e: print(f"  MAC error: {e}")
    print("  → fallback broadcast"); return lmac, "ff:ff:ff:ff:ff:ff"

def send_frame(ip_bytes, lmac, rmac, timeout):
    pkt = Ether(src=lmac, dst=rmac, type=0x0800) / Raw(load=ip_bytes)
    return scapy.srp(pkt, timeout=timeout, verbose=0, iface=scapy.conf.iface)

# ── padding / send-params ─────────────────────────────────────────────────────

def ask_padding():
    if input("\nAdd padding? (y/n) [n]: ").strip().lower() not in ('y','yes'):
        return b''
    cnt = max(1, min(100, int(input("Count [4]: ").strip() or 4)))
    b   = int((input("Byte hex [00]: ").strip() or "00"), 16) & 0xFF
    print(f"  → {cnt}×0x{b:02x}"); return bytes([b])*cnt

def ask_send_params():
    count    = int(input("\nProbes per hop [3]: ").strip() or 3)
    interval = float(input("Interval s [0.6]: ").strip() or 0.6)
    timeout  = float(input("Timeout s [2.0]: ").strip() or 2.0)
    max_hops = int(input("Max hops [30]: ").strip() or 30)
    return count, interval, timeout, max_hops

# ── payload generator ─────────────────────────────────────────────────────────

def gen_payload(n, ptype, pat=None):
    if n <= 0: return b''
    if ptype == 1: return bytes(random.randint(0,1) for _ in range(n))
    if ptype == 2: return bytes(random.randint(0,255) for _ in range(n))
    if ptype == 3:
        b = pat if isinstance(pat,int) else random.randint(0,255)
        print(f"  → repeat 0x{b:02x}"); return bytes([b])*n
    if ptype == 4:
        buf, v = bytearray(), 0
        for _ in range(n):
            buf.append(v%256)
            op = random.choice(['+2','*2','/2','nop'])
            if op=='+2': v+=2
            elif op=='*2': v*=2
            elif op=='/2' and v: v//=2
        return bytes(buf)
    if ptype == 5:
        pool = (string.ascii_letters+string.digits+string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(n))
    if ptype == 6:
        bs = ''.join(random.choice('01') for _ in range(n*8))
        for _ in range(random.randint(2,6)):
            p=random.randint(0,n*8-100); rl=random.randint(16,80)
            bs=bs[:p]+random.choice('01')*rl+bs[p+rl:]
        bs=bs[:n*8]
        buf=bytearray(int(bs[j:j+8].ljust(8,'0'),2) for j in range(0,len(bs),8))
        print("  → bit stream"); return bytes(buf)
    if ptype == 7:
        p = random.choice([(0x55,0xAA),(0xA5,0x5A),(0xFF,0x00),(0xF0,0x0F),(0xCC,0x33),(0xAB,0xCD)])
        print(f"  → hex-pair {p[0]:02X}{p[1]:02X}")
        return bytes(p[j%2] for j in range(n))
    if ptype == 8:
        b = hex_to_bytes(input("Custom hex: ").strip())
        if not b: print("  → invalid → random"); return bytes(random.randint(0,255) for _ in range(n))
        b = b[:n] if len(b)>=n else (b*((n+len(b)-1)//len(b)))[:n]
        print(f"  → custom {len(b)}B"); return b
    return b''

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("=== ICMP Traceroute Crafter v2 ===")
    print("  Bit/Byte/Hex ref: 4b=<1B  8b=1B=2hex  16b=2B=4hex  32b=4B=8hex")
    print("─" * 60)

    # ── IP Header ──────────────────────────────────────────────
    print("\n── IP Header ──")
    version = parse_num(prompt("Version",4,"4","0100","4",lo=4,hi=4),             4,"Version")
    ihl     = parse_num(prompt("IHL",4,"5","0101","5",note="5=20B 6=24B 7=28B"),  5,"IHL")
    dscp    = parse_num(prompt("DSCP",6,"00","000000","0",lo=0,hi=63),             0,"DSCP")
    ecn     = parse_num(prompt("ECN",2,"00","00","0",lo=0,hi=3),                   0,"ECN")
    proto   = parse_num(prompt("Proto",8,"01","00000001","1",lo=0,hi=255,note="1B"),1,"Proto")
    ip_id_base = parse_num(prompt("IP ID base",16,"0000","0"*16,"0",lo=0,hi=65535,note="2B"),0,"ID")
    src     = input(f"Src IP [{src_ip()}]: ").strip() or src_ip()
    dst     = input("Dst IP [8.8.8.8]: ").strip() or "8.8.8.8"
    SRC, DST = scapy.inet_aton(src), scapy.inet_aton(dst)
    tos     = (dscp<<2)|ecn

    # TTL start (per-hop increment)
    ttl_start = parse_num(prompt("Starting TTL",8,"01","00000001","1",lo=1,hi=255,note="increments per hop"),1,"TTL start")

    # ── IP Fragmentation ───────────────────────────────────────
    print("\n── IP Fragmentation ──")
    reserved = 1 if input("Reserved (evil) bit = 1? (y/n) [n]: ").strip().lower() in ('y','yes') else 0
    df       = 1 if input("DF bit = 1? (y/n) [n]: ").strip().lower() in ('y','yes') else 0
    mf       = 1 if input("MF bit = 1? (y/n) [n]: ").strip().lower() in ('y','yes') else 0
    frag_offset = parse_num(
        input("Fragment offset (8-byte units) [0]: ").strip() or "0",
        0, "FragOffset", lo=0, hi=65520)
    frag_offset = (frag_offset // 8) * 8
    ff = ((reserved<<2)|(df<<1)|mf) << 13 | (frag_offset // 8)

    # ── IP Options ─────────────────────────────────────────────
    ip_opts = b''
    if input("\nAdd IP options? (y/n) [n]: ").strip().lower() in ('y','yes'):
        h = input("Options hex (mult of 4B, max 40B=80 hex chars): ").strip().replace(" ","").replace("0x","").upper()
        if h and all(c in "0123456789ABCDEF" for c in h) and len(h)//2 <= 40:
            try:
                ip_opts = bytes.fromhex(h)
                pad = (4 - len(ip_opts)%4)%4
                if pad: ip_opts += b'\x00'*pad; print(f"  → padded: {ip_opts.hex().upper()}")
                else:   print(f"  → accepted: {h}")
                ihl = 5 + len(ip_opts)//4
                print(f"  → IHL={ihl} ({ihl*4}B)")
            except Exception as e: print(f"  → error: {e}")
        else: print("  → invalid/too long → no options")

    # ── IP Checksum ────────────────────────────────────────────
    print("\n── IP Checksum ──")
    print("  1. Auto (correct)   2. Custom value   3. Auto + extra bytes")
    ip_ck_mode = (input("→ [1]: ").strip() or "1")
    ip_ck_custom_val  = None
    ip_ck_extra_bytes = 0

    if ip_ck_mode == "2":
        cs = input("Desired IP checksum hex [0x0000]: ").strip()
        try:
            ip_ck_custom_val = int(cs.replace("0x",""),16) & 0xFFFF
            print(f"  → custom 0x{ip_ck_custom_val:04x}")
        except: print("  → invalid → auto")
    elif ip_ck_mode == "3":
        try:
            ip_ck_extra_bytes = max(0, min(100, int(input("Extra bytes [0]: ").strip() or 0)))
            print(f"  → auto + {ip_ck_extra_bytes}B extra")
        except: pass

    def get_ip_ck(tlen, cur_id, ttl_val):
        if ip_ck_custom_val is not None:
            return ip_ck_custom_val
        # auto  = standard 20B header only (no opts)
        # extra = standard 20B header + extra null bytes appended into calc
        opts_for_ck = b'\x00' * ip_ck_extra_bytes
        return ip_chksum_calc(version, ihl, tos, tlen, cur_id, ff, ttl_val, proto, SRC, DST, opts_for_ck)

    # ── Protocol ───────────────────────────────────────────────
    print("\n── Protocol / Body ──\n  1. ICMP   2. Raw hex")
    use_raw = (input("→ [1]: ").strip() or "1") == "2"

    # ── RAW MODE ───────────────────────────────────────────────
    if use_raw:
        print("\nAny case accepted (deadBEEF / DEADBEEF / deadbeef)")
        raw_bytes = hex_to_bytes(input("Raw hex → ").strip())
        if raw_bytes is None:
            print("  → invalid → empty"); raw_bytes = b''

        padding = ask_padding()
        probes_per_hop, interval, timeout, max_hops = ask_send_params()

        print(f"\nTraceroute to {dst}, max {max_hops} hops, {probes_per_hop} probe(s)/hop\n")
        lmac, rmac = resolve_mac(dst, src)
        body = raw_bytes + padding

        reached_dst = False
        for hop in range(1, max_hops + 1):
            ttl  = ttl_start + hop - 1
            print(f"Hop {hop:2d} ", end="", flush=True)
            for probe in range(1, probes_per_hop + 1):
                cur_id = (ip_id_base + (hop-1)*probes_per_hop + probe - 1) % 65536
                tlen   = ihl*4 + len(body)
                ck     = get_ip_ck(tlen, cur_id, ttl)
                hdr    = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts, ck)
                ans, _ = send_frame(hdr + body, lmac, rmac, timeout)
                if ans:
                    r   = ans[0][1]
                    rtt = (r.time - ans[0][0].sent_time) * 1000
                    rip = r[IP].src if IP in r else "?"
                    print(f"{rip} {rtt:.1f}ms ", end="", flush=True)
                    if IP in r and r[IP].src == dst:
                        reached_dst = True
                else:
                    print("* ", end="", flush=True)
                time.sleep(interval)
            print()
            if reached_dst: break

        if not reached_dst: print("\n→ Destination not reached.")
        print("\nDone."); return

    # ── ICMP MODE ──────────────────────────────────────────────
    print("\n── ICMP Layer ──")
    print("  8/0=EchoReq  0/0=EchoRep  3/x=Unreach  11/0=TimeExc\n")
    itype = parse_num(prompt("Type",8,"08","00001000","8",lo=0,hi=255,note="1B"), 8,"Type")
    icode = parse_num(prompt("Code",8,"00","00000000","0",lo=0,hi=255,note="1B"), 0,"Code")
    iid   = parse_num(prompt("ID",16,"0001","0"*15+"1","1",lo=0,hi=65535,note="2B"),1,"ID")
    seqb  = parse_num(prompt("Seq base",16,"0001","0"*15+"1","1",lo=0,hi=65535,note="2B"),1,"Seq")

    # ── ICMP Checksum ──────────────────────────────────────────
    print("\n── ICMP Checksum ──")
    print("  1. Auto (correct)   2. Custom value   3. Auto + extra bytes")
    icmp_ck_mode = (input("→ [1]: ").strip() or "1")
    icmp_ck_custom_val  = None
    icmp_ck_extra_bytes = 0
    prefer_odd          = True

    if icmp_ck_mode == "2":
        cs = input("Desired ICMP checksum hex [0x0000]: ").strip()
        try:
            icmp_ck_custom_val = int(cs.replace("0x",""),16) & 0xFFFF
            print(f"  → custom 0x{icmp_ck_custom_val:04x}")
            parity = input("Parity when adjusting (odd/even) [odd]: ").strip().lower()
            prefer_odd = not parity.startswith('e')
        except: print("  → invalid → auto")
    elif icmp_ck_mode == "3":
        try:
            icmp_ck_extra_bytes = max(0, min(100, int(input("Extra bytes [0]: ").strip() or 0)))
            print(f"  → auto + {icmp_ck_extra_bytes}B extra")
        except: pass

    # ── Payload ────────────────────────────────────────────────
    print("\n── Payload ──")
    print("  1=rand-bits 2=rand-hex 3=repeat 4=arith 5=mixed 6=bits 7=hex-pair 8=custom")
    try:
        ptype = int(input("→ [5]: ").strip() or 5); ptype = ptype if 1<=ptype<=8 else 5
    except: ptype = 5
    pat = None
    if ptype == 3:
        try:    pat = int((input("Pattern byte [AA]: ").strip() or "AA"), 16) & 0xFF
        except: pat = 0xAA

    use_dynamic = False
    fixed_payload_len = 420
    if icmp_ck_custom_val is not None:
        print(f"  → Dynamic size (start ~{MIN_PAYLOAD_DYNAMIC}B + {PAYLOAD_GROW_PER_HOP}B/hop, max {MAX_PAYLOAD}B) for checksum fitting")
        use_dynamic = True
    elif ptype != 8:
        try:
            v = input(f"Fixed payload size B [420]: ").strip()
            fixed_payload_len = max(8, int(v or 420))
            print(f"  → {fixed_payload_len}B")
        except: fixed_payload_len = 420

    padding = ask_padding()
    probes_per_hop, interval, timeout, max_hops = ask_send_params()

    flags_str = f"R={reserved} DF={df} MF={mf}"
    print(f"\nTraceroute to {dst}, TTL start={ttl_start}, max {max_hops} hops, "
          f"{probes_per_hop} probe(s)/hop")
    print(f"IP Flags: {flags_str}  FragOffset={frag_offset}")
    if ip_opts: print(f"IP Options: {len(ip_opts)}B {ip_opts.hex().upper()}")
    print()

    lmac, rmac = resolve_mac(dst, src)
    reached_dst = False

    for hop in range(1, max_hops + 1):
        ttl = ttl_start + hop - 1
        print(f"Hop {hop:2d} (TTL={ttl}) ", end="", flush=True)

        for probe in range(1, probes_per_hop + 1):
            seq    = (seqb + (hop-1)*probes_per_hop + probe - 1) % 65536
            cur_id = (ip_id_base + (hop-1)*probes_per_hop + probe - 1) % 65536

            # build payload
            if ptype == 8 or not use_dynamic:
                payload = gen_payload(fixed_payload_len, ptype, pat)
            else:
                pl_len  = min(MIN_PAYLOAD_DYNAMIC + (hop-1)*PAYLOAD_GROW_PER_HOP, MAX_PAYLOAD)
                payload = gen_payload(pl_len, ptype, pat)

            # ICMP checksum
            icmp_base_bytes = bytes(ICMP(type=itype, code=icode, id=iid, seq=seq, chksum=0))
            reason = ""

            if icmp_ck_custom_val is not None:
                desired = icmp_ck_custom_val
                cur_sum = checksum(icmp_base_bytes + payload)
                if cur_sum != desired:
                    # try tail-word adjustment first
                    if len(payload) >= 2:
                        delta   = (cur_sum - desired) % 65536
                        last2   = int.from_bytes(payload[-2:], 'big')
                        new_l2  = (last2 - delta) % 65536
                        p2      = payload[:-2] + new_l2.to_bytes(2,'big')
                        if checksum(icmp_base_bytes + p2) == desired:
                            payload = p2; reason = "adj"
                    # length-sweep
                    if reason != "adj":
                        cl = len(payload)
                        found = False
                        for d in range(2, 201, 2):
                            for sign in [1, -1]:
                                nl = cl + sign*d
                                if nl < 40: continue
                                if (nl%2==1) == prefer_odd:
                                    p2 = gen_payload(nl, ptype, pat)
                                    if checksum(icmp_base_bytes + p2) == desired:
                                        payload = p2; reason = f"adj:{nl}"; found = True; break
                            if found: break
                fck = desired
            else:
                # extra-bytes: compute checksum over payload + extra null bytes,
                # but only the normal payload is actually sent in the packet
                fck = checksum(icmp_base_bytes + payload + b'\x00' * icmp_ck_extra_bytes)

            # ICMP bytes — packet contains only real payload (no extra bytes sent)
            ih = icmp_base_bytes
            icmp_bytes = ih[:2] + fck.to_bytes(2,'big') + ih[4:] + payload + padding

            # IP header
            tlen   = ihl*4 + len(icmp_bytes)
            ip_ck  = get_ip_ck(tlen, cur_id, ttl)
            hdr    = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts, ip_ck)

            ans, _ = send_frame(hdr + icmp_bytes, lmac, rmac, timeout)

            if ans:
                r   = ans[0][1]
                rtt = (r.time - ans[0][0].sent_time) * 1000
                rip = r[IP].src if IP in r else "?"
                print(f"{rip} {rtt:.1f}ms", end="")
                if ICMP in r:
                    ck_ok = checksum(bytes(r[ICMP])) == 0
                    print(f" {'✓' if ck_ok else '✗'}chks", end="")
                    if r[ICMP].type == 0 and itype == 8:
                        recv_pl = bytes(r[ICMP].payload)
                        match   = recv_pl == payload
                        print(f" {'✓' if match else f'pl?{len(recv_pl)}/{len(payload)}'}", end="")
                        print(" ←dst", end="")
                        reached_dst = True
                if reason: print(f" [{reason}]", end="")
                print(f"  IPck=0x{ip_ck:04x} ICMPck=0x{fck:04x} ID=0x{cur_id:04x}", end="")
            else:
                print("*", end="")
            print("  ", end="", flush=True)
            time.sleep(interval)

        print()
        if reached_dst: break

    if not reached_dst: print("\n→ Destination not reached.")
    print("\nDone.")

if __name__ == "__main__":
    try:    main()
    except KeyboardInterrupt: print("\nStopped.")
    except Exception as e:    print(f"Error: {e}", file=sys.stderr)
