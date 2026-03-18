#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         ICMP Traceroute Crafter  v4                          ║
║  Full IP/ICMP field control + fragmentation + raw modes      ║
╚══════════════════════════════════════════════════════════════╝

  Bit · Byte · Hex quick reference
  ─────────────────────────────────
   4 bit  = <1 byte  =  1 hex char
   8 bit  =  1 byte  =  2 hex chars
  16 bit  =  2 bytes =  4 hex chars
  32 bit  =  4 bytes =  8 hex chars
"""

import random, string, time, sys
import scapy.all as scapy
from scapy.utils import checksum
from scapy.layers.inet import IP, ICMP, Raw
from scapy.layers.l2 import Ether

MIN_PAYLOAD_DYNAMIC  = 48
MAX_PAYLOAD          = 2000
PAYLOAD_GROW_PER_HOP = 44

# ─────────────────────────────────────────────────────────────
#  ANSI color palette
#  Grammar:
#    CYAN       section headers / titles
#    YELLOW     field names / prompts / labels
#    WHITE_B    default values / hex values / important numbers
#    GREEN      success / accepted / OK / reply hits
#    RED        errors / warnings / bad checksum / no reply
#    MAGENTA    table borders / decorative lines
#    BLUE       info / notes / arrows
#    ORANGE     hop number / TTL / timing
#    RESET      back to terminal default
# ─────────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

CYAN    = "\033[96m"
YELLOW  = "\033[93m"
WHITE_B = "\033[97m"
GREEN   = "\033[92m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"
ORANGE  = "\033[38;5;208m"
GRAY    = "\033[90m"

def c(color, text):
    """Wrap text in color + reset."""
    return f"{color}{text}{RESET}"

def ok(text):    return c(GREEN,   f"  ✓  {text}")
def err(text):   return c(RED,     f"  ✗  {text}")
def warn(text):  return c(YELLOW,  f"  ⚠  {text}")
def arrow(text): return c(BLUE,    f"  →  {text}")
def info(text):  return c(GRAY,    f"  {text}")

# ─────────────────────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────────────────────

def src_ip():
    try:    return scapy.get_if_addr(scapy.conf.iface)
    except: return "127.0.0.1"

def section(title):
    bar = c(MAGENTA, "─" * 60)
    print(f"\n{bar}\n  {c(CYAN, BOLD + title + RESET)}\n{bar}")

def prompt(name, bits, def_hex, def_bin, def_dec, lo=None, hi=None, note=None):
    lo_s = f"  {c(GRAY,'min:')} {c(WHITE_B, 'h='+hex(lo)[2:].zfill(bits//4 or 1)+'  d='+str(lo))}" if lo is not None else ""
    hi_s = f"  {c(GRAY,'max:')} {c(WHITE_B, 'h='+hex(hi)[2:].zfill(bits//4 or 1)+'  d='+str(hi))}" if hi is not None else ""
    nt_s = f"\n  {c(BLUE, 'note: ' + note)}" if note else ""
    bit_info = c(GRAY, f"[{bits} bit = {bits//8 or '<1'} byte = {bits//4 or '<1'} hex]")
    hdr  = f"\n{c(YELLOW, name)}  {bit_info}"
    dfl  = f"  {c(GRAY,'default →')} {c(WHITE_B, f'hex={def_hex}  bin={def_bin}  dec={def_dec}')}"
    return input(f"{hdr}\n{dfl}{lo_s}{hi_s}{nt_s}\n  {c(CYAN,'→')} ").strip()

def parse_num(s, default, name, lo=None, hi=None):
    if not s: return default
    s = s.strip().replace(" ", "").lower()
    for base in (10, 16, 2):
        try:
            v = int(s.replace("0x", ""), base) if base == 16 else int(s, base)
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                print(warn(f"{name}={v} is outside standard range → using anyway"))
            return v
        except ValueError:
            pass
    print(err(f"Invalid {name} → using default {default}"))
    return default

def hex_to_bytes(s):
    clean = s.replace(" ", "").replace("0x", "")
    if not clean or not all(c in "0123456789abcdefABCDEF" for c in clean):
        return None
    try:    return bytes.fromhex(clean)
    except: return None

# colored table printer
def tbl(lines):
    for line in lines.split('\n'):
        # borders in magenta, content stays
        colored = (line
            .replace('┌', c(MAGENTA,'┌')).replace('┐', c(MAGENTA,'┐'))
            .replace('└', c(MAGENTA,'└')).replace('┘', c(MAGENTA,'┘'))
            .replace('├', c(MAGENTA,'├')).replace('┤', c(MAGENTA,'┤'))
            .replace('┬', c(MAGENTA,'┬')).replace('┴', c(MAGENTA,'┴'))
            .replace('┼', c(MAGENTA,'┼'))
            .replace('─', c(MAGENTA,'─'))
            .replace('│', c(MAGENTA,'│'))
        )
        print(colored)

# ─────────────────────────────────────────────────────────────
#  IP header helpers
# ─────────────────────────────────────────────────────────────

def ip_chksum(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts=b''):
    h = bytearray()
    h += bytes([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, 0, 0]) + src + dst + opts
    s = 0
    for i in range(0, len(h), 2):
        w = (h[i]<<8) + (h[i+1] if i+1 < len(h) else 0)
        s = (s+w & 0xffff) + ((s+w) >> 16)
    return ~s & 0xffff

def build_ip_hdr(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts, ck):
    h = bytearray([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, (ck>>8)&0xff, ck&0xff])
    h += src + dst + opts
    return bytes(h)

# ─────────────────────────────────────────────────────────────
#  Network helpers
# ─────────────────────────────────────────────────────────────

def resolve_mac(dst, src):
    lmac = scapy.get_if_hwaddr(scapy.conf.iface)
    _, _, nh = scapy.conf.route.route(dst)
    target = dst if nh in ("0.0.0.0", src) else nh
    print(info(f"Resolving MAC for {c(WHITE_B, target)} ..."))
    try:
        mac = scapy.getmacbyip(target)
        if mac:
            print(ok(f"MAC: {c(WHITE_B, mac)}"))
            return lmac, mac
    except Exception as e:
        print(err(f"MAC error: {e}"))
    print(arrow("fallback to broadcast"))
    return lmac, "ff:ff:ff:ff:ff:ff"

def send_frame(ip_bytes, lmac, rmac, timeout, wait_reply=False):
    pkt = Ether(src=lmac, dst=rmac, type=0x0800) / Raw(load=ip_bytes)
    if wait_reply:
        return scapy.srp(pkt, timeout=timeout, verbose=0, iface=scapy.conf.iface)
    scapy.sendp(pkt, verbose=0, iface=scapy.conf.iface)
    return None, None

# ─────────────────────────────────────────────────────────────
#  Common input helpers
# ─────────────────────────────────────────────────────────────

def ask_padding():
    if input(f"\n  {c(YELLOW,'Add padding bytes?')} (y/n) {c(GRAY,'[n]')}: ").strip().lower() not in ('y','yes'):
        return b''
    cnt = max(1, min(100, int(input(f"  {c(YELLOW,'Count')} {c(GRAY,'[4]')}: ") or 4)))
    b   = int((input(f"  {c(YELLOW,'Byte hex')} {c(GRAY,'[00]')}: ").strip() or "00"), 16) & 0xFF
    print(arrow(f"{cnt} × {c(WHITE_B, f'0x{b:02x}')}"))
    return bytes([b]) * cnt

def ask_trace_params():
    print()
    probes   = int(input(f"  {c(YELLOW,'Probes per hop')}  {c(GRAY,'[3]')}:   ") or 3)
    interval = float(input(f"  {c(YELLOW,'Interval s')}      {c(GRAY,'[0.6]')}: ") or 0.6)
    timeout  = float(input(f"  {c(YELLOW,'Timeout s')}       {c(GRAY,'[2.0]')}: ") or 2.0)
    max_hops = int(input(f"  {c(YELLOW,'Max hops')}        {c(GRAY,'[30]')}:  ") or 30)
    return probes, interval, timeout, max_hops

# ─────────────────────────────────────────────────────────────
#  Payload generator
# ─────────────────────────────────────────────────────────────

def gen_payload(n, ptype, pat=None):
    if n <= 0: return b''
    if ptype == 1: return bytes(random.randint(0,1) for _ in range(n))
    if ptype == 2: return bytes(random.randint(0,255) for _ in range(n))
    if ptype == 3:
        b = pat if isinstance(pat, int) else random.randint(0,255)
        print(arrow(f"repeat {c(WHITE_B, f'0x{b:02x}')}"))
        return bytes([b]) * n
    if ptype == 4:
        buf, v = bytearray(), 0
        for _ in range(n):
            buf.append(v % 256)
            op = random.choice(['+2','*2','/2','nop'])
            if   op == '+2':       v += 2
            elif op == '*2':       v *= 2
            elif op == '/2' and v: v //= 2
        return bytes(buf)
    if ptype == 5:
        pool = (string.ascii_letters + string.digits + string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(n))
    if ptype == 6:
        bs = ''.join(random.choice('01') for _ in range(n*8))
        for _ in range(random.randint(2,6)):
            p  = random.randint(0, n*8-100)
            rl = random.randint(16, 80)
            bs = bs[:p] + random.choice('01')*rl + bs[p+rl:]
        bs  = bs[:n*8]
        buf = bytearray(int(bs[j:j+8].ljust(8,'0'), 2) for j in range(0, len(bs), 8))
        print(arrow("bit stream pattern"))
        return bytes(buf)
    if ptype == 7:
        pair = random.choice([(0x55,0xAA),(0xA5,0x5A),(0xFF,0x00),
                               (0xF0,0x0F),(0xCC,0x33),(0xAB,0xCD)])
        print(arrow(f"hex-pair {c(WHITE_B, f'{pair[0]:02X} {pair[1]:02X}')} repeating"))
        return bytes(pair[j%2] for j in range(n))
    if ptype == 8:
        raw = input(f"  {c(YELLOW,'Custom hex payload')}: ").strip()
        b   = hex_to_bytes(raw)
        if not b:
            print(err("Invalid hex → falling back to random bytes"))
            return bytes(random.randint(0,255) for _ in range(n))
        b = b[:n] if len(b) >= n else (b * ((n+len(b)-1)//len(b)))[:n]
        print(arrow(f"custom payload {c(WHITE_B, str(len(b))+'B')}"))
        return b
    return b''

# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    # banner
    banner = f"""
{c(CYAN, BOLD)}╔══════════════════════════════════════════════════════════════╗{RESET}
{c(CYAN, BOLD)}║{RESET}  {c(WHITE_B, BOLD+'ICMP Traceroute Crafter  v4'+RESET)}                               {c(CYAN, BOLD)}║{RESET}
{c(CYAN, BOLD)}║{RESET}  {c(GRAY,'Full IP/ICMP field control + fragmentation + raw modes')}  {c(CYAN, BOLD)}║{RESET}
{c(CYAN, BOLD)}╚══════════════════════════════════════════════════════════════╝{RESET}

  {c(YELLOW, BOLD+'Bit · Byte · Hex quick reference'+RESET)}
  {c(MAGENTA,'─────────────────────────────────')}
  {c(GRAY,' 4 bit')}  {c(MAGENTA,'=')} {c(WHITE_B,'<1 byte')}  {c(MAGENTA,'=')}  {c(WHITE_B,'1 hex char')}
  {c(GRAY,' 8 bit')}  {c(MAGENTA,'=')} {c(WHITE_B,' 1 byte')}  {c(MAGENTA,'=')}  {c(WHITE_B,'2 hex chars')}
  {c(GRAY,'16 bit')}  {c(MAGENTA,'=')} {c(WHITE_B,' 2 bytes')} {c(MAGENTA,'=')}  {c(WHITE_B,'4 hex chars')}
  {c(GRAY,'32 bit')}  {c(MAGENTA,'=')} {c(WHITE_B,' 4 bytes')} {c(MAGENTA,'=')}  {c(WHITE_B,'8 hex chars')}
"""
    print(banner)

    # ── IP Header ────────────────────────────────────────────
    section("IP Header")

    version = parse_num(prompt("Version", 4, "4","0100","4", lo=4, hi=4), 4, "Version")
    ihl     = parse_num(prompt("IHL", 4, "5","0101","5", lo=5, hi=15,
                               note="5=20B(base only)  6=24B  7=28B ... 15=60B  |  "
                                    "max IHL=15 → 60B total = 20B base + 40B options"),
                        5, "IHL")
    dscp    = parse_num(prompt("DSCP", 6, "00","000000","0", lo=0, hi=63),  0, "DSCP")
    ecn     = parse_num(prompt("ECN",  2, "00","00","0",     lo=0, hi=3),   0, "ECN")
    ttl_start = parse_num(prompt("Starting TTL", 8, "01","00000001","1", lo=1, hi=255,
                                 note="1 byte  |  increments +1 per hop  |  "
                                      "common start: 1 (strict) or 64 (skip local hops)"),
                          1, "TTL start")

    tbl(f"""
  {c(YELLOW, BOLD+'Protocol number reference'+RESET)} {c(GRAY,'(8 bit = 1 byte = 2 hex chars)')}
  ┌──────┬──────┬─────────────────────────────────────────┐
  │ {c(YELLOW,'dec')}  │ {c(YELLOW,'hex')}  │ {c(YELLOW,'protocol')}                                │
  ├──────┼──────┼─────────────────────────────────────────┤
  │ {c(WHITE_B,'  1')}  │ {c(WHITE_B,'0x01')} │ {c(GREEN,'ICMP')}   Internet Control Message        │
  │ {c(WHITE_B,'  2')}  │ {c(WHITE_B,'0x02')} │ IGMP   Internet Group Management       │
  │ {c(WHITE_B,'  4')}  │ {c(WHITE_B,'0x04')} │ IPv4   IP-in-IP encapsulation          │
  │ {c(WHITE_B,'  6')}  │ {c(WHITE_B,'0x06')} │ TCP    Transmission Control Protocol   │
  │ {c(WHITE_B,' 17')}  │ {c(WHITE_B,'0x11')} │ UDP    User Datagram Protocol          │
  │ {c(WHITE_B,' 41')}  │ {c(WHITE_B,'0x29')} │ IPv6   IPv6 encapsulation              │
  │ {c(WHITE_B,' 47')}  │ {c(WHITE_B,'0x2F')} │ GRE    Generic Routing Encapsulation   │
  │ {c(WHITE_B,' 50')}  │ {c(WHITE_B,'0x32')} │ ESP    IPsec Encap Security Payload    │
  │ {c(WHITE_B,' 51')}  │ {c(WHITE_B,'0x33')} │ AH     IPsec Authentication Header     │
  │ {c(WHITE_B,' 58')}  │ {c(WHITE_B,'0x3A')} │ ICMPv6 ICMP for IPv6                   │
  │ {c(WHITE_B,' 89')}  │ {c(WHITE_B,'0x59')} │ OSPF   Open Shortest Path First        │
  │ {c(WHITE_B,'132')}  │ {c(WHITE_B,'0x84')} │ SCTP   Stream Control Transmission     │
  └──────┴──────┴─────────────────────────────────────────┘""")

    proto      = parse_num(prompt("Proto", 8, "01","00000001","1", lo=0, hi=255,
                                  note="1 byte  |  see table above"), 1, "Proto")
    ip_id_base = parse_num(prompt("IP ID base", 16, "0000","0"*16,"0", lo=0, hi=65535,
                                  note="2 bytes  |  increments per probe"), 0, "ID")

    src = input(f"\n  {c(YELLOW,'Src IP')}  {c(GRAY,'['+src_ip()+']')}: ").strip() or src_ip()
    dst = input(f"  {c(YELLOW,'Dst IP')}  {c(GRAY,'[8.8.8.8]')}:  ").strip() or "8.8.8.8"

    # ── IP Fragmentation ─────────────────────────────────────
    section("IP Fragmentation")
    print(info(f"Flags field is 3 bits: {c(WHITE_B,'[Reserved | DF | MF]')}"))
    reserved = 1 if input(f"\n  {c(YELLOW,'Reserved (evil) bit')} = 1? (y/n) {c(GRAY,'[n]')}: ").strip().lower() in ('y','yes') else 0
    df       = 1 if input(f"  {c(YELLOW,'Don\\'t Fragment (DF)')} = 1? (y/n) {c(GRAY,'[n]')}: ").strip().lower() in ('y','yes') else 0
    mf       = 1 if input(f"  {c(YELLOW,'More Fragments (MF)')} = 1? (y/n) {c(GRAY,'[n]')}: ").strip().lower() in ('y','yes') else 0
    frag_offset = parse_num(
        input(f"  {c(YELLOW,'Fragment offset')} (8-byte units) {c(GRAY,'[0]')}: ").strip() or "0",
        0, "FragOffset", lo=0, hi=65520)
    frag_offset = (frag_offset // 8) * 8
    ff = (((reserved<<2)|(df<<1)|mf) << 13) | (frag_offset // 8)
    print(arrow(f"flags {c(WHITE_B,f'R={reserved} DF={df} MF={mf}')}  "
                f"offset={c(WHITE_B,str(frag_offset))}  "
                f"ff={c(WHITE_B,f'0x{ff:04x}')}"))

    # ── IP Options ───────────────────────────────────────────
    tbl(f"""
  {c(YELLOW, BOLD+'IP Options'+RESET)}
  ┌─────────────────────────────────────────────────────┐
  │  {c(GRAY,'min')}  =  {c(WHITE_B,' 4B')}  {c(GRAY,'( 8 hex chars)')}                         │
  │  {c(GRAY,'max')}  =  {c(WHITE_B,'40B')}  {c(GRAY,'(80 hex chars)')}                         │
  │  {c(GRAY,'step')} =  {c(WHITE_B,' 4B')}  {c(GRAY,'(must be multiple of 4 — one IHL word)')} │
  │  {c(GRAY,'valid sizes:')} {c(WHITE_B,'4 8 12 16 20 24 28 32 36 40')} bytes     │
  │  {c(GRAY,'non-multiples are auto zero-padded to next 4B')}      │
  └─────────────────────────────────────────────────────┘""")

    ip_opts = b''
    if input(f"  {c(YELLOW,'Add IP options?')} (y/n) {c(GRAY,'[n]')}: ").strip().lower() in ('y','yes'):
        h = input(f"  {c(YELLOW,'Options hex')} {c(CYAN,'→')} ").strip().replace(" ","").replace("0x","").upper()
        if h and all(ch in "0123456789ABCDEF" for ch in h):
            try:
                ip_opts = bytes.fromhex(h)
                if len(ip_opts) > 40:
                    print(warn(f"Exceeds max 40B (got {len(ip_opts)}B) → truncating to 40B"))
                    ip_opts = ip_opts[:40]
                pad = (4 - len(ip_opts) % 4) % 4
                if pad:
                    ip_opts += b'\x00' * pad
                    print(arrow(f"Auto-padded +{pad}B → {c(WHITE_B,str(len(ip_opts))+'B')}: {c(WHITE_B,ip_opts.hex().upper())}"))
                else:
                    print(ok(f"Accepted {len(ip_opts)}B: {c(WHITE_B,h)}"))
                needed_ihl = 5 + len(ip_opts) // 4
                if needed_ihl != ihl:
                    print(warn(f"IHL conflict: you set IHL={ihl} ({ihl*4}B) but "
                               f"{len(ip_opts)}B options require IHL={needed_ihl} ({needed_ihl*4}B)"))
                    print(f"     {c(GREEN,'1.')} Auto-adjust IHL to {c(WHITE_B,str(needed_ihl))}  (correct)")
                    print(f"     {c(YELLOW,'2.')} Keep IHL={c(WHITE_B,str(ihl))}  (intentional mismatch on wire)")
                    if (input(f"  {c(CYAN,'→')} {c(GRAY,'[1]')}: ").strip() or "1") == "2":
                        print(arrow(f"Keeping IHL={c(WHITE_B,str(ihl))} ({ihl*4}B)  — mismatch intentional"))
                    else:
                        ihl = needed_ihl
                        print(arrow(f"IHL auto-adjusted to {c(WHITE_B,str(ihl))} ({ihl*4}B)"))
                else:
                    ihl = needed_ihl
                print(arrow(f"IHL={c(WHITE_B,str(ihl))}  ({ihl*4}B total = 20B base + {len(ip_opts)}B options)  {c(GRAY,'[IHL max=15=60B]')}"))
            except Exception as e:
                print(err(f"Error: {e} → no options added"))
        else:
            print(err("Invalid hex → no options added"))

    SRC, DST = scapy.inet_aton(src), scapy.inet_aton(dst)
    tos      = (dscp<<2)|ecn
    ip_opts_for_ck = ip_opts

    # ── Payload size (first ask) ──────────────────────────────
    print()
    _pl = input(f"  {c(YELLOW,'ICMP Payload size B')}  {c(GRAY,'[default 420B | 0 = empty]')}: ").strip()
    try:    payload_len = max(0, int(_pl)) if _pl else 420
    except: payload_len = 420
    print(arrow(f"{'empty payload' if payload_len == 0 else c(WHITE_B,str(payload_len)+'B')}  "
                f"{c(GRAY,'(can override again inside ICMP header section)')}"))

    # ── IP Checksum ──────────────────────────────────────────
    section("IP Checksum")
    print(info(f"{c(WHITE_B,'auto')}        = standard 20B header only (no options fed into calc)"))
    print(info(f"{c(WHITE_B,'auto+extra')}  = 20B header + N extra null bytes fed into calc"))
    print(info(f"             {c(GRAY,'→ result differs from correct by those extra bytes contribution')}"))
    print(info(f"{c(WHITE_B,'custom')}      = you supply the raw 16-bit value directly"))

    preview   = ip_chksum(version, ihl, tos, ihl*4+8+payload_len,
                          ip_id_base, ff, ttl_start, proto, SRC, DST, b'')
    opts_info = f"{len(ip_opts)}B = {ip_opts.hex().upper()}" if ip_opts else "none"
    print(f"\n  {c(GRAY,'preview (20B only)')} = {c(WHITE_B,f'0x{preview:04x}')}  "
          f"{c(GRAY,'|')}  ID base = {c(WHITE_B,f'0x{ip_id_base:04x}')}  "
          f"{c(GRAY,'|')}  opts = {c(BLUE,opts_info)}")

    cs_in = input(f"\n  {c(YELLOW,'Desired IP checksum')}  {c(GRAY,'[Enter = auto  |  or type custom hex]')}: ").strip()
    ip_custom, ip_ck_fixed, ip_opts_for_ck_extra = False, preview, 0

    if cs_in:
        try:
            ip_ck_fixed = int(cs_in.replace("0x",""), 16) & 0xFFFF
            ip_custom   = True
            print(arrow(f"custom {c(WHITE_B,f'0x{ip_ck_fixed:04x}')}"))
        except:
            print(err("Invalid → using auto"))
    else:
        ex_in = input(f"  {c(YELLOW,'Extra null bytes in IP checksum calc?')} {c(GRAY,'[0]')}: ").strip()
        try:    ip_opts_for_ck_extra = max(0, min(100, int(ex_in))) if ex_in else 0
        except: ip_opts_for_ck_extra = 0
        ip_opts_for_ck = b'\x00' * ip_opts_for_ck_extra
        ip_ck_fixed    = None
        print(arrow(f"auto{c(WHITE_B, f'  +{ip_opts_for_ck_extra}B extra null bytes') if ip_opts_for_ck_extra else ''}"))

    def get_ip_ck(tlen, cur_id, ttl_val):
        if ip_custom:
            return ip_ck_fixed
        return ip_chksum(version, ihl, tos, tlen, cur_id, ff, ttl_val, proto, SRC, DST, ip_opts_for_ck)

    # ── Protocol / body mode ─────────────────────────────────
    section("Protocol / Body")
    print(f"  {c(WHITE_B,'1.')}  {c(GREEN,'ICMP')}")
    print(f"  {c(WHITE_B,'2.')}  {c(YELLOW,'Raw hex')}  {c(GRAY,'(bytes placed after IP header, uses proto field set above)')}")
    print(f"  {c(WHITE_B,'3.')}  {c(MAGENTA,'IP Raw payload')}  {c(GRAY,'(reserved / non-standard proto — bare IP + raw body)')}")
    proto_sel  = (input(f"\n  {c(CYAN,'→')} {c(GRAY,'[1]')}: ").strip() or "1")
    use_raw    = (proto_sel == "2")
    use_ip_raw = (proto_sel == "3")

    # ════════════════════════════════════════════════════════
    #  RAW MODE
    # ════════════════════════════════════════════════════════
    if use_raw:
        section("Raw Payload Traceroute")
        print(info("Hex bytes placed directly after the IP header."))
        print(info(f"TTL increments per hop.  Any case: {c(WHITE_B,'deadBEEF / DEADBEEF / deadbeef')}"))
        print()
        raw_in    = input(f"  {c(YELLOW,'Raw hex')} {c(CYAN,'→')} ").strip()
        raw_bytes = hex_to_bytes(raw_in)
        if raw_bytes is None:
            print(err("Invalid hex → empty body"))
            raw_bytes, raw_in = b'', ""
        else:
            print(ok(f"Accepted: {c(WHITE_B,raw_in)}  ({len(raw_bytes)}B)"))

        padding = ask_padding()
        probes, interval, timeout, max_hops = ask_trace_params()
        body = raw_bytes + padding

        print(f"\n  {c(CYAN,'Traceroute')} to {c(WHITE_B,dst)}, "
              f"TTL start={c(ORANGE,str(ttl_start))}, "
              f"max {c(WHITE_B,str(max_hops))} hops, "
              f"{c(WHITE_B,str(probes))} probe(s)/hop\n")
        lmac, rmac = resolve_mac(dst, src)
        reached   = False

        for hop in range(1, max_hops + 1):
            ttl = ttl_start + hop - 1
            print(f"  {c(ORANGE, BOLD+f'Hop {hop:2d}'+RESET)}  {c(GRAY,f'(TTL={ttl})')}  ", end="", flush=True)
            for probe in range(1, probes + 1):
                cur_id = (ip_id_base + (hop-1)*probes + probe - 1) % 65536
                tlen   = ihl*4 + len(body)
                ck     = get_ip_ck(tlen, cur_id, ttl)
                hdr    = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl,
                                      proto, SRC, DST, ip_opts, ck)
                ans, _ = send_frame(hdr + body, lmac, rmac, timeout, wait_reply=True)
                if ans:
                    r   = ans[0][1]
                    rtt = (r.time - ans[0][0].sent_time) * 1000
                    rip = r[IP].src if IP in r else "?"
                    print(f"{c(GREEN,rip)}  {c(ORANGE,f'{rtt:.1f}ms')}  "
                          f"{c(GRAY,'IPck=')}{c(WHITE_B,f'0x{ck:04x}')}  ", end="", flush=True)
                    if IP in r and r[IP].src == dst:
                        reached = True
                else:
                    print(c(RED,"*  "), end="", flush=True)
                time.sleep(interval)
            print()
            if reached: break

        print(f"\n  {c(GREEN, BOLD+'✓  Destination reached!') if reached else c(RED,'→  Destination not reached.')}")
        print(f"\n  {c(CYAN,'Done.')}")
        return

    # ════════════════════════════════════════════════════════
    #  IP RAW PAYLOAD MODE
    # ════════════════════════════════════════════════════════
    if use_ip_raw:
        section("IP Raw Payload Traceroute  (reserved / non-standard protocol)")
        tbl(f"""  {c(YELLOW,'Reserved / unassigned protocol numbers (suggestions):')}
  ┌──────┬──────┬────────────────────────────────────────────┐
  │ {c(YELLOW,'dec')}  │ {c(YELLOW,'hex')}  │ {c(YELLOW,'status')}                                     │
  ├──────┼──────┼────────────────────────────────────────────┤
  │ {c(WHITE_B,'  0')}  │ {c(WHITE_B,'0x00')} │ HOPOPT  (reserved, rarely used)            │
  │ {c(WHITE_B,' 61')}  │ {c(WHITE_B,'0x3D')} │ any host internal protocol (unassigned)    │
  │ {c(WHITE_B,' 63')}  │ {c(WHITE_B,'0x3F')} │ any local network (unassigned)             │
  │ {c(WHITE_B,'143')}  │ {c(WHITE_B,'0x8F')} │ unassigned                                 │
  │ {c(WHITE_B,'253')}  │ {c(WHITE_B,'0xFD')} │ {c(GREEN,'RFC 3692 experiment / testing')}              │
  │ {c(WHITE_B,'254')}  │ {c(WHITE_B,'0xFE')} │ {c(GREEN,'RFC 3692 experiment / testing')}              │
  │ {c(WHITE_B,'255')}  │ {c(WHITE_B,'0xFF')} │ reserved                                   │
  └──────┴──────┴────────────────────────────────────────────┘
""")
        ip_raw_proto = parse_num(
            prompt("IP Proto for raw payload", 8, "FD","11111101","253",
                   lo=0, hi=255, note="reserved suggestions: 61 63 143 253 254 255"),
            253, "IP proto")

        print(info(f"Raw IP payload bytes (entire body after IP header)."))
        print(info(f"Any case: {c(WHITE_B,'deadBEEF / DEADBEEF / deadbeef')}"))
        print()
        raw_in    = input(f"  {c(YELLOW,'Raw hex')} {c(CYAN,'→')} ").strip()
        raw_bytes = hex_to_bytes(raw_in)
        if raw_bytes is None:
            print(err("Invalid hex → empty body"))
            raw_bytes, raw_in = b'', ""
        else:
            print(ok(f"Accepted: {c(WHITE_B,raw_in)}  ({len(raw_bytes)}B)"))

        padding = ask_padding()
        probes, interval, timeout, max_hops = ask_trace_params()
        body = raw_bytes + padding

        print(f"\n  {c(CYAN,'Traceroute')} to {c(WHITE_B,dst)}, "
              f"proto={c(MAGENTA,str(ip_raw_proto))} ({c(MAGENTA,f'0x{ip_raw_proto:02x}')}), "
              f"TTL start={c(ORANGE,str(ttl_start))}, "
              f"max {c(WHITE_B,str(max_hops))} hops, "
              f"{c(WHITE_B,str(probes))} probe(s)/hop\n")
        lmac, rmac = resolve_mac(dst, src)
        reached   = False

        for hop in range(1, max_hops + 1):
            ttl = ttl_start + hop - 1
            print(f"  {c(ORANGE, BOLD+f'Hop {hop:2d}'+RESET)}  {c(GRAY,f'(TTL={ttl})')}  ", end="", flush=True)
            for probe in range(1, probes + 1):
                cur_id = (ip_id_base + (hop-1)*probes + probe - 1) % 65536
                tlen   = ihl*4 + len(body)
                ck     = get_ip_ck(tlen, cur_id, ttl)
                hdr    = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl,
                                      ip_raw_proto, SRC, DST, ip_opts, ck)
                ans, _ = send_frame(hdr + body, lmac, rmac, timeout, wait_reply=True)
                if ans:
                    r   = ans[0][1]
                    rtt = (r.time - ans[0][0].sent_time) * 1000
                    rip = r[IP].src if IP in r else "?"
                    print(f"{c(GREEN,rip)}  {c(ORANGE,f'{rtt:.1f}ms')}  "
                          f"{c(GRAY,'IPck=')}{c(WHITE_B,f'0x{ck:04x}')}  ", end="", flush=True)
                    if IP in r and r[IP].src == dst:
                        reached = True
                else:
                    print(c(RED,"*  "), end="", flush=True)
                time.sleep(interval)
            print()
            if reached: break

        print(f"\n  {c(GREEN, BOLD+'✓  Destination reached!') if reached else c(RED,'→  Destination not reached.')}")
        print(f"\n  {c(CYAN,'Done.')}")
        return

    # ════════════════════════════════════════════════════════
    #  ICMP MODE
    # ════════════════════════════════════════════════════════
    section("ICMP Header")
    tbl(f"""  {c(YELLOW,'Type / Code reference')}
  ┌──────┬──────┬────────────────────────────────────────┐
  │ {c(YELLOW,'type')} │ {c(YELLOW,'code')} │ {c(YELLOW,'meaning')}                                │
  ├──────┼──────┼────────────────────────────────────────┤
  │ {c(WHITE_B,'  0')}  │ {c(WHITE_B,'  0')}  │ {c(GREEN,'Echo Reply')}                             │
  │ {c(WHITE_B,'  3')}  │ {c(WHITE_B,'0-15')} │ {c(RED,'Destination Unreachable')}                │
  │ {c(WHITE_B,'  8')}  │ {c(WHITE_B,'  0')}  │ {c(GREEN,'Echo Request (ping)')}                    │
  │ {c(WHITE_B,' 11')}  │ {c(WHITE_B,'  0')}  │ {c(YELLOW,'Time Exceeded (TTL expired)')}            │
  │ {c(WHITE_B,' 12')}  │ {c(WHITE_B,'  0')}  │ {c(YELLOW,'Parameter Problem')}                      │
  └──────┴──────┴────────────────────────────────────────┘
""")

    itype = parse_num(prompt("Type", 8, "08","00001000","8",  lo=0, hi=255, note="1 byte"), 8, "Type")
    icode = parse_num(prompt("Code", 8, "00","00000000","0",  lo=0, hi=255, note="1 byte"), 0, "Code")
    iid   = parse_num(prompt("ID",  16, "0001","0"*15+"1","1",lo=0, hi=65535, note="2 bytes"), 1, "ID")
    seqb  = parse_num(prompt("Seq base", 16, "0001","0"*15+"1","1", lo=0, hi=65535,
                             note="2 bytes — increments per probe"), 1, "Seq")

    # ── ICMP Checksum ────────────────────────────────────────
    section("ICMP Checksum")
    print(info(f"{c(WHITE_B,'auto')}        = standard checksum over ICMP header + payload"))
    print(info(f"{c(WHITE_B,'auto+extra')}  = checksum over ICMP header + payload + N extra null bytes"))
    print(info(f"             {c(GRAY,'→ result differs from correct; extra bytes NOT sent in packet')}"))
    print(info(f"{c(WHITE_B,'custom')}      = you supply the raw 16-bit value directly"))
    print(info(f"             {c(GRAY,'→ payload length may be adjusted to hit the target checksum')}"))

    ick_in = input(f"\n  {c(YELLOW,'Desired ICMP checksum')}  {c(GRAY,'[Enter = auto  |  or type custom hex]')}: ").strip()
    icmp_custom, icmp_ck_val, icmp_extra = bool(ick_in), None, 0
    prefer_odd = True

    if icmp_custom:
        try:
            icmp_ck_val = int(ick_in.replace("0x",""), 16) & 0xFFFF
            print(arrow(f"custom {c(WHITE_B,f'0x{icmp_ck_val:04x}')}"))
            parity = input(f"  {c(YELLOW,'Preferred parity for length adjustment')} (odd/even) {c(GRAY,'[odd]')}: ").strip().lower()
            prefer_odd = not parity.startswith('e')
        except:
            print(err("Invalid → auto"))
            icmp_custom = False
    else:
        ex_in = input(f"  {c(YELLOW,'Extra null bytes in ICMP checksum calc?')} {c(GRAY,'[0]')}: ").strip()
        try:    icmp_extra = max(0, min(100, int(ex_in))) if ex_in else 0
        except: icmp_extra = 0
        print(arrow(f"auto{c(WHITE_B, f'  +{icmp_extra}B extra null bytes') if icmp_extra else ''}"))

    # ── Payload size (second ask) ────────────────────────────
    cur_pl_label = 'empty' if payload_len == 0 else f'{payload_len}B'
    print(f"\n  {c(GRAY,'Payload size is currently')} {c(WHITE_B,cur_pl_label)}  {c(GRAY,'(set earlier)')}")

    if icmp_custom:
        print(arrow(f"Dynamic sizing active (start ~{c(WHITE_B,str(MIN_PAYLOAD_DYNAMIC)+'B')} + "
                    f"{c(WHITE_B,str(PAYLOAD_GROW_PER_HOP)+'B')}/hop, max {c(WHITE_B,str(MAX_PAYLOAD)+'B')}) "
                    f"for checksum fitting"))
        use_dynamic = True
    else:
        pl_ov = input(f"  {c(YELLOW,'ICMP Payload size B')}  "
                      f"{c(GRAY,f'[Enter = keep {cur_pl_label}  |  0 = empty  |  or new size]')}: ").strip()
        if pl_ov:
            try:
                payload_len = max(0, int(pl_ov))
                print(arrow(f"{'empty payload' if payload_len == 0 else c(WHITE_B,str(payload_len)+'B')}"))
            except:
                print(err(f"Invalid → keeping {cur_pl_label}"))
        else:
            print(arrow(f"keeping {c(WHITE_B,cur_pl_label)}"))
        use_dynamic = False

    # ── Payload type ─────────────────────────────────────────
    ptype, pat = 5, None
    if payload_len > 0 or use_dynamic:
        tbl(f"""
  {c(YELLOW, BOLD+'Payload type'+RESET)}
  ┌───┬──────────────────────────────────────────────────┐
  │ {c(WHITE_B,'1')} │ random bits     {c(GRAY,'(0 or 1 per byte)')}                │
  │ {c(WHITE_B,'2')} │ random hex      {c(GRAY,'(0x00–0xFF random bytes)')}         │
  │ {c(WHITE_B,'3')} │ repeat pattern  {c(GRAY,'(single byte repeated)')}           │
  │ {c(WHITE_B,'4')} │ arithmetic      {c(GRAY,'(incrementing with ops)')}          │
  │ {c(WHITE_B,'5')} │ mixed           {c(GRAY,'(printable ASCII + symbols)')}      │
  │ {c(WHITE_B,'6')} │ bit stream      {c(GRAY,'(random runs of 0s and 1s)')}       │
  │ {c(WHITE_B,'7')} │ hex pair        {c(GRAY,'(two-byte alternating pattern)')}   │
  │ {c(WHITE_B,'8')} │ custom hex      {c(GRAY,'(you supply the bytes)')}           │
  └───┴──────────────────────────────────────────────────┘""")
        try:    ptype = int(input(f"  {c(CYAN,'→')} {c(GRAY,'[5]')}: ").strip() or 5); ptype = ptype if 1<=ptype<=8 else 5
        except: ptype = 5
        if ptype == 3:
            try:    pat = int((input(f"  {c(YELLOW,'Pattern byte hex')} {c(GRAY,'[AA]')}: ").strip() or "AA"), 16) & 0xFF
            except: pat = 0xAA
    else:
        print(arrow("payload type skipped (empty payload)"))

    padding = ask_padding()
    probes, interval, timeout, max_hops = ask_trace_params()

    # summary
    print(f"\n  {c(CYAN, BOLD+'Traceroute Summary'+RESET)}")
    print(f"  {c(GRAY,'Destination')}  {c(WHITE_B,dst)}")
    print(f"  {c(GRAY,'TTL start')}    {c(ORANGE,str(ttl_start))}  →  max hop TTL = {c(ORANGE,str(ttl_start+max_hops-1))}")
    print(f"  {c(GRAY,'Max hops')}     {c(WHITE_B,str(max_hops))}  ×  {c(WHITE_B,str(probes))} probe(s)/hop")
    print(f"  {c(GRAY,'IP flags')}     R={c(WHITE_B,str(reserved))} DF={c(WHITE_B,str(df))} MF={c(WHITE_B,str(mf))}  "
          f"offset={c(WHITE_B,str(frag_offset))}")
    if ip_opts: print(f"  {c(GRAY,'IP opts')}      {c(BLUE,str(len(ip_opts))+'B: '+ip_opts.hex().upper())}")
    print()

    lmac, rmac = resolve_mac(dst, src)
    reached    = False

    for hop in range(1, max_hops + 1):
        ttl = ttl_start + hop - 1
        print(f"\n  {c(ORANGE, BOLD+f'Hop {hop:2d}'+RESET)}  {c(GRAY,f'TTL={ttl}')}")

        for probe in range(1, probes + 1):
            seq    = (seqb  + (hop-1)*probes + probe - 1) % 65536
            cur_id = (ip_id_base + (hop-1)*probes + probe - 1) % 65536

            # build payload
            if use_dynamic:
                pl_len  = min(MIN_PAYLOAD_DYNAMIC + (hop-1)*PAYLOAD_GROW_PER_HOP, MAX_PAYLOAD)
                payload = gen_payload(pl_len, ptype, pat)
            else:
                payload = gen_payload(payload_len, ptype, pat)

            # ICMP checksum
            icmp_base = bytes(ICMP(type=itype, code=icode, id=iid, seq=seq, chksum=0))
            reason    = ""

            if icmp_custom:
                desired = icmp_ck_val
                cur_sum = checksum(icmp_base + payload)
                if cur_sum != desired:
                    if len(payload) >= 2:
                        delta  = (cur_sum - desired) % 65536
                        last2  = int.from_bytes(payload[-2:], 'big')
                        new_l2 = (last2 - delta) % 65536
                        p2     = payload[:-2] + new_l2.to_bytes(2,'big')
                        if checksum(icmp_base + p2) == desired:
                            payload = p2; reason = "adj"
                    if reason != "adj":
                        cl, found = len(payload), False
                        for d in range(2, 201, 2):
                            for sign in [1, -1]:
                                nl = cl + sign*d
                                if nl < 40: continue
                                if (nl%2==1) == prefer_odd:
                                    p2 = gen_payload(nl, ptype, pat)
                                    if checksum(icmp_base + p2) == desired:
                                        payload = p2; reason = f"adj:{nl}"; found = True; break
                            if found: break
                fck = desired
            else:
                fck = checksum(icmp_base + payload + b'\x00' * icmp_extra)

            icmp_bytes = icmp_base[:2] + fck.to_bytes(2,'big') + icmp_base[4:] + payload + padding

            tlen   = ihl*4 + len(icmp_bytes)
            ip_ck  = get_ip_ck(tlen, cur_id, ttl)
            hdr    = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl,
                                  proto, SRC, DST, ip_opts, ip_ck)

            ans, _ = send_frame(hdr + icmp_bytes, lmac, rmac, timeout, wait_reply=True)

            tag = f"{c(GRAY,f'[{probe}/{probes}]')}"
            if ans:
                r   = ans[0][1]
                rtt = (r.time - ans[0][0].sent_time) * 1000
                rip = r[IP].src if IP in r else "?"
                print(f"    {tag}  {c(GREEN,rip)}  {c(ORANGE,f'{rtt:.1f}ms')}"
                      f"  {c(GRAY,'IPck=')}{c(WHITE_B,f'0x{ip_ck:04x}')}"
                      f"  {c(GRAY,'ICMPck=')}{c(WHITE_B,f'0x{fck:04x}')}"
                      f"  {c(GRAY,'ID=')}{c(WHITE_B,f'0x{cur_id:04x}')}"
                      f"  {c(GRAY,'pay=')}{c(WHITE_B,str(len(payload))+'B')}"
                      f"{c(BLUE,f'  [{reason}]') if reason else ''}")

                if ICMP in r:
                    ck_ok   = checksum(bytes(r[ICMP])) == 0
                    recv_pl = bytes(r[ICMP].payload) if r[ICMP].payload else b''
                    match   = recv_pl == payload
                    ck_str  = c(GREEN,'OK') if ck_ok else c(RED,'BAD')
                    mt_str  = c(GREEN,'YES') if match else c(RED,f'NO  (sent {len(payload)}B  recv {len(recv_pl)}B)')
                    print(f"         {c(CYAN,'↳')}  ck={ck_str}  match={mt_str}", end="")
                    if itype == 8 and r[ICMP].type == 0:
                        print(f"  {c(GREEN, BOLD+'← dst reached'+RESET)}", end="")
                        reached = True
                    print()
            else:
                print(f"    {tag}  {c(RED,'*  (no reply)')}"
                      f"  {c(GRAY,'IPck=')}{c(WHITE_B,f'0x{ip_ck:04x}')}"
                      f"  {c(GRAY,'ICMPck=')}{c(WHITE_B,f'0x{fck:04x}')}"
                      f"  {c(GRAY,'ID=')}{c(WHITE_B,f'0x{cur_id:04x}')}")

            time.sleep(interval)

        if reached: break

    print(f"\n  {c(GREEN, BOLD+'✓  Destination reached!') if reached else c(RED,'→  Destination not reached.')}")
    print(f"\n  {c(CYAN,'Done.')}")


if __name__ == "__main__":
    try:    main()
    except KeyboardInterrupt: print(f"\n\n  {c(YELLOW,'Stopped.')}")
    except Exception as e:    print(f"\n  {c(RED,'Error:')} {e}", file=sys.stderr)
