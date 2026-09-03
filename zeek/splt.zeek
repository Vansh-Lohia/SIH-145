##! Per-packet SPLT logger for the encrypted-session detector.
##!
##! Zeek's conn.log gives only aggregate byte/packet counts. The shape/timing (SPLT)
##! feature family (CLAUDE.md §6.2) needs the first N packets of each flow as
##! (size, direction, inter-arrival). This script records exactly that, passively, from
##! the packets Zeek already sees — no extra capture, no outbound anything.
##!
##! Emits splt.log: one row per recorded packet, keyed by the connection uid so
##! ingest/zeek_reader.py can rebuild the per-session sequence and join it to ssl.log.

module SPLT;

export {
    redef enum Log::ID += { LOG };

    ## Cap packets recorded per connection. N=20 is the detector's default decision window
    ## (CLAUDE.md §4; open item §11 tests 20 vs 30) — record a few extra for headroom.
    const max_packets = 30 &redef;

    type Info: record {
        ts:      time    &log;   ## packet timestamp
        uid:     string  &log;   ## connection uid (joins conn.log / ssl.log)
        seq:     count   &log;   ## 0-based index of this packet within the flow
        len:     count   &log;   ## IP total length (bytes on the wire, content opaque)
        is_orig: bool    &log;   ## true = client->server (up), false = server->client (down)
    };
}

# per-connection packet counter
global counts: table[string] of count &default=0;

event zeek_init()
    {
    Log::create_stream(SPLT::LOG, [$columns=Info, $path="splt"]);
    }

event new_packet(c: connection, p: pkt_hdr)
    {
    local uid = c$uid;
    if ( counts[uid] >= max_packets )
        return;

    # IPv4 or IPv6 length; skip non-IP packets defensively.
    local len: count = 0;
    if ( p?$ip )
        len = p$ip$len;
    else if ( p?$ip6 )
        len = p$ip6$len;
    else
        return;

    local is_orig = p?$ip ? (p$ip$src == c$id$orig_h)
                          : (p?$ip6 ? (p$ip6$src == c$id$orig_h) : T);

    Log::write(SPLT::LOG, [$ts=network_time(), $uid=uid, $seq=counts[uid],
                           $len=len, $is_orig=is_orig]);
    counts[uid] += 1;
    }

event connection_state_remove(c: connection)
    {
    delete counts[c$uid];
    }
