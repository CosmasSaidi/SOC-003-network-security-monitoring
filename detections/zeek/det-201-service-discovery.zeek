##! SOC-003 Phase 2 -- DET-201: Network Service Discovery Behaviour.
##!
##! CONSERVATIVE STATEMENT OF WHAT THIS DETECTS
##! -------------------------------------------
##! A single source producing a bounded burst of TCP connection attempts that
##! fail to complete normally (no reply, refused, or reset) across multiple
##! destination hosts AND multiple destination ports, inside a short window.
##!
##! This is the observable network signature of host/service enumeration. It is
##! NOT a claim about intent, tooling, or a specific attack. A benign inventory
##! tool, a load-balancer health checker probing many backends, or a
##! misconfigured client can produce the same shape.
##!
##! DATA SOURCE
##! -----------
##! `conn.log` (Zeek Conn framework) via the `connection_state_remove` event.
##!
##! LOGIC
##! -----
##! For each source address, accumulate connection attempts that terminated in a
##! non-established state ("probe attempts"). Reset the accumulator when the
##! observation window is exceeded. Fire once per window when all three
##! thresholds are met, then stay quiet for the remainder of that window.
##!
##! THRESHOLDS (see ../../detections/README.md for rationale and calibration)
##!   window       60 s
##!   attempts     >= 10 failed attempts
##!   ports        >=  5 distinct destination ports
##!   hosts        >=  2 distinct destination hosts
##!
##! Requires BOTH breadth (ports) and fan-out (hosts) in addition to volume, so
##! that a repeated retry loop against a single service does not fire.

@load base/frameworks/notice
@load ./det-common

module Phase2Det;

export {
	redef enum Notice::Type += {
		## Bounded multi-host / multi-port failed-TCP-probe burst from one source.
		DET_201_Service_Discovery,
	};

	const det201_window: interval = 60sec &redef;
	const det201_min_attempts: count = 10 &redef;
	const det201_min_ports: count = 5 &redef;
	const det201_min_hosts: count = 2 &redef;
}

# Conn states that mean "the attempt did not become a normal established session".
const det201_probe_states: set[string] = {
	"S0",   # SYN sent, no reply            (filtered / silently dropped)
	"S1",   # established, never properly closed
	"REJ",  # SYN answered with RST         (port refused)
	"RSTO", # handshake done, originator aborted with RST
	"RSTR", # handshake done, responder aborted with RST
	"OTH",  # mid-stream, no SYN observed
};

type Det201_State: record {
	started: bool &default=F;
	window_start: time &default=double_to_time(0.0);
	attempts: count &default=0;
	host_order: vector of addr &default=vector();
	port_order: vector of port &default=vector();
	hosts_seen: set[addr] &default=set();
	ports_seen: set[port] &default=set();
	reported: bool &default=F;
};

global det201_state: table[addr] of Det201_State &create_expire=10min;

function det201_join_hosts(v: vector of addr): string {
	local out = "";
	for (i in v) {
		if (i > 0) out += ",";
		out += fmt("%s", v[i]);
	}
	return out;
}

function det201_join_ports(v: vector of port): string {
	local out = "";
	for (i in v) {
		if (i > 0) out += ",";
		out += fmt("%s", v[i]);
	}
	return out;
}

event connection_state_remove(c: connection) {
	if (get_port_transport_proto(c$id$resp_p) != tcp) return;
	if (! (c$conn?$conn_state)) return;
	if (c$conn$conn_state !in det201_probe_states) return;

	local src = c$id$orig_h;
	if (src !in det201_state) det201_state[src] = Det201_State();
	local st = det201_state[src];

	# Window arithmetic uses the connection's OWN start time, not
	# network_time(): on offline replay Zeek removes un-established
	# connections lazily (when the next packet advances the clock past their
	# inactivity timeout), so network_time() would collapse a whole burst of
	# probes onto a single instant and destroy the time dimension.
	local now = c$start_time;

	# Roll over to a fresh window when the previous one has elapsed.
	if (st$started && now - st$window_start > det201_window)
		st$started = F;

	if (! st$started) {
		st$started = T;
		st$window_start = now;
		st$attempts = 0;
		st$host_order = vector();
		st$port_order = vector();
		st$hosts_seen = set();
		st$ports_seen = set();
		st$reported = F;
	}

	st$attempts += 1;
	if (c$id$resp_h !in st$hosts_seen) {
		add st$hosts_seen[c$id$resp_h];
		st$host_order += c$id$resp_h;
	}
	if (c$id$resp_p !in st$ports_seen) {
		add st$ports_seen[c$id$resp_p];
		st$port_order += c$id$resp_p;
	}

	if (st$reported) return;
	if (st$attempts < det201_min_attempts) return;
	if (|st$ports_seen| < det201_min_ports) return;
	if (|st$hosts_seen| < det201_min_hosts) return;

	st$reported = T;

	local window = interval_to_double(now - st$window_start);
	local hosts_s = det201_join_hosts(st$host_order);
	local ports_s = det201_join_ports(st$port_order);

	NOTICE([$note=DET_201_Service_Discovery,
		$msg=fmt("DET-201 network service discovery behaviour: %d failed TCP probes from %s to %d hosts / %d ports in %.1fs",
		         st$attempts, src, |st$hosts_seen|, |st$ports_seen|, window),
		$src=src,
		$sub=fmt("%s | %s", hosts_s, ports_s),
		$identifier=fmt("DET-201-%s", src),
		$suppress_for=0sec]);

	log_detection([
		$ts=network_time(),
		$det_id="DET-201",
		$det_title="Network Service Discovery Behaviour",
		$src=src,
		$window_start=st$window_start,
		$dst_hosts=hosts_s,
		$dst_ports=ports_s,
		$attempts=st$attempts,
		$unique_hosts=|st$hosts_seen|,
		$unique_ports=|st$ports_seen|,
		$window_seconds=window,
		$severity="medium",
		$evidence=fmt("%d non-established TCP connection attempts from %s to %d distinct hosts (%s) and %d distinct ports (%s) spanning %.3f s, measured between the first and the threshold-crossing attempt",
		              st$attempts, src, |st$hosts_seen|, hosts_s, |st$ports_seen|, ports_s, window),
	]);
}
