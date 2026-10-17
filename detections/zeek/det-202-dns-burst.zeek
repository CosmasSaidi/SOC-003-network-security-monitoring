##! SOC-003 Phase 2 -- DET-202: DNS Burst / Unique Subdomain Behaviour.
##!
##! CONSERVATIVE STATEMENT OF WHAT THIS DETECTS
##! -------------------------------------------
##! One source emitting a high volume of DISTINCT DNS query names in a short
##! interval.
##!
##! This is deliberately NOT labelled DGA, DNS tunnelling or malicious DNS. A
##! burst of unique names is consistent with many benign behaviours (browser
##! page loads, CDN / long-tail resolution, software update checks, a monitoring
##! sweep, a mail server resolving many internal names). It is a volume/anomaly
##! observation that warrants a look -- nothing more.
##!
##! DATA SOURCE
##! -----------
##! `dns.log` (Zeek DNS framework) via the `dns_request` event.
##!
##! LOGIC
##! -----
##! Per source address, count DISTINCT query names inside a rolling window that
##! resets when the window is exceeded. Fire once per window when the distinct
##! count reaches the threshold. Repeated queries for the same name do not
##! accumulate, so ordinary repeated lookups do not fire.
##!
##! THRESHOLDS (see ../../detections/README.md)
##!   window            30 s
##!   unique qnames  >= 20

@load base/frameworks/notice
@load ./det-common

module Phase2Det;

export {
	redef enum Notice::Type += {
		## High-volume unique-subdomain DNS burst from one source.
		DET_202_DNS_Burst,
	};

	const det202_window: interval = 30sec &redef;
	const det202_min_unique_qnames: count = 20 &redef;
	const det202_sample_size: count = 8 &redef;
}

type Det202_State: record {
	started: bool &default=F;
	window_start: time &default=double_to_time(0.0);
	total_queries: count &default=0;
	qnames_seen: set[string] &default=set();
	qname_order: vector of string &default=vector();
	reported: bool &default=F;
};

global det202_state: table[addr] of Det202_State &create_expire=10min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
	local src = c$id$orig_h;
	local q = to_lower(query);
	if (|q| > 0 && q[|q| - 1] == ".") q = sub_bytes(q, 0, |q| - 1);
	if (|q| == 0) return;

	if (src !in det202_state) det202_state[src] = Det202_State();
	local st = det202_state[src];

	local now = network_time();

	if (st$started && now - st$window_start > det202_window)
		st$started = F;

	if (! st$started) {
		st$started = T;
		st$window_start = now;
		st$total_queries = 0;
		st$qnames_seen = set();
		st$qname_order = vector();
		st$reported = F;
	}

	st$total_queries += 1;
	if (q !in st$qnames_seen) {
		add st$qnames_seen[q];
		if (|st$qname_order| < det202_sample_size) st$qname_order += q;
	}

	if (st$reported) return;
	if (|st$qnames_seen| < det202_min_unique_qnames) return;

	st$reported = T;

	local window = interval_to_double(now - st$window_start);

	local sample = "";
	for (i in st$qname_order) {
		if (i > 0) sample += ",";
		sample += st$qname_order[i];
	}

	NOTICE([$note=DET_202_DNS_Burst,
		$msg=fmt("DET-202 DNS burst: %d unique query names (%d queries) from %s in %.1fs",
		         |st$qnames_seen|, st$total_queries, src, window),
		$src=src,
		$sub=sample,
		$identifier=fmt("DET-202-%s", src),
		$suppress_for=0sec]);

	log_detection([
		$ts=now,
		$det_id="DET-202",
		$det_title="DNS Burst / Unique Subdomain Behaviour",
		$src=src,
		$window_start=st$window_start,
		$unique_qnames=|st$qnames_seen|,
		$sample_qnames=sample,
		$window_seconds=window,
		$severity="low",
		$evidence=fmt("%d distinct DNS query names (%d total queries) from %s within a %.3f s window",
		              |st$qnames_seen|, st$total_queries, src, window),
	]);
}
