##! SOC-003 Phase 2 -- DET-203: Periodic HTTP Behaviour.
##!
##! CONSERVATIVE STATEMENT OF WHAT THIS DETECTS
##! -------------------------------------------
##! One source making repeated HTTP requests to the same destination at a
##! regular inter-arrival interval (low jitter).
##!
##! This describes "periodic / beacon-like HTTP behaviour". It is NOT a claim of
##! command-and-control. Periodicity is a *shape*; benign software (health
##! checks, telemetry agents, RSS pollers, monitoring) is frequently periodic by
##! design. Periodicity ALONE is insufficient to establish C2, and this
##! detection must never be reported as C2 without corroborating evidence
##! (payload content, destination reputation, host-side telemetry, unusual
##! destination, etc.).
##!
##! DATA SOURCE
##! -----------
##! `http.log` (Zeek HTTP framework) via the `http_request` event, keyed on the
##! (source, destination) pair.
##!
##! LOGIC
##! -----
##! Keep the inter-arrival intervals between consecutive requests for each
##! (source, destination) pair. Once at least `det203_min_intervals` intervals
##! exist, compute the mean and the population standard deviation and derive the
##! coefficient of variation CV = stdev / mean. Fire when the mean interval is
##! inside a plausible "periodic" band AND CV is at or below the tolerance.
##!
##! THRESHOLDS (see ../../detections/README.md)
##!   min intervals      4   (i.e. >= 5 requests -> 4 intervals)
##!   mean interval      5 s .. 600 s
##!   CV tolerance   <=  0.05 (<= 5 % relative jitter)

@load base/frameworks/notice
@load ./det-common

module Phase2Det;

export {
	redef enum Notice::Type += {
		## Low-jitter repeated HTTP requests from one source to one destination.
		DET_203_Periodic_HTTP,
	};

	const det203_min_intervals: count = 4 &redef;
	const det203_min_mean: double = 5.0 &redef;
	const det203_max_mean: double = 600.0 &redef;
	const det203_cv_tolerance: double = 0.05 &redef;
}

type Det203_State: record {
	have_first: bool &default=F;
	first: time &default=double_to_time(0.0);
	have_last: bool &default=F;
	last: time &default=double_to_time(0.0);
	requests: count &default=0;
	intervals: vector of double &default=vector();
	reported: bool &default=F;
};

global det203_state: table[addr, addr] of Det203_State &create_expire=1hr;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
	local src = c$id$orig_h;
	local dst = c$id$resp_h;
	local now = network_time();

	if ([src, dst] !in det203_state) det203_state[src, dst] = Det203_State();
	local st = det203_state[src, dst];

	if (! st$have_first) {
		st$have_first = T;
		st$first = now;
	}
	if (st$have_last) st$intervals += interval_to_double(now - st$last);
	st$have_last = T;
	st$last = now;
	st$requests += 1;

	# Bound memory: keep the window to the most recent 32 intervals.
	if (|st$intervals| > 64) {
		local trimmed: vector of double = vector();
		local keep_from = |st$intervals| - 32;
		for (i in st$intervals) if (i >= keep_from) trimmed += st$intervals[i];
		st$intervals = trimmed;
	}

	if (st$reported) return;
	if (|st$intervals| < det203_min_intervals) return;

	local n = |st$intervals|;
	local sum = 0.0;
	for (i in st$intervals) sum += st$intervals[i];
	local mean = sum / n;

	local acc = 0.0;
	for (i in st$intervals) acc += (st$intervals[i] - mean) * (st$intervals[i] - mean);
	local stdev = sqrt(acc / n);
	local cv = (mean > 0.0) ? (stdev / mean) : 0.0;

	if (mean < det203_min_mean || mean > det203_max_mean) return;
	if (cv > det203_cv_tolerance) return;

	st$reported = T;

	local observed = interval_to_double(st$last - st$first);

	NOTICE([$note=DET_203_Periodic_HTTP,
		$msg=fmt("DET-203 periodic HTTP behaviour: %d requests %s -> %s, mean interval %.3fs, CV %.4f",
		         st$requests, src, dst, mean, cv),
		$src=src,
		$dst=dst,
		$identifier=fmt("DET-203-%s-%s", src, dst),
		$suppress_for=0sec]);

	log_detection([
		$ts=now,
		$det_id="DET-203",
		$det_title="Periodic HTTP Behaviour",
		$src=src,
		$window_start=st$first,
		$dst_hosts=fmt("%s", dst),
		$request_count=st$requests,
		$mean_interval=mean,
		$stdev_interval=stdev,
		$cv=cv,
		$window_seconds=observed,
		$severity="low",
		$evidence=fmt("%d HTTP requests from %s to %s with %d intervals over %.1f s, mean %.3f s, population stdev %.6f s, CV %.5f (tolerance %.2f)",
		              st$requests, src, dst, n, observed, mean, stdev, cv, det203_cv_tolerance),
	]);
}
