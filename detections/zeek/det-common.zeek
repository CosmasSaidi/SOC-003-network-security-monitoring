##! SOC-003 Phase 2 -- shared detection scaffolding.
##!
##! Defines the structured Phase 2 detection log stream (`phase2_detections`)
##! and the writer used by DET-201 / DET-202 / DET-203.
##!
##! Design notes
##! ------------
##! * One structured record per detection event, written with JSON ASCII output
##!   so that downstream tooling and investigations can consume it directly.
##! * Every field that would otherwise be an unordered `set` is emitted as a
##!   deterministic, comma-joined string built from an insertion-ordered
##!   `vector`, so repeated runs over the same PCAP produce identical records.

module Phase2Det;

export {
	redef enum Log::ID += { LOG };

	## One row per detection event.
	type Info: record {
		## Wall/network time of the detection.
		ts: time &log;
		## Detection identifier, e.g. "DET-201".
		det_id: string &log;
		## Human-readable detection title.
		det_title: string &log;
		## Source that triggered the detection.
		src: addr &log;
		## Comma-joined destination hosts observed (DET-201).
		dst_hosts: string &log &optional;
		## Comma-joined destination ports observed (DET-201).
		dst_ports: string &log &optional;
		## Number of qualifying probe attempts (DET-201).
		attempts: count &log &optional;
		## Distinct destination hosts contacted (DET-201).
		unique_hosts: count &log &optional;
		## Distinct destination ports contacted (DET-201).
		unique_ports: count &log &optional;
		## Start of the observation window the detection decision is based on.
		window_start: time &log &optional;
		## Length of the observation window in seconds (DET-201/DET-202).
		window_seconds: double &log &optional;
		## Distinct query names observed (DET-202).
		unique_qnames: count &log &optional;
		## Sample of query names, first-seen order (DET-202).
		sample_qnames: string &log &optional;
		## HTTP requests observed for the source/destination pair (DET-203).
		request_count: count &log &optional;
		## Mean inter-arrival interval, seconds (DET-203).
		mean_interval: double &log &optional;
		## Population standard deviation of intervals, seconds (DET-203).
		stdev_interval: double &log &optional;
		## Coefficient of variation (stdev/mean) (DET-203).
		cv: double &log &optional;
		## Analyst-facing severity hint (informational only).
		severity: string &log &optional;
		## Free-text analyst evidence summary.
		evidence: string &log;
	};

	## Write one structured detection record to `phase2_detections.log`.
	global log_detection: function(info: Info);
}

event zeek_init() &priority=5 {
	Log::create_stream(Phase2Det::LOG, [$columns=Info, $path="phase2_detections"]);
}

function log_detection(info: Info) {
	Log::write(Phase2Det::LOG, info);
}
