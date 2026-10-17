##! SOC-003 Phase 2 -- detection loader.
##!
##! Loads the three Phase 2 detections and their shared scaffolding.
##! Usage (offline replay):
##!
##!   /opt/zeek/bin/zeek -r <pcap> LogAscii::use_json=T \
##!       detections/zeek/phase2-load.zeek

@load ./det-common
@load ./det-201-service-discovery
@load ./det-202-dns-burst
@load ./det-203-periodic-http
