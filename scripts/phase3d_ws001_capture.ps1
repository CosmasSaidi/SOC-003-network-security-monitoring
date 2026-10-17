$ErrorActionPreference='Continue'
$etl='C:\Windows\Temp\soc003-p3d-ws001-dc1.etl'
$pcap='C:\Windows\Temp\soc003-p3d-ws001-dc1.pcapng'
$log='C:\Windows\Temp\soc003-p3d-capture-run.txt'
function W($t){$t|Out-String|Tee-Object -FilePath $log -Append}
W "### PRE_CAPTURE"
W (pktmon list)
W "filters_before:"; W (pktmon filter list)
W "status_before:";  W (pktmon status)
W "### FILTERS"
W (pktmon filter remove)
W (pktmon filter add ws001-dc1-pair -i 192.168.56.102 192.168.56.10)
W (pktmon filter add ws001-dns-dc1 -t UDP -p 53 -i 192.168.56.10)
W "filters_now:"; W (pktmon filter list)
W "### START"
W ("capture_begin_ts="+(Get-Date -Format o))
W (pktmon start --capture --comp 9 --pkt-size 0 --file-name $etl)
Start-Sleep -Seconds 2
W (pktmon status)
W "### WAVE1_SECURE_CHANNEL"
W ("wave1_ts="+(Get-Date -Format o))
W (& nltest.exe /sc_verify:soc002.local 2>&1)
W (& nltest.exe /sc_query:soc002.local 2>&1)
Start-Sleep -Seconds 8
W "### WAVE2_DNS_TO_DC1"
W ("wave2_ts="+(Get-Date -Format o))
W (Resolve-DnsName -Name soc002-dc1.soc002.local -Type A -ErrorAction SilentlyContinue)
W (Resolve-DnsName -Name _ldap._tcp.soc002.local -Type SRV -ErrorAction SilentlyContinue)
W (Resolve-DnsName -Name _kerberos._tcp.soc002.local -Type SRV -ErrorAction SilentlyContinue)
W (Resolve-DnsName -Name _gc._tcp.soc002.local -Type SRV -ErrorAction SilentlyContinue)
Start-Sleep -Seconds 8
W "### WAVE3_DC_DISCOVERY"
W ("wave3_ts="+(Get-Date -Format o))
W (& nltest.exe /dsgetdc:soc002.local 2>&1)
W (& whoami.exe /fqdn 2>&1)
W (& klist.exe 2>&1)
W (& klist.exe tgt 2>&1)
Start-Sleep -Seconds 8
W "### WAVE4_GPO_SYSVOL_WEF"
W ("wave4_ts="+(Get-Date -Format o))
W (& gpresult.exe /scope:computer /r 2>&1|Select-Object -First 25)
W (& wecutil.exe gs SOC002-WS001-Security 2>&1)
W (& net.exe use 2>&1)
Start-Sleep -Seconds 8
W "### WAVE5_CLOCK_OFFSET_AND_TIME"
W ("wave5_ts="+(Get-Date -Format o))
W (& w32tm.exe /stripchart /computer:192.168.56.10 /samples:3 /dataonly 2>&1)
W (& w32tm.exe /query /source 2>&1)
W (& w32tm.exe /query /status 2>&1)
W (Get-Service WinRM,W32Time,Dnscache|Select-Object Name,Status,StartType)
W "### HOLD_WINDOW"
W ("hold_begin_ts="+(Get-Date -Format o))
Start-Sleep -Seconds 60
W ("hold_end_ts="+(Get-Date -Format o))
W "### STOP"
W ("capture_end_ts="+(Get-Date -Format o))
W (pktmon stop)
Start-Sleep -Seconds 3
W (pktmon filter remove)
W "status_after_stop:"; W (pktmon status)
W "### FILES"
W (Get-Item $etl|Select-Object FullName,Length,LastWriteTime|Format-List)
W ("sha256_etl="+(Get-FileHash $etl -Algorithm SHA256).Hash)
W "### CONVERT"
W (pktmon etl2pcap $etl --out $pcap)
Start-Sleep -Seconds 2
W (Get-Item $pcap|Select-Object FullName,Length,LastWriteTime|Format-List)
W ("sha256_pcapng="+(Get-FileHash $pcap -Algorithm SHA256).Hash)
W "### DONE"
