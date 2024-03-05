#!/bin/sh

# example of usage:
#./analyse.sh replies "/data/dnscap/andraste/andraste.ns.nic.cz.20120401.*" > anom_andraste_20120401.txt

REPLY=replies
QUERY=queries
WHOLE=whole

WINDOW=600
INTERVAL=600
AGGREG=8
GAMMAPAR="both"
THRESH=1.2
HASHCNT=25
SKETCHCNT=32

GRAPH_ANOMALY="~/source-code/dns-detect-flow-anomaly/scripts/graph-anomaly"
#GRAPH_INTERMEDIATE="~/source-code/dns-detect-flow-anomaly/scripts/graph-intermediate"

#dnsanalyzer -w 600  -i 600 -a 8 -p "both" -t 1.2 -P "srcIP" -c 25 -s 32 -g "/home/thanh/source-code/dns-anomaly-injection/dnsFloodNXDOMAIN/output"   > test_parse.txt                           #-G ${GRAPH_INTERMEDIAT>
#srcIP, dstIP, qname

if [ "x$1" = "x${REPLY}" ]; then
	POLICY="srcIP"
	ADDITIONAL="-q"
	COMMAND="mergecap $2 -w - | dnsanalyzer -w ${WINDOW} -i ${INTERVAL} -a ${AGGREG} -p ${GAMMAPAR} -t ${THRESH} -P ${POLICY} -c ${HASHCNT} -s ${SKETCHCNT} ${ADDITIONAL}"
	echo "#${COMMAND}"
	sh -c "${COMMAND}"
	echo ok
else if [ "x$1" = "x${QUERY}" ]; then
	POLICY="dstIP"
	ADDITIONAL="-q"
	COMMAND="mergecap $2 -w - | dnsanalyzer -w ${WINDOW} -i ${INTERVAL} -a ${AGGREG} -p ${GAMMAPAR} -t ${THRESH} -P ${POLICY} -c ${HASHCNT} -s ${SKETCHCNT} ${ADDITIONAL} -g ${GRAPH_ANOMALY} -G ${GRAPH_INTERMEDIATE}"
	echo "#${COMMAND}"
	sh -c "${COMMAND}"
else if [ "x$1" = "x${WHOLE}" ]; then
	POLICY="qname"
	COMMAND="mergecap $2 -w - | dnsanalyzer -w ${WINDOW} -i ${INTERVAL} -a ${AGGREG} -p ${GAMMAPAR} -t ${THRESH} -P ${POLICY} -c ${HASHCNT} -s ${SKETCHCNT} -g ${GRAPH_ANOMALY}" # -G ${GRAPH_INTERMEDIATE}  "
	echo "#${COMMAND}"
	sh -c "${COMMAND}"
else
	echo "Usage: $0 ${REPLY}|${QUERY}|${WHOLE} \"pcap_file_wildcard\""
fi
fi
fi
