#!/bin/sh
#
# see README-testing for more information
# do some basic booth operation tests for the given config
#

PROG=`basename $0`
usage() {
	cat<<EOF
usage:

	[NETEM_ENV=<envfun>[:<val>]] $PROG <booth.conf> [<test> ...]

EOF
	if [ $1 -eq 0 ]; then
		list_all
		examples
	fi
	exit
}

list_all() {
	echo "Tests:"
	grep "^test_.*{$" $0 | sed 's/test_//;s/(.*//;s/^/	/'
	echo
	echo "Netem functions:"
	grep "^NETEM_ENV_.*{$" $0 | sed 's/NETEM_ENV_//;s/(.*//;s/^/	/'
}
examples() {
	cat<<EOF

Examples:

	$0 booth.conf
	$0 booth-5node.conf grant revoke
	NETEM_ENV=net_delay:150 $0 mybooth.conf

EOF
}

[ $# -eq 0 ] && usage 0

cnf=$1
shift 1
logf=test_booth.log
iprules=/usr/share/booth/tests/test/booth_path
: ${HA_LOGFACILITY:="syslog"}

logmsg() {
	logger -t "BOOTHTEST" -p $HA_LOGFACILITY.info -- "$@"
}

ext_prog_log() {
	local cmd="$@"
	echo "run: $cmd" >&2
	logmsg "$cmd"
	$cmd
}
get_stat_fld() {
	local fld=$1
	sed "s/.* $fld=//;s/ .*//;s/'//g"
}

# tc netem, simulate packet loss, wan, etc
netem_delay() {
	ext_prog_log tc qdisc add dev $1 root netem delay $2ms $(($2/10))ms
}
netem_loss() {
	ext_prog_log tc qdisc add dev $1 root netem loss $2%
}
netem_reset() {
	ext_prog_log tc qdisc del dev $1 root netem
}
local_netem_env() {
	local fun=$1 arg=$2
	local t netif=""
	local my_addr
	my_addr=`booth status | get_stat_fld booth_addr_string`
	if [ -z "$my_addr" ]; then
		echo "cannot find my address, booth running?" >&2
		return 1
	fi
	for t in `ip link | grep '^[1-9]:' | sed 's/.: //;s/: .*//'`
	do
		if ip a l $t | fgrep -wq $my_addr; then
			netif=$t
			break
		fi
	done
	if [ -n "$netif" ]; then
		$fun $netif $arg
	else
		echo "cannot find netif for $my_addr, netem not set" >&2
	fi
}

if [ "$1" = "__netem__" ]; then
	shift 1
	local_netem_env $@
	exit
fi

is_function() {
    test z"`command -v $1`" = z"$1"
}
runcmd() {
	local h=$1 rc
	shift 1
	logmsg "$h: running '$@'"
	if ip a l | fgrep -wq $h; then
		$@
	else
		ssh $h $@
	fi
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "$h: '$@' failed (exit code $rc)" >&2
		logmsg "$h: '$@' failed (exit code $rc)"
	fi
	return $rc
}
manage_site() {
	runcmd $1 crm resource $2 booth
}
manage_arbitrator() {
	runcmd $1 systemctl $2 booth@booth.service
}
start_site() {
	manage_site $1 start
}
start_arbitrator() {
	manage_arbitrator $1 start
}
stop_site_clean() {
	manage_site $1 stop &&
	sleep 1 &&
	runcmd $1 crm --force site ticket revoke $tkt
}
stop_site() {
	manage_site $1 stop
}
stop_arbitrator() {
	manage_arbitrator $1 stop
}
restart_site() {
	manage_site $1 restart
}
restart_arbitrator() {
	manage_arbitrator $1 restart
}
booth_status() {
	test "`runcmd $1 booth status | get_stat_fld booth_state`" = "started"
}
stop_booth() {
	local h
	for h in $sites; do
		stop_site $h
	done >/dev/null 2>&1
	for h in $arbitrators; do
		stop_arbitrator $h
	done >/dev/null 2>&1
	wait_timeout
}
start_booth() {
	local h
	for h in $sites; do
		start_site $h
	done >/dev/null 2>&1
	for h in $arbitrators; do
		start_arbitrator $h
	done >/dev/null 2>&1
	wait_timeout
}
restart_booth() {
	local h procs
	for h in $sites; do
		restart_site $h & procs="$! $procs"
	done >/dev/null 2>&1
	for h in $arbitrators; do
		restart_arbitrator $h
	done >/dev/null 2>&1
	wait $procs
	wait_timeout
}
sync_conf() {
	local h rc=0
	for h in $sites $arbitrators; do
		rsync -q $cnf $h:/etc/booth/booth.conf
		rc=$((rc|$?))
	done
	return $rc
}
dump_conf() {
	echo "test configuration file $cnf:"
	grep -v '^#' $cnf | grep -v '^[[:space:]]*$' | sed "s/^/$cnf: /"
}
forall() {
	local h rc=0
	for h in $sites $arbitrators; do
		runcmd $h $@
		rc=$((rc|$?))
	done
	return $rc
}
forall_sites() {
	local h rc=0
	for h in $sites; do
		runcmd $h $@
		rc=$((rc|$?))
	done
	return $rc
}
forall_fun() {
	local h rc=0 f=$1
	for h in $sites $arbitrators; do
		$f $h
		rc=$((rc|$?))
		[ $rc -ne 0 ] && break
	done
	return $rc
}
# run on all hosts whatever function produced on stdout
forall_fun2() {
	local h rc=0 f
	f=$1
	shift 1
	for h in $sites $arbitrators; do
		$f $@ | ssh $h
		rc=$((rc|$?))
		[ $rc -ne 0 ] && break
	done
	return $rc
}
run_site() {
	local n=$1 h
	shift 1
	h=`echo $sites | awk '{print $'$n'}'`
	runcmd $h $@
}
run_arbitrator() {
	local n=$1 h
	shift 1
	h=`echo $arbitrators | awk '{print $'$n'}'`
	runcmd $h $@
}
get_site() {
	local n=$1
	echo $sites | awk '{print $'$n'}'
}

get_port() {
	grep "^port" | 
		sed -n 's/.*="//;s/"//p'
}
get_servers() {
	grep "^$1" | 
		sed -n 's/.*="//;s/"//p'
}
get_rsc() {
	awk '/before-acquire-handler/{print $NF}' $cnf
}

break_external_prog() {
	echo "location __pref_booth_live_test `get_rsc` rule -inf: defined #uname" | run_site 1 crm configure
}
repair_external_prog() {
	run_site $1 crm configure delete __pref_booth_live_test
}
get_tkt() {
	grep "^ticket=" | head -1 | sed 's/ticket=//;s/"//g'
}
get_tkt_settings() {
awk '
n && /^	/ && /expire|timeout/ {
	sub(" = ", "=", $0);
	sub("^	", "T_", $0);
	print
	next
}
n && /^$/ {exit}
/^ticket.*'$tkt'/ {n=1}
' $cnf
}
wait_exp() {
	sleep $T_expire
}
wait_half_exp() {
	sleep $((T_expire/2))
}
wait_timeout() {
	local t=2
	[ "$T_timeout" -gt $t ] && t=$T_timeout
	[ "$PKT_LOSS" ] && t=$((t+PKT_LOSS/6))
	sleep $t
}

set_netem_env() {
	local modfun args
	modfun=`echo $1 | sed 's/:.*//'`
	args=`echo $1 | sed 's/[^:]*://;s/:/ /g'`
	if ! is_function NETEM_ENV_$modfun; then
		echo "NETEM_ENV_$modfun: doesn't exist"
		exit 1
	fi
	NETEM_ENV_$modfun $args
}
reset_netem_env() {
	[ -z "$NETEM_ENV" ] && return
	forall $0 $cnf __netem__ netem_reset
}
setup_netem() {
	[ -z "$NETEM_ENV" ] && return
	for env in $NETEM_ENV; do
		set_netem_env $env
	done
	trap "reset_netem_env" EXIT
}

cib_status() {
	local h=$1 stat
	stat=`runcmd $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	test "$stat" != "-1"
}
is_cib_granted() {
	local stat h=$1
	stat=`runcmd $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	[ "$stat" = "granted" ]
}
check_cib_consistency() {
	local h gh="" rc=0
	for h in $sites; do
		if is_cib_granted $h; then
			[ -n "$gh" ] && rc=1 # granted twice
			gh="$gh $h"
		fi
	done
	[ -z "$gh" ] && gh="none"
	if [ $rc -eq 0 ]; then
		echo $gh
		return $rc
	fi
	cat<<EOF >&2
CIB consistency test failed
ticket granted to $gh
EOF
	return $rc
}
check_cib() {
	local exp_grantee=$1 cib_grantee booth_grantee
	local rc=0 pending
	cib_grantee=`check_cib_consistency`
	booth_grantee=`booth_where_granted`
	pending=$?
	if [ $pending -eq 0 ]; then
		[ "$cib_grantee" = "$booth_grantee" ]
		rc=$?
	else
		# ticket is not committed to cib yet
		[ "$exp_grantee" = "$booth_grantee" ]
		rc=$?
		exp_grantee="" # cheat a bit
	fi
	case "$exp_grantee" in
	"any") [ "$cib_grantee" != "none" ] ;;
	"") [ "$cib_grantee" = "none" ] ;;
	*) [ "$cib_grantee" = "$exp_grantee" ] ;;
	esac
	rc=$((rc|$?))
	if [ $rc -ne 0 ]; then
		cat<<EOF >&2
CIB check failed
CIB grantee: $cib_grantee
booth grantee: $booth_grantee
expected grantee: $exp_grantee
EOF
	fi
	return $rc
}

booth_where_granted() {
	local grantee ticket_line
	# we don't know which sites could be stopped, so run booth
	# list on all of them (at least one should have booth
	# running)
	ticket_line=`forall_sites booth list | grep $tkt | sort -u | head -1`
	grantee=`echo "$ticket_line" | sed 's/.*leader: //;s/,.*//'`
	echo $grantee
	[ "$grantee" = "none" ] && return
	! runcmd $grantee booth list | grep -q "$tkt.*pending"
}
booth_list_fld() {
	cut -d, -f $1 | sed 's/[^:]*://'
}
max_booth_time_diff() {
	local l
	booth_list_fld 3 |
	while read l; do
		date -d "$l" "+%s"
	done |
	awk '
	{t[n++]=$0}
	END{
		for (i=0; i<n; i++)
			for (j=i+1; j<n; j++) {
				x=t[i]-t[j];
				print x >= 0 ? x : -x;
			}
	}
	' | sort -n | tail -1
}
booth_leader_consistency() {
	test `booth_list_fld 2 | sort -u | wc -l` -eq 1
}
check_booth_consistency() {
	local tlist rc maxdiff
	tlist=`forall booth list 2>/dev/null | grep $tkt |
		sed 's/commit:.*//;s/NONE/none/'`
	maxdiff=`echo "$tlist" | max_booth_time_diff`
	test "$maxdiff" -eq 0
	rc=$?
	echo "$tlist" | booth_leader_consistency
	rc=$(($rc | $?<<1))
	test $rc -eq 0 && return
	cat<<EOF >&2
`if [ $rc -gt 1 ]; then
	echo "booth list consistency failed (more than one leader!):"
else
	echo "booth list consistency failed (max valid time diff: $maxdiff):"
fi`
===========
"$tlist"
===========
EOF
	test $rc -le 1
}

check_consistency() {
	local exp_grantee=$1
	check_booth_consistency &&
	check_cib $exp_grantee
}

reset_booth() {
	start_booth
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
}
all_booth_status() {
	forall_fun booth_status
}

can_run_test() {
	if is_function applicable_$1; then
		if ! applicable_$1; then
			echo "(not applicable, skipping)"
			return 1
		fi
	fi
	if ! is_function test_$1 || ! is_function check_$1; then
		echo "(test missing)"
		return 1
	fi
}
run_report() {
	local start_ts=$1 end_ts=$2 name=$3
	echo "running hb_report" >&2
	hb_report -f "`date -d @$((start_ts-5))`" \
		-t "`date -d @$((end_ts+60))`" \
		-n "$sites $arbitrators" $name >&2
}
runtest() {
	local start_ts end_ts rc booth_status
	local start_time end_time
	TEST=$1
	start_time=`date`
	start_ts=`date +%s`
	echo -n "Testing: $1... "
	can_run_test $1 || return 0
	logmsg "starting booth test $1 ..."
	setup_netem
	test_$1 && check_$1
	rc=$?
	end_time=`date`
	end_ts=`date +%s`
	reset_netem_env
	logmsg "finished booth test $1 (exit code $rc)"
	is_function recover_$1 && recover_$1
	sleep 3
	all_booth_status
	booth_status=$?
	if [ $rc -eq 0 -a $booth_status -eq 0 ]; then
		echo OK
		[ "$GET_REPORT" ] && run_report $start_ts $end_ts $TEST
	else
		echo "FAIL (running hb_report ... $1.tar.bz2; see also $logf)"
		[ $booth_status -ne 0 ] &&
			echo "unexpected: some booth daemons not running"
		run_report $start_ts $end_ts $TEST
	fi
}

[ -f "$cnf" ] || {
	ls $cnf
	usage 1
}

sites=`get_servers site < $cnf`
arbitrators=`get_servers arbitrator < $cnf`
port=`get_port < $cnf`
: ${port:=9929}
site_cnt=`echo $sites | wc -w`
arbitrator_cnt=`echo $arbitrators | wc -w`
tkt=`get_tkt < $cnf`
eval `get_tkt_settings`

[ -z "$sites" ] && {
	echo no sites in $cnf
	usage 1
}

[ -z "$T_expire" ] && {
	echo set $tkt expire time in $cnf
	usage 1
}

exec 2>$logf
BASH_XTRACEFD=2
PS4='+ `date +"%T"`: '
set -x

#
# the tests
#

## TEST: grant ##

# just a grant
test_grant() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
}
check_grant() {
	check_consistency `get_site 1`
}

## TEST: grant_noarb ##

# just a grant with no arbitrators
test_grant_noarb() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	local h
	for h in $arbitrators; do
		stop_arbitrator $h
	done >/dev/null 2>&1
	sleep 1
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
}
check_grant_noarb() {
	check_consistency `get_site 1`
}
recover_grant_noarb() {
	local h
	for h in $arbitrators; do
		start_arbitrator $h
	done >/dev/null 2>&1
}

## TEST: revoke ##

# just a revoke
test_revoke() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
}
check_revoke() {
	check_consistency
}

## TEST: grant_elsewhere ##

# just a grant to another site
test_grant_elsewhere() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant -s `get_site 2` $tkt >/dev/null
	wait_timeout
}
check_grant_elsewhere() {
	check_consistency `get_site 2`
}

## TEST: grant_site_lost ##

# grant with one site lost
test_grant_site_lost() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	stop_site `get_site 2`
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	check_cib `get_site 1` || return 1
	wait_exp
}
check_grant_site_lost() {
	check_consistency `get_site 1`
}
recover_grant_site_lost() {
	start_site `get_site 2`
}

## TEST: simultaneous_start_even ##

# simultaneous start of even number of members
test_simultaneous_start_even() {
	local serv
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 2 booth grant $tkt >/dev/null
	wait_timeout
	stop_booth
	wait_timeout
	for serv in $(echo $sites | sed "s/`get_site 1` //"); do
		start_site $serv &
	done
	for serv in $arbitrators; do
		start_arbitrator $serv &
	done
	wait_half_exp
	start_site `get_site 1`
	wait_timeout
	wait_timeout
}
check_simultaneous_start_even() {
	check_consistency `get_site 2`
}

## TEST: slow_start_granted ##

# slow start
test_slow_start_granted() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	stop_booth
	wait_timeout
	for serv in $sites; do
		start_site $serv
		wait_timeout
	done
	for serv in $arbitrators; do
		start_arbitrator $serv
		wait_timeout
	done
}
check_slow_start_granted() {
	check_consistency `get_site 1`
}

## TEST: restart_granted ##

# restart with ticket granted
test_restart_granted() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	restart_site `get_site 1`
	wait_timeout
}
check_restart_granted() {
	check_consistency `get_site 1`
}

## TEST: restart_granted_nocib ##

# restart with ticket granted (but cib empty)
test_restart_granted_nocib() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	stop_site_clean `get_site 1` || return 1
	wait_timeout
	start_site `get_site 1`
	wait_timeout
	wait_timeout
	wait_timeout
}
check_restart_granted_nocib() {
	check_consistency `get_site 1`
}

## TEST: notgranted ##

# restart with ticket not granted
test_restart_notgranted() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	stop_site `get_site 2`
	sleep 1
	start_site `get_site 2`
	wait_timeout
}
check_restart_notgranted() {
	check_consistency `get_site 1`
}

## TEST: failover ##

# ticket failover
test_failover() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	stop_site_clean `get_site 1` || return 1
	booth_status `get_site 1` && return 1
	wait_exp
	wait_timeout
	wait_timeout
	wait_timeout
}
check_failover() {
	check_consistency any
}
recover_failover() {
	start_site `get_site 1`
}

## TEST: split_leader ##

# split brain (leader alone)
test_split_leader() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 1 $iprules stop $port  >/dev/null
	wait_exp
	wait_timeout
	check_cib any || return 1
	run_site 1 $iprules start $port  >/dev/null
	wait_timeout
	wait_timeout
	wait_timeout
}
check_split_leader() {
	check_consistency any
}
recover_split_leader() {
	run_site 1 $iprules start $port  >/dev/null
}

## TEST: split_follower ##

# split brain (follower alone)
test_split_follower() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 2 $iprules stop $port  >/dev/null
	wait_exp
	wait_timeout
	run_site 2 $iprules start $port  >/dev/null
	wait_timeout
}
check_split_follower() {
	check_consistency `get_site 1`
}

## TEST: split_edge ##

# split brain (leader alone)
test_split_edge() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 1 $iprules stop $port  >/dev/null
	wait_exp
	run_site 1 $iprules start $port  >/dev/null
	wait_timeout
}
check_split_edge() {
	check_consistency any
}

## TEST: external_prog_failed ##

# external test prog failed
test_external_prog_failed() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	sleep 1
	break_external_prog 1
	wait_half_exp
	wait_timeout
}
check_external_prog_failed() {
	check_consistency any &&
	[ `booth_where_granted` != `get_site 1` ]
}
recover_external_prog_failed() {
	repair_external_prog 1
}
applicable_external_prog_failed() {
	[ -n `get_rsc` ]
}

#
# environment modifications
#

# packet loss at one site 30%
NETEM_ENV_single_loss() {
	run_site 1 $0 $cnf __netem__ netem_loss ${1:-30}
	PKT_LOSS=${1:-30}
}

# packet loss everywhere 30%
NETEM_ENV_loss() {
	forall $0 $cnf __netem__ netem_loss ${1:-30}
	PKT_LOSS=${1:-30}
}

# network delay 100ms
NETEM_ENV_net_delay() {
	forall $0 $cnf __netem__ netem_delay ${1:-100}
}

sync_conf || exit
restart_booth
all_booth_status || {
	reset_booth
	all_booth_status || exit
}

dump_conf >&2

TESTS="$@"

: ${TESTS:="grant grant_noarb grant_elsewhere grant_site_lost revoke
simultaneous_start_even slow_start_granted
restart_granted restart_granted_nocib restart_notgranted
failover split_leader split_follower split_edge
external_prog_failed"}

for t in $TESTS; do
	runtest $t
done
