#!/bin/sh
#
# see README-testing for more information
# do some basic booth operation tests for the given config
#

usage() {
	echo "$0: {booth.conf}"
	exit
}

[ $# -eq 0 ] && usage

cnf=$1
shift 1
logf=test_booth.log
iprules=/usr/share/booth/tests/test/booth_path
netif=eth0
: ${HA_LOGFACILITY:="syslog"}

is_function() {
    test z"`command -v $1`" = z"$1"
}
manage_site() {
	ssh $1 crm resource $2 booth
}
manage_arbitrator() {
	ssh $1 systemctl $2 booth@booth.service
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
	ssh $1 crm --force site ticket revoke $tkt
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
get_stat_fld() {
	local h=$1 fld=$2
	ssh $h booth status | sed "s/.* $fld=//;s/ .*//;s/'//g"
}
booth_status() {
	test "`get_stat_fld $1 booth_state`" = "started"
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
		ssh $h $@
		rc=$((rc|$?))
	done
	return $rc
}
forall_sites() {
	local h rc=0
	for h in $sites; do
		ssh $h $@
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
	ssh $h $@ || {
		echo "$h: '$@' failed (exit code $?)" >&2
	}
}
run_arbitrator() {
	local n=$1 h
	shift 1
	h=`echo $arbitrators | awk '{print $'$n'}'`
	ssh $h $@
}
get_site() {
	local n=$1
	echo $sites | awk '{print $'$n'}'
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
	sleep $t
}

ext_prog_log() {
	local cmd="$@"
	echo "run: $cmd" >&2
	logger -p $HA_LOGFACILITY.info "$cmd"
	$cmd
}

# tc netem, simulate packet loss, wan, etc
netem_delay() {
	echo "tc qdisc add dev $netif root netem delay $1ms $(($1/10))ms"
}
netem_loss() {
	echo "tc qdisc add dev $netif root netem loss $1%"
}
netem_reset() {
	echo "tc qdisc del dev $netif root netem"
}

cib_status() {
	local h=$1 stat
	stat=`ssh $h crm_ticket -L |
		grep "^$tkt" | awk '{print $2}'`
	test "$stat" != "-1"
}
is_cib_granted() {
	local stat h=$1
	stat=`ssh $h crm_ticket -L |
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
	! ssh $grantee booth list | grep -q "$tkt.*pending"
}
check_booth_consistency() {
	local cnt tlist
	tlist=`forall booth list 2>/dev/null | grep $tkt |
		sed 's/commit:.*//;s/NONE/none/'`
	cnt=`echo "$tlist" | sort -u | wc -l`
	test $cnt -eq 1 && return
	cat<<EOF >&2
booth list consistency test failed:
===========
"$tlist"
===========
EOF
	return 1
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
runtest() {
	local start_ts end_ts rc booth_status
	local start_time end_time
	TEST=$1
	start_time=`date`
	start_ts=`date +%s`
	echo -n "Testing: $1... "
	can_run_test $1 || return 0
	logger -p $HA_LOGFACILITY.info "starting booth test $1 ..."
	test_$1 && check_$1
	rc=$?
	end_time=`date`
	end_ts=`date +%s`
	logger -p $HA_LOGFACILITY.info "finished booth test $1 (exit code $rc)"
	is_function recover_$1 && recover_$1
	sleep 3
	all_booth_status
	booth_status=$?
	if [ $rc -eq 0 -a $booth_status -eq 0 ]; then
		echo OK
	else
		echo "FAIL (running hb_report ... $1.tar.bz2; see also $logf)"
		[ $booth_status -ne 0 ] &&
			echo "unexpected: some booth daemons not running"
		echo "running hb_report" >&2
		hb_report -f "`date -d @$((start_ts-5))`" \
			-t "`date -d @$((end_ts+60))`" \
			-n "$sites $arbitrators" $1 >&2
	fi
}

[ -f "$cnf" ] || {
	ls $cnf
	usage
}

sites=`get_servers site < $cnf`
arbitrators=`get_servers arbitrator < $cnf`
site_cnt=`echo $sites | wc -w`
arbitrator_cnt=`echo $arbitrators | wc -w`
tkt=`get_tkt < $cnf`
eval `get_tkt_settings`

[ -z "$sites" ] && {
	echo no sites in $cnf
	usage
}

[ -z "$T_expire" ] && {
	echo set $tkt expire time in $cnf
	usage
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
	run_site 1 $iprules stop  >/dev/null
	wait_exp
	wait_timeout
	check_cib any || return 1
	run_site 1 $iprules start  >/dev/null
	wait_timeout
}
check_split_leader() {
	check_consistency any
}
recover_split_leader() {
	run_site 1 $iprules start  >/dev/null
}

## TEST: split_follower ##

# split brain (follower alone)
test_split_follower() {
	run_site 1 booth revoke $tkt >/dev/null
	wait_timeout
	run_site 1 booth grant $tkt >/dev/null
	wait_timeout
	run_site 2 $iprules stop  >/dev/null
	wait_exp
	wait_timeout
	run_site 2 $iprules start  >/dev/null
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
	run_site 1 $iprules stop  >/dev/null
	wait_exp
	run_site 1 $iprules start  >/dev/null
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
ENV_single_loss() {
	run_site 1 netem_loss ${1:-30}
}

# packet loss everywhere 30%
ENV_loss() {
	forall_fun2 netem_loss ${1:-30}
}

# network delay 100ms
ENV_net_delay() {
	forall_fun2 netem_delay ${1:-100}
}

set_env() {
	local modfun args
	modfun=`echo $1 | sed 's/:.*//'`
	args=`echo $1 | sed 's/[^:]*://;s/:/ /g'`
	if ! is_function ENV_$modfun; then
		echo "ENV_$modfun: doesn't exist"
		exit 1
	fi
	echo running $modfun $args
	ENV_$modfun $args
}
reset_env() {
	trap "forall_fun2 netem_reset" EXIT
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

if [ -n "$NETEM_ENV" ]; then
	for env in $NETEM_ENV; do
		set_env $env
	done
	reset_env
fi

for t in $TESTS; do
	runtest $t
done
