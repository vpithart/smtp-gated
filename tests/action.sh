#!/bin/sh

ACTION_DAT="../log/action.dat"

[ -f "$ACTION_DAT" ] || exit 1
. $ACTION_DAT

(
	echo "PROXY_NAME=$PROXY_NAME"
	echo "UNIXTIME=$UNIXTIME"
	echo "TIME=$TIME"
	echo "FOUND=$FOUND"
	echo "VIRUS_NAME=$VIRUS_NAME"
	echo "SPAM_SCORE=$SPAM_SCORE"
	echo "SOURCE_IP=$SOURCE_IP"
	echo "SOURCE_PORT=$SOURCE_PORT"
	echo "TARGET_IP=$TARGET_IP"
	echo "TARGET_PORT=$TARGET_PORT"
	echo "LOCAL_IP=$LOCAL_IP"
	echo "LOCAL_PORT=$LOCAL_PORT"
	echo "IDENT=$IDENT"
	echo "IDENT_COUNT=$IDENT_COUNT"
	echo "HELO=$HELO"
	echo "MAIL_FROM=$MAIL_FROM"
	echo "RCPTS_TOTAL=$RCPTS_TOTAL"
	echo "SIZE=$SIZE"
	echo "TRANSACTION=$TRANSACTION"
	echo "SPOOL_NAME=$SPOOL_NAME"
	echo "LOCK_FILE=$LOCK_FILE"
	echo "LOCK_DURATION=$LOCK_DURATION"
	echo "----- flush -----"
	sleep $ACTION_SLEEP
	echo "--------------------------"
	set
) >$ACTION_LOG

kill -HUP $ACTION_PID

