#! /bin/sh
### BEGIN INIT INFO
# Provides:          smtp-gated
# Required-Start:    $local_fs $remote_fs
# Required-Stop:     $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      S 0 1 6
# Short-Description: smtp-gated startup script
# Description:       smtp-gated is transparent SMTP proxy.
#                    Uses netfilter to relay connections to proper MTA.
### END INIT INFO

# Author: Bartlomiej Korupczynski <bartek@klolik.org>

# Do NOT "set -e"

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/usr/sbin:/usr/bin:/sbin:/bin
DESC="SMTP Proxy"
NAME=smtp-gated
DAEMON=/usr/sbin/$NAME
CONFIG=/etc/smtp-gated.conf
DAEMON_ARGS="$CONFIG"
#PIDFILE=/var/run/$NAME/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
PIDFILE=

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
[ -f /etc/default/rcS ] && . /etc/default/rcS

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

# After possible overriding config file by /etc/default script
# try to get it from configuration file
[ -z "$PIDFILE" ] && PIDFILE=`$DAEMON -t "$CONFIG" | awk '(/^pidfile/) {print $2}'`
# last chance: try default value
[ -z "$PIDFILE" ] && PIDFILE=/var/run/$NAME/$NAME.pid

#
# Function that starts the daemon/service
#

do_verify()
{
	$DAEMON -t "$CONFIG" >/dev/null
	[ $? = 0 ] && return 0
	echo "Configuration syntax error. See syslog for details"
	exit 1
}

do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --test > /dev/null \
		|| return 1
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- \
		$DAEMON_ARGS \
		|| return 2
	# Add code here, if necessary, that waits for the process to be ready
	# to handle requests from services started subsequently which depend
	# on this one.  As a last resort, sleep for some time.
}

#
# Function that stops the daemon/service
#
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
	$DAEMON -K $DAEMON_ARGS
#	start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME
#	RETVAL="$?"
#	[ "$RETVAL" = 2 ] && return 2
	# Wait for children to finish too if this is a daemon that forks
	# and if the daemon is only ever run from this initscript.
	# If the above conditions are not satisfied then add some other code
	# that waits for the process to drop all resources that could be
	# needed by services started subsequently.  A last resort is to
	# sleep for some time.
#	start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec $DAEMON
#	[ "$?" = 2 ] && return 2
	# Many daemons don't delete their pidfiles when they exit.
#	rm -f $PIDFILE
#	return "$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
	#
	# If the daemon can reload its configuration without
	# restarting (for example, when it is sent a SIGHUP),
	# then implement that here.
	#
	$DAEMON -r $DAEMON_ARGS
#	start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE --name $NAME
	#$DAEMON -r "$CONFIG"
	return 0
}

case "$1" in
  start)
	[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
	do_start
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  stop)
	[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  reload|force-reload)
	#
	# If do_reload() is not implemented then leave this commented out
	# and leave 'force-reload' as an alias for 'restart'.
	#
	log_daemon_msg "Reloading $DESC" "$NAME"
	do_verify
	do_reload
	log_end_msg $?
	;;
  restart|force-reload)
	#
	# If the "reload" option is implemented then remove the
	# 'force-reload' alias
	#
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_verify
	do_stop
	sleep 1
	case "$?" in
	  0|1)
		do_start
		case "$?" in
			0) log_end_msg 0 ;;
			1) log_end_msg 1 ;; # Old process is still running
			*) log_end_msg 1 ;; # Failed to start
		esac
		;;
	  *)
	  	# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
  status)
	$DAEMON -s "$CONFIG"
	;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload|status}" >&2
	exit 3
	;;
esac

:
