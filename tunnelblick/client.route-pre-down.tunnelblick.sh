#!/bin/bash -e
# Note: must be bash; uses bash-specific tricks
#
# ******************************************************************************************************************
# This Tunnelblick script does everything! It handles TUN and TAP interfaces, 
# pushed configurations and DHCP leases. :)
# 
# This is the "route-pre-down" version of the script, executed before the connection is closed.
#
# It is a modified version of the "down" script written by Nick Williams
#
# It releases the DHCP lease for any TAP devices.
# It has no effect for TUN devices or TAP devices not using DHCP.
#
# ******************************************************************************************************************

trap "" TSTP
trap "" HUP
trap "" INT
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"

readonly LOG_MESSAGE_COMMAND=$(basename "${0}")

# Quick check - is the configuration there?
if ! scutil -w State:/Network/OpenVPN &>/dev/null -t 1 ; then
	# Configuration isn't there, so we forget it
	echo "$(date '+%a %b %e %T %Y') *Tunnelblick $LOG_MESSAGE_COMMAND: WARNING: No existing OpenVPN DNS configuration found; not tearing down anything; exiting."
	exit 0
fi

# NOTE: This script does not use any arguments passed to it by OpenVPN, so it doesn't shift Tunnelblick options out of the argument list

# Get info saved by the up script
TUNNELBLICK_CONFIG="$( scutil <<-EOF
	open
	show State:/Network/OpenVPN
	quit
EOF
)"

ARG_MONITOR_NETWORK_CONFIGURATION="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*MonitorNetwork :' | sed -e 's/^.*: //g')"
LEASEWATCHER_PLIST_PATH="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*LeaseWatcherPlistPath :' | sed -e 's/^.*: //g')"
PSID="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*Service :' | sed -e 's/^.*: //g')"
SCRIPT_LOG_FILE="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*ScriptLogFile :' | sed -e 's/^.*: //g')"
# Don't need: ARG_RESTORE_ON_DNS_RESET="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*RestoreOnDNSReset :' | sed -e 's/^.*: //g')"
# Don't need: ARG_RESTORE_ON_WINS_RESET="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*RestoreOnWINSReset :' | sed -e 's/^.*: //g')"
# Don't need: PROCESS="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*PID :' | sed -e 's/^.*: //g')"
# Don't need: ARG_IGNORE_OPTION_FLAGS="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*IgnoreOptionFlags :' | sed -e 's/^.*: //g')"
ARG_TAP="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*IsTapInterface :' | sed -e 's/^.*: //g')"

bRouteGatewayIsDhcp="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*RouteGatewayIsDhcp :' | sed -e 's/^.*: //g')"
sTunnelDevice="$(echo "${TUNNELBLICK_CONFIG}" | grep -i '^[[:space:]]*TunnelDevice :' | sed -e 's/^.*: //g')"

# @param String message - The message to log
logMessage()
{
	echo "$(date '+%a %b %e %T %Y') *Tunnelblick $LOG_MESSAGE_COMMAND: "${@} >> "${SCRIPT_LOG_FILE}"
}

trim()
{
	echo ${@}
}

if ${ARG_TAP} ; then
	if [ "$bRouteGatewayIsDhcp" == "true" ]; then
        # Issue warning if the primary service ID has changed
        PSID_CURRENT="$( scutil <<-EOF |
            open
            show State:/Network/OpenVPN
            quit
EOF
grep Service | sed -e 's/.*Service : //'
)"
        if [ "${PSID}" != "${PSID_CURRENT}" ] ; then
            logMessage "Ignoring change of Network Primary Service from ${PSID} to ${PSID_CURRENT}"
        fi

        # Remove leasewatcher
        if ${ARG_MONITOR_NETWORK_CONFIGURATION} ; then
            launchctl unload "${LEASEWATCHER_PLIST_PATH}"
            rm -f "${LEASEWATCHER_PLIST_PATH}"
            logMessage "Cancelled monitoring of system configuration changes"
            
            # Indicate leasewatcher has been removed
            scutil <<-EOF
            open
            get State:/Network/OpenVPN
            d.remove MonitorNetwork
            d.add MonitorNetwork        "false"
            set State:/Network/OpenVPN
            quit
EOF
        fi
            
        # Release the DHCP lease
        if [ -z "$dev" ]; then
            # If $dev is not defined, then use TunnelDevice, which was set from $dev by client.up.tunnelblick.sh
            # ($dev is not defined when this script is called from MenuController to clean up when OpenVPN has crashed)
            if [ -n "${sTunnelDevice}" ]; then
                logMessage "DEBUG: \$dev not defined; using TunnelDevice: ${sTunnelDevice}"
                set +e
                ipconfig set "${sTunnelDevice}" NONE 2>/dev/null
                set -e
                logMessage "Released the DHCP lease via ipconfig set \"${sTunnelDevice}\" NONE."
            else
                logMessage "Cannot release the DHCP lease without \$dev or State:/Network/OpenVPN/TunnelDevice being defined. Device may not have disconnected properly."
            fi
        else
            set +e
            ipconfig set "$dev" NONE 2>/dev/null
            set -e
            logMessage "Released the DHCP lease via ipconfig set \"$dev\" NONE."
        fi

        # Indicate the DHCP lease has been released
        scutil <<-EOF
        open
        get State:/Network/OpenVPN
        d.remove TapDeviceSetNone
        d.add TapDeviceHasBeenSetNone "true"
        set State:/Network/OpenVPN
        quit
EOF
	fi
else
    logMessage "No route-pre-downn action is required because this is not a TAP connection using DHCP via the TAP device."
fi

exit 0
