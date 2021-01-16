#!/bin/sh
SCRIPTNAME="${0##*/}"
DIR="${0%\/*}"
##### Find Shell #####
if [ -f "/usr/bin/lua" ]; then SHELLIS="ash"; fi 
if [ "${SHELLIS}" = "ash" ]; then WAITLOCK="-w"; else WAITLOCK="";fi
if [ "${SHELLIS}" = "ash" ]; then
	#OpenWRT xtables fix for LagDrop
	if { grep -q "x_tables" "/etc/modules.d/nf-ipt"; }; then
		sed -i "/x_tables/d" "/etc/modules.d/nf-ipt"
		service firewall stop; service firewall start
		wait $!
	fi
	#Remove xtables.lock because it interferes with LagDrop
	while :;do { rm -f /var/run/xtables.lock &> /dev/null; }; done &
	#while sleep 5; do KEEP_RUNNING="$(ping -q -c 1 -W 1 "example.com")"; done & #Keep OpenWRT Connection alive
fi &> /dev/null &
if { command -v stty|grep -Eq "stty$" &> /dev/null; }; then stty -echo &> /dev/null; fi &> /dev/null
if { command -v usleep|grep -Eq "usleep$" &> /dev/null; }; then USLEEP_EXISTS=1; USLEEP_DELAY_MULTIPLIER=500000; else USLEEP_EXISTS=0; fi &> /dev/null #if usleep is available on the device, then usleep multiplier will be used instead of sleep.
if { command -v nvram|grep -Eq "nvram$" &> /dev/null; }; then NVRAM_EXISTS=1; else NVRAM_EXISTS=0; fi &> /dev/null
if { command -v ifconfig|grep -Eq "ifconfig$" &> /dev/null; }; then IFCONFIG_EXISTS=1; else IFCONFIG_EXISTS=0; fi &> /dev/null
LDTEMPFOLDER=ldtmp
SALT=""; if { echo "$SALT"|grep -Eqi "[a-z]"; }; then SALT="273918335FEA6545";fi
ITER=""; if { echo "$ITER"|grep -Eqi "[a-z]"; }; then ITER="4200";fi
HEARTBREAKHOTEL="-aes-256-cbc -k ${SALT} -base64 -S ${SALT}"
for i in $(ps|grep -E "($SCRIPTNAME|lagdrop|debuggingmonitorscript|laggregator)"|grep -Eo "^(\s*)?[0-9]{1,}\b"|grep -Ev "\b($$)\b"|sed -E "s/\s//g"); do kill -15 $i & done &> /dev/null
{
if [ ! -d "/tmp/${LDTEMPFOLDER}" ]; then mkdir -p "/tmp/${LDTEMPFOLDER}" ; fi
POPULATE=""
MAKE_TWEAK=""
cache_tidy(){
	for file in $(ls -1 "$DIR/42Kmi/$SUBFOLDER/"|grep -Ev "\b(filterignore|geomem|pingmem)\b$"); do rm -rf ""$DIR"/42Kmi/$SUBFOLDER/$file"; done
}
cleanall(){
	wait $!
	#Exit message
	echo -e "${BLUE}Exiting LagDrop... Hold on${NC}"
	{
		#Exit magic
		if { command -v stty|grep -Eq "stty$" &> /dev/null; }; then stty echo &> /dev/null; fi &> /dev/null
		if [ "$DECONGEST" = 1 ]; then
			if [ $IFCONFIG_EXISTS = 1 ]; then
				txqueuelen_restore &> /dev/null
			fi
		fi
		#Empty LDKTA table and adjust geomem and pingmem files
		iptables -F LDKTA
		#Clean caches files if needed
		if { grep -Eq "\b(((#(.*)#(.*)#$)|(^#|##))|(NOT(%| )FOUND(%| )-(%| )CANNOT(%| )CONNECT))\b|(\, \, \,)" ""$DIR"/42Kmi/cache/"*; }; then
			HITLIST="$(echo "$(grep -E "\b(((#(.*)#(.*)#$)|(^#|##))|(NOT(%| )FOUND(%| )-(%| )CANNOT(%| )CONNECT))\b|(\, \, \,)" "$DIR/42Kmi/cache/"*|grep "cache"|sed -E "s/\:.*$//g"|sed "s/^.*\///g")"|awk '!a[$0]++')"
			for file in $HITLIST; do
				sed -i -E "/((#(.*)#(.*)#$)|(^#|##))|(NOT(%| )FOUND(%| )-(%| )CANNOT(%| )CONNECT)|(\, \, \,)/d" ""$DIR"/42Kmi/cache/$file" #Deletes lines with 3 #
			done
			cache_tidy
		fi
		#Encrypt logfile
		if { grep -q "@" "/tmp/$RANDOMGET"; } || [ -z "/tmp/$RANDOMGET" ]; then
			echo "$(tail +1 "/tmp/$RANDOMGET"|openssl enc ${HEARTBREAKHOTEL})" > "/tmp/$RANDOMGET"
		fi
			wait $!
		rm -rf "/tmp/${LDTEMPFOLDER}"
		if [ "${SHELLIS}" != "ash" ] && [ $NVRAM_EXISTS = 1 ]; then
			restore_original_values(){
				eval "nvram set dmz_enable=${ORIGINAL_DMZ}"
				eval "nvram set dmz_ipaddr=${ORIGINAL_DMZ_IPADDR}"
				eval "nvram set block_multicast=${ORIGINAL_MULTICAST}"
				eval "nvram set block_wan=${ORIGINAL_BLOCKWAN}"
			}
			restore_original_values
		fi
		for i in $(ps|grep -E "($SCRIPTNAME|lagdrop|debuggingmonitorscript)"|grep -Eo "^(\s*)?[0-9]{1,}\b"|grep -Ev "\b($$)\b"|sed -E "s/\s//g"); do kill -9 $i & done
		for i in $(ps|grep -E "($SCRIPTNAME|lagdrop|debuggingmonitorscript)"|grep -Eo "^(\s*)?[0-9]{1,}\b"|sed -E "s/\s//g"); do kill -9 $i & done
		if [ $POPULATE = 1 ]; then
			iptables -F LDIGNORE
		fi
		if [ -f "${DIR}"/killall.sh ]; then "${DIR}"/killall.sh; fi
		exit &> /dev/null
	} &> /dev/null
}
exit_trap(){
	trap cleanall 0 1 2 3 6 9 15 23 24 #Placed at loops and functions to kill when killed
}
exit_trap &> /dev/null
check_dependencies(){
	#For OpenWRT, please install curl and openssl-util!!
	DEPENDENCY_LIST="curl openssl ping traceroute iptables awk sed grep head tail mkdir tr"
	for depend_exist in $DEPENDENCY_LIST; do
		if ! { command -v ${depend_exist}|grep -Eq "${depend_exist}$"; }; then
			echo -e "${RED}${depend_exist}${NC} not found. Please ensure ${RED}${depend_exist}${NC} is installed before running LagDrop."
			MISSING_DEPEND=1
		fi
	done; wait $!
	if [ $MISSING_DEPEND = 1 ]; then kill -15 $$; fi
	if [ $MISSING_DEPEND = 1 ]; then cleanall; fi
}
PROCESS="$$"
##### LINE OPTIONS #####
for i in "$@"; do
	case $i in
		-c|--clear) #Cleans old LagDrop records, but directories and options remain. Terminates
			if  { ls -1 /tmp|grep -Ei "[0-9a-f]{38,}"; } &> /dev/null;  then
				iptables -nL LDACCEPT; iptables -nL LDREJECT; iptables -nL LDIGNORE; iptables -nL LDSENTSTRIKE; iptables -nL LDTEMPHOLD; iptables -nL LDBAN; iptables -nL LDKTA kill -15 $$ 2>&1 >/dev/null &
				for i in $(ls -1 /tmp|grep -Ei "[0-9a-f]{38,}"); do
					rm -f /tmp/"$i" &> /dev/null
				done &> /dev/null
			fi; break
		{ exit 0; } &> /dev/null
		;;
		-s|--smart) # Enable Smart Mode, after 5 passed results, average of passed pings becomes the new ping limit. Successively decreases to best pings
			SMARTMODE=1
			SHOWSMART=1
		;;
		-p|--populate) #with location enabled, fills caches for ping approximation. LagDrop doesn't filter
			POPULATE=1
			SHOWLOCATION=1
		;;
		-t|--tweakmake) #Creates tweak.txt to customize normally fixed values.
			MAKE_TWEAK=1
		;;
		-b|--bytes) #When Sentinel is enabled, use bytes instead.
			USE_BYTES=1
		;;
		-v|--verify) #When Sentinel is enabled, enables verify values.
			ENABLE_VERIFY=1
		;;
	esac
done
##### LINE OPTIONS #####
SHOWLOCATION=1 #Location is now always enabled. Location flag is obsolete
##### Colors & Escapes#####
NC="\033[0m"; RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; MARK="\033[1;37m"; GRAY="\033[1;30m"; BLUE="\033[1;34m"; MAGENTA="\033[1;35m"; DEFAULT="\033[1;39m"; BLACK="\033[1;30m"; CYAN="\033[1;36m"; LIGHTGRAY="\033[1;37m"; DARKGRAY="\033[1;90m"; LIGHTRED="\033[1;91m"; LIGHTGREEN="\033[1;92m"; LIGHTYELLOW="\033[1;93m"; LIGHTBLUE="\033[1;94m"; LIGHTMAGENTA="\033[1;95m"; LIGHTCYAN="\033[1;96m"; WHITE="\033[1;97m";HIDE="\033[8m";BOLD="\033[1m"
SAVECURSOR="\033[s" #Save Cursor Position
RESTORECURSOR="\033[u" #Restore Cursor Position
REFRESHALL="\033[H\033[2J" # From Top and Left of screen
REFRESH="\033[H\033[2J" # From cursor
CLEARLINE="\033[K" #Clears line at cursor position and beyond
CLEARSCROLLBACK="\033[H\033[3J" # Clears scrollback
##### BG COLORS #####
BG_BLACK="\033[1;40m"; BG_RED="\033[1;41m"; BG_GREEN="\033[1;42m"; BG_YELLOW="\033[1;43m"; BG_BLUE="\033[1;44m"; BG_MAGENTA="\033[1;45m"; BG_CYAN="\033[1;46m"; BG_WHITE="\033[1;47m"
##### BG COLORS #####
CUSSORLEFT1="\033[1D"
##### Colors & Escapes#####
LOGO="
                           MM
                        MMMMM                             MMMMMMMMMMMMMM
          ${CYAN}         MMM${NC} MMMMMM                           MMMMMMMMMMMMMMMM
          ${CYAN}    M  MMMMM${NC} MMMMMM                  MMMMMMM MMMMMMMMMMMMMMMMM
          ${CYAN} MMMM KMMMMM${NC} MMMMMM               MMMMMMMMMM MMMMMMMMMMMMMMMMM
          ${CYAN}MMMMM KMMMMM${NC} MMMMMM            MMMMMMMMMMMMM MMMMMMMMMMMMMMMMM
          ${CYAN}MMMMM KMMMMM${NC} MMMMMM           MMMMMMMM  MMMM MMMMMMMM   MMMMMM
          ${CYAN}MMMMM KMMMMM${NC} MMMMMM         MMMMMMMM    MMMMMMMMMMMM
    MM\`   ${CYAN}MMMMM KMMMMM${NC} MMMMMM         MMMMMM      MMMMMMMMMMM     MMMMMM
   MMMMMM   ${CYAN}MMM KMMMMM${NC} MMMMMM        MMMMMMM     MMMMMMMMMMMM     MMMMMM
   MMMMMMMM  ${CYAN}MM KMMMMM${NC} MMMMMM        MMMMMMMM   MMMMMMMMMMMMMMM  MMMMMMM
   MMMMMMMMMM   ${CYAN}KMMMMM${NC} MMMMMMMM          MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
   MMMMMMMMMMM   ${CYAN}MMMMM${NC} MMMMMMMMMMMMMMMMMM MMMMMMMMMMMMM MMMMMMMMMMMMMMMMM
   MMMMMMMMMMMMM  ${CYAN}MMMM${NC} MMMMMMMMMMMMMMMMMM MMMMMMMMMMMMM MMMMMMMMMMMMMMMMM
   MMMMMMMMMMMMMMM  ${CYAN}MM${NC}  MMMMMMMMMMMMMMMMM MMMMMMMM  MMM  MMMMMMM  MMMMMM
   MMMMMMMM MMMMMMM+                          \`MMMM            :dy
   MMMMMMM    MMMMMMM    MMMMMM MMMMMMMMMM MMMMMMMMMMMM MMMMMMMMMMMMMMMM
   MMMMMMM      MMMMMMd  MMMMMMMMMMMMMMMMM MMMMMMMMMMMM MMMMMMMMMMMMMMMMM
   MMMMMMM       MMMMMMM MMMMMMMMMMMMMMMMM MMMMMMMMMMMM MMMMMMMM   MMMMMM
   MMMMMMM        MMMMMM MMMMMMMMMMMMMMMMM MMMMMMMMMMMM MMMMMMM      MMMM
   MMMMMMMM       MMMMMMMMMMMMMMMMMMMMMMMM        MMMMM MMMMMMM      MMMM
   MMMMMMMM      MMMMMMMM MMMMMM    MMMMMM        :MMMM MMMMMMM      MMMM
   MMMMMMMMMMMMMMMMMMMMMM MMMMMM                   MMMM MMMMMMMM   MMMMMM
    MMMMMMMMMMMMMMMMMMMM MMMMMMM    MMMMMM        NMMMM MMMMMMMMMMMMMMMM
    MMMMMMMMMMMMMMMMMMM  MMMMMMM    MMMMMMMMy  oMMMMMMM MMMMMMMMMMMMMMMM
     MMMMMMMMMMMMMMMMM   MMMMMMM    MMMMMMMMMMMMMMMMMMM MMMMMMM
       MMMMMMMMMMMMM     MMMMMMM    MMMMMMMMMMMMMMMMMMM MMMMMMM
          +MMMMM         \`MMM        sMMMMMMMMMMMMMMMM   MMMMMM
"
VERSION="Ver 3.0.0 beta, #OneForAll"
MESSAGE="$(echo -e "	${LOGO}
Enter an identifier!! Eg: WIIU, XBOX, PS4, PC, etc.
Usage: ./path_to/lagdrop.sh identifier -s -l
### 42Kmi LagDrop "${VERSION}\ ###"
Router-based Anti-Lag Dynamic Firewall for P2P online games.
Supported identifiers load the appropriate filters for the console/device.
Running LagDrop without argument will terminate all instances of the script.
	Identifiers:
	${RED}Nintendo filters: Nintendo, Switch, Wii, WiiU, NDS, DS, 3DS, 2DS${NC}
	${BLUE}Playstation filters: PlayStation, PS3, PS4, PS2, PSX${NC}
	${GREEN}Xbox filters: Xbox, Xbox360, XBL, XboxOne, X1${NC}
	${YELLOW}No set filters: anything other than listed above${NC}
	${YELLOW}debug: disables all filters${NC}
	Flags:
	-p, --populate \tRuns LagDrop to fill caches without performing filtering.
		 \tOnly run once (for ~1 hour). Do not run during regular
		 \tLagDrop use.
	-s, --smart \tSmart mode: Ping, TR averages and adjusts limits for
		\tincoming peers.
	-t, --tweak \tCreates tweak.txt for more parameters customization.
		 \tOptional, only run once. Do not run if tweak.txt exists.
	-b, --bytes \tWhen Sentinel is enabled, bytes are used instead of packets.
	-v, --verify \tWhen Sentinel is enabled, LagDrop will create verify files for
		\tconnected peers. Use the Excel macro to convert to graphs.
42Kmi.com | LagDrop.com"
)"
check_dependencies
IDENT="$(echo "$1"|sed -E "/^\-/d")"
##### Kill if no argument #####
if [ "${IDENT}" = "$(echo -n "${IDENT}" | grep -Eio "((\ ?){1,}|)")" ] && ! { echo "$@"|grep -Eoq "\-p"; }; then
echo -e "${MESSAGE}"
cleanall &> /dev/null &
exit
else
kill -9 $(echo $(ps|grep "$(echo "${0##*/}")"|grep -Ev "^(\s*)?($$)\b"|grep -Eo "^(\s*)?[0-9]{1,}\b"))|: #Kill previous instances. Can't run in two places at same time.
##### Kill if no argument #####
######################################################################################################
#               .////////////   -+osyyys+-   `////////////////////-                      `//////////`#
#              /Ny++++++++hM+/hNho/----:+hNo hN++++++oMMm++++++mMy`                      hMhhhhhhdMh #
#            `yN/        .NNmd/           :MmM/      hMy`    `hN/```````.--.`   `---.   oMy+++++omN` #
#           :Nd.        `mMM+     ods      NMs      oN+     /NMmdddddmMNhyshNhymdysydNo:MmhhhhhhNM:  #
#          sMo   `      yMM+     yMM:     /Md      -d.    `yMMd      :-     `s+`     :MMd      :Mo   #
#        -mm-   o`     /MMh.....+Md-     /MN.     `o`    -mdNN`     -o.      /+      /MN.     .Nh    #
#       +Ms`  .d-     .NmhhhhhNMm/     `sMM/      `     oMosM:     :Mm      sMs     `mM/      dN`    #
#     .hN:   :No      mm`   -hN+      +NNMs            yM-:Ms     `NM-     /Md      hMs      oM:     #
#    /Nh`   +Mh      sM-  -hNo`     /md/md             mm`Nd      hM+     .NN.     +Md      :Mo      #
#   yN+    yNm`     :NMm+yNo`     +md: hN.     `-      MhhN.     oMy      dM/     -MN.     `Nd       #
#  oM:               -MMNo`    `+md:  +M/      h.     .MNM:     -Mm`     sMs     `mM/      dN.       #
# :Ms               `mNo`    `oNMdssssMy      +m      :MMs     `NM-     /Md      yMy      oM:        #
#`NMmdddddds      sdms`      -::::::NMm`     -My      +Md      hM+     .NN.     +Mm`     :Ms         #
#        dN`     /MMy              yMN.     `mM/      oN.     oMh      dM/     -MN.     `Nd          #
#       sMhooooooNMMsoooooooooooooyMMdoooooodMMyoooooomdooooosMMsooooohMNoooooomMdoooooodN.          #
#       :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::.           #
######################################################################################################
##### 42Kmi International Competitive Gaming #####
##### Please visit and join 42Kmi.com #####
##### Be Glorious, Be Best #####
##### Don't Be Racist, Homophobic, Islamophobic, Misogynistic, Bigoted, Sexist, etc. #####
##### #BlackLivesMatter #####
##### Ban SLOW Peers #####
##### Special thanks to CharcoalBurst, robus9one, Deniz, Driphter, AverageJoeShmoe87, s1cp, CowMuffins, MajkStone, Nerf, sid, Sianos, sneakybae, fLcKrypt  #####
######Items only needed to initialize
IPTABLESVER=$(iptables -V|grep -Eo "([0-9]{1,}\.?){3}")
SUBFOLDER="cache"
##### Memory Dir #####
PINGMEM="cache/pingmem"
GEOMEMFILE="cache/geomem"
FILTERIGNORE="cache/filterignore"
##### Memory Dir #####
gogetem(){
	#Hexdump/xxd agnostic version
	RANDOMGET_GET="$(dd if=/dev/urandom | tr -dc '0-9A-F' | head -c 42)"
	if ! [ -f ""$DIR"/42Kmi/${FILTERIGNORE}" ]; then touch ""$DIR"/42Kmi/${FILTERIGNORE}"; fi
	if ! [ -f ""$DIR"/42Kmi/${GEOMEMFILE}" ]; then touch ""$DIR"/42Kmi/${GEOMEMFILE}"; fi
	if  { ls -1 /tmp|grep -Eio "[0-9a-f]{42}"; } &> /dev/null;  then
		RANDOMGET="$(ls -1 /tmp|grep -Eio "[0-9a-f]{42}"|sed -n 1p)"
		##### Decrypt existing log file #####
		if { [ -n "/tmp/$RANDOMGET" ] && ! { grep -Eq "^@" "/tmp/$RANDOMGET"; }; } then
		echo "$(tail +1 "/tmp/$RANDOMGET"|openssl enc ${HEARTBREAKHOTEL} -d)" > "/tmp/$RANDOMGET"
		else
		rm -f "/tmp/$RANDOMGET"
		fi; wait $!
	else
		RANDOMGET="${RANDOMGET_GET}"
		touch "/tmp/$RANDOMGET" #; chmod 000 "/tmp/$RANDOMGET"
	fi
	LTIME=$(date +%s -r "/tmp/$RANDOMGET")
	LSIZE=$(tail +1 "/tmp/$RANDOMGET"|wc -c)
}; gogetem && cache_tidy
##### Get ROUTER'S IPs #####
if [ "${SHELLIS}" = "ash" ]; then
	ROUTER=$(uci get network.lan.ipaddr|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b") # For OpenWRT
	#WAN_Address=$(ubus call network.interface.wan status|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|sed -n 1p)# For OpenWRT
else
	ROUTER=$(nvram get lan_ipaddr|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b") # For DD-WRT
	#WAN_Address=$(nvram get wan_ipaddr|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b") #DD-WRT
fi
ROUTERSHORT=$(echo "$ROUTER"|grep -Eo '(([0-9]{1,3}\.?){2})'|sed -E 's/\./\\./g'|sed -n 1p)
ROUTERSHORT="${ROUTERSHORT}[0-9]{1,3}\.[0-9]{1,3}"
ROUTERSHORT_POP=$(echo "$ROUTER"|grep -Eo '(([0-9]{1,3}\.?){2})'|sed -n 1p)
##### Get ROUTER'S IPs #####
##### Check ping version #####
if [ $(date +%Y -r "/bin/ping") -ge 2020 ]; then export PING_A=' -A'; else export PING_A=''; fi
##### Check ping version #####
##### Find Shell #####
SCRIPTNAME="${0##*/}"
DIR="${0%\/*}"
if [ -f ""$DIR"/42Kmi/${GEOMEMFILE}" ]; then sed -E -i "/#$/d" ""$DIR"/42Kmi/${GEOMEMFILE}"; fi #Housekeeping
##### Make Files #####
CONSOLENAME="${IDENT}"
##### Get Static IP #####
if [ "${SHELLIS}" = "ash" ]; then
	GETSTATIC="$(tail +1 "/var/dhcp.leases"|grep -i "$CONSOLENAME"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|sed -n 1p)" # for OpenWRT
else
	GETSTATIC="$(tail +1 "/tmp/dnsmasq.leases"|grep -i "$CONSOLENAME"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|sed -n 1p)" # for DD-WRT
fi
##### Get Static IP #####
##### Prepare LagDrop's IPTABLES Chains #####
maketables(){
	if ! { iptables -nL LDACCEPT|grep -E "Chain LDACCEPT \([1-9][0-9]{0,} reference(s)?\)"; }; then
	iptables -N LDACCEPT;iptables -P LDACCEPT ACCEPT;iptables -t filter -I FORWARD -j LDACCEPT; fi
	if ! { iptables -nL LDREJECT|grep -E "Chain LDREJECT \([1-9][0-9]{0,} reference(s)?\)"; }; then
	iptables -N LDREJECT;iptables -P LDREJECT REJECT ;iptables -t filter -I FORWARD -j LDREJECT; fi
	if ! { iptables -nL LDBAN|grep -E "Chain LDBAN \([1-9][0-9]{0,} reference(s)?\)"; }; then
	iptables -N LDBAN;iptables -P LDBAN REJECT;iptables -t filter -I FORWARD -j LDBAN; fi
	if ! { iptables -nL LDIGNORE|grep -E "Chain LDIGNORE \([0-9]?[0-9]{0,} reference(s)?\)"; }; then
	iptables -N LDIGNORE #|iptables -P LDIGNORE ACCEPT|iptables -t filter -A FORWARD -j LDIGNORE;
	fi
	if ! { iptables -nL LDTEMPHOLD|grep -E "Chain LDTEMPHOLD \([0-9]?[0-9]{0,} reference(s)?\)"; }; then
	iptables -N LDTEMPHOLD #|iptables -t filter -I INPUT -j LDTEMPHOLD;
	fi  #Hold for clear
	if ! { iptables -nL LDKTA|grep -E "Chain LDKTA \([1-9][0-9]{0,} reference(s)?\)"; }; then
	iptables -N LDKTA;iptables -P LDKTA REJECT;iptables -t filter -I FORWARD -j LDKTA; fi  #Table for DECONGEST
	if ! { iptables -nL LDSENTSTRIKE|grep -E "Chain LDSENTSTRIKE \([0-9]?[0-9]{0,} reference(s)?\)"; }; then
	iptables -N LDSENTSTRIKE #|iptables -t filter -I FORWARD -j LDSENTSTRIKE
	fi  #Table for Sentinel
}
maketables &> /dev/null &
##### Prepare LagDrop's IPTABLES Chains #####
##### Make Options #####
if [ ! -d "$DIR"/42Kmi ]; then mkdir -p "$DIR"/42Kmi ; fi
if [ ! -d "$DIR"/42Kmi/$SUBFOLDER ]; then mkdir -p "$DIR"/42Kmi/$SUBFOLDER ; fi
if ! { echo "$@"|grep -Eoq "\-p"; }; then
if [ ! -f "$DIR"/42Kmi/options_"$CONSOLENAME".txt ]; then echo "$CONSOLENAME=$GETSTATIC
PINGLIMIT=100
COUNT=10
SIZE=7500
TRACELIMIT=100
ACTION=REJECT
SENTINEL=OFF
SENTBAN=ON
STRIKECOUNT=10
STRIKERESET=ON
CLEARALLOWED=ON
CLEARBLOCKED=ON
CLEARLIMIT=10
CHECKPORTS=NO
PORTS=
RESTONMULTIPLAYER=NO
NUMBEROFPEERS=
DECONGEST=OFF
SWITCH=ON
;" > "$DIR"/42Kmi/options_"$CONSOLENAME".txt; fi ### Makes options file if it doesn't exist
fi
##### Make Options #####
##### Filter #####
{
case "${IDENT}" in
     "$(echo "${IDENT}" | grep -Eio "(nintendo(.*)?|wiiu|wii|switch|[0-9]?ds|NSW)")") #Nintendo
		NINTENDO_SERVERS="(45\.55\(\.[0-9]{1,3}){2})|(173\.255\.((19[2-9)|(2[0-9]{2}))\.[0-9]{1,3})|(38\.112\.28\.(9[6-9]))|(60\.32\.179\.((1[6-9])|(2[0-3])))|(60\.36\.183\.(15[2-9]))|(64\.124\.44\.((4[4-9])|(5[0-5])))|(64\.125\.103\.[0-9]{1,3})|(65\.166\.10\.((10[4-9])|11[01]))|(84\.37\.20\.((20[89])|(21[0-5])))|(84\.233\.128\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7]))|(84\.233\.202\.([0-9]|[1-2][0-9]|3[0-1]))|(89\.202\.218\.([0-9]|1[0-5]))|(125\.196\.255\.(19[6-9]|20[0-7]))|(125\.199\.254\.(4[89]|5[0-9]|6[0-7]))|(125\.206\.241\.(1[7-8][0-9]|19[01]))|(133\.205\.103\.(19[2-9]|20[0-7]))|(192\.195\.204\.[0-9]{1,3})|(194\.121\.124\.(22[4-9]|23[01]))|(194\.176\.154\.(16[89]|17[0-5]))|(195\.10\.13\.(1[6-9]|[2-6][0-9]|7[0-5]))|(195\.27\.92\.(9[2-9]|1[0-9]{2}|20[0-7]))|(195\.27\.195\.([0-9]|1[0-5]))|(195\.73\.250\.(22[4-5]|23[01]))|(195\.243\.236\.(13[6-9]|14[0-3]))|(202\.232\.234\.(12[89]|13[0-9]|14[0-3]))|(205\.166\.76\.[0-9]{1,3})|(206\.19\.110\.[0-9]{1,3})|(208\.186\.152\.[0-9]{1,3})|(210\.88\.88\.(17[6-9]|18[0-9]|19[01]))|(210\.138\.40\.(2[4-9]|3[01]))|(210\.151\.57\.(8[0-9]|9[0-5]))|(210\.169\.213\.(3[2-9]|[45][0-9]|6[0-3]))|(210\.172\.105\.(1[678][0-9]|19[01]))|(210\.233\.54\.(3[2-9]|4[0-7]))|(211\.8\.190\.(19[2-9]|2[01][0-9]|22[0-3]))|(212\.100\.231\.6[01])|(213\.69\.144\.(1[678][0-9]|19[01]))|(217\.161\.8\.2[4-7])|(219\.96\.82\.(17[6-9]|18[0-9]|19[01]))|(220\.109\.217\.16[0-7])|(207\.38\.([8-9]|1[0-5])\.([0-9]{1,3}))|(209\.67\.106\.141)"
		NIN_EXTRA="(95\.142\.154\.181|185\.157\.232\.22|163\.172\.141\.219|95\.216\.149\.205)"
		FILTERIP="^(${NINTENDO_SERVERS}|${NIN_EXTRA})"
		LOADEDFILTER="${RED}Nintendo${NC}"
          ;;
     "$(echo "${IDENT}" | grep -Eio "(playstation|ps[2-9]|sony|psx)")") #Sony
		SONY_SERVERS="(63\.241\.6\.(4[8-9]|5[0-5]))|(63\.241\.60\.4[0-4])|(64\.37\.(12[8-9]|1[3-9][0-9])\.)|(69\.153\.161\.(1[6-9]|2[0-9]|3[0-1]))|(199\.107\.70\.7[2-9])|(199\.108\.([0-9]|1[0-5])\.)|(199\.108\.(19[2-9]|20[0-7])\.[0-9]{1,3})"
        LIMELIGHTNETWORKS_SERVERS="(208\.111\.1(2[89]|[3-8][0-9]|9[01])\.[0-9]{1,3})" #CDN
		FREEWHEEL_MEDIA_SERVERS="75\.98\.70\.[0-9]{1,3}" #Media/TV Server, Comcast
		ADOBE_SERVERS="216.104.2(0[89]|1[0-9]|2[0-3])\.[0-9]{1,3}" #Media/TV Server
		FILTERIP="^(${SONY_SERVERS}|${LIMELIGHTNETWORKS_SERVERS}|${FREEWHEEL_MEDIA_SERVERS}|${ADOBE_SERVERS})"
		LOADEDFILTER="${BLUE}PlayStation${NC}"
          ;;
     "$(echo "${IDENT}" | grep -Eio "(microsoft|x[boxne1360]{1,}|xsx|SeriesX)")") #Microsoft
        FILTERIP="^104\.((6[4-9]{1})|(7[0-9]{1})|(8[0-9]{1})|(9[0-9]{1})|(10[0-9]{1})|(11[0-9]{1})|(12[0-7]{1}))|^13\.((6[4-9]{1})|(7[0-9]{1})|(8[0-9]{1})|(9[0-9]{1})|(10[0-7]{1}))|^131\.253\.(([2-4]{1}[1-9]{1}))|^134\.170\.|^137\.117\.|^137\.135\.|^138\.91\.|^152\.163\.|^157\.((5[4-9]{1})|60)\.|^168\.((6[1-3]{1}))\.|^191\.239\.160\.97|^23\.((3[2-9]{1})|(6[0-7]{1}))\.|^23\.((9[6-9]{1})|(10[0-3]{1}))\.|^2((2[4-9]{1})|(3[0-9]{1}))\.|^40\.((7[4-9]{1})|([8-9]{1}[0-9]{1})|(10[0-9]{1})|(11[0-9]{1})|(12[0-5]{1}))\.|^52\.((8[4-9]{1})|(9[0-5]{1}))\.|^54\.((22[4-9]{1})|(23[0-9]{1}))\.|^54\.((23[0-1]{1}))\.|^64\.86\.|^65\.((5[2-5]{1}))\.|^69\.164.\(([0-9]{1})|([1-5]{1}[0-9]{1})|((6[0-3]{1}))\.|^40.(7[4-9]|[8-9][0-9]|1[0-1][0-9]|12[0-7]).|^138.91.|^13.64.|^157.54.|^157\.(5[4-9]|60)\.|^(204\.79\.(19[5-7])\.[0-9]{1,3})|^(204\.79\.(19[5-7])\.[0-9]{1,3})"
		LOADEDFILTER="${GREEN}Xbox${NC}"
          ;;
     *) #PC/Debug/Custom
        FILTERIP="^99999" #Debug, Add IPs to whitelist.txt file instead
		LOADEDFILTER="${YELLOW}"${IDENT}"${NC}"
esac
}
if [ "${IDENT}" != "$(echo "${IDENT}" | grep -Eio "debug")" ] || [ $POPULATE != 0 ]; then
	ONTHEFLYFILTER="(((([0-9A-Za-z\-]+\.)*google\.(((co|ad|ae)(m)?(\.)?[a-z]{2})|cat)(/|$)))|GOOGLE\-CLOUD|GOGL|goog)|(amazonaws|AMAZO|akamaitechnologies|Akamai|AKAMAI\-[A-Z]{1,}|AKAMAI-TATAC)|(verizondigitalmedia|EDGECAST\-NETBLK\-[0-9]{1,})|(TWITT|twitter)|EDGECAST(.*)?|edgecast|cdn|nintendowifi\.net|(nintendo|xboxlive|sony|playstation)\.net|ps[2-9]|(nflxvideo|netflix)|(easo\.ea\.com|\.ea\.com)|\.1e100\.net|Sony Online Entertainment|cloudfront\.net|(facebook|fb\-net)|(IANA|IANA\-RESERVED)|(CLOUDFLARENET|Cloudflare)|BAD REQUEST|blizzard|(NC Interactive|ncsoft|NCINT)|(RIOT(\s)?GAMES|RIOT)|SQUARE ENIX|Valve Corporation|Ubisoft|(LVLT-ORG-[0-9]{1,}-[0-9]{1,})|not found|\b(dns|ns|NS|DNS)([0-9]{1,}?(\.|\-))\b|LINODE|oath(\s)holdings|thePlatform|(MoPub\,\sInc|mopub)|((([0-9A-Za-z\-]+\.)*nintendo\.(((co(m)?)((\.)?[a-z]{2})?))(/|$))|(([0-9A-Za-z\-]+\.)*nintendo-europe\.com(/|$))|(([0-9A-Za-z\-]+\.)*nintendoservicecentre\.co\.uk(/|$)))|(limelightnetworks\.com|limelightnetworks|LLNW|ipapi\.co)|(AMAZON\-DUB)" # Ignores if these words are found in whois requests
	AMAZON_SERVERS="(13\.(2(4[89]|5[01]))\.[0-9]{1,3}\.[0-9]{1,3})|(52\.([0-2][0-9]|3[[01])\.[0-9]{1,3}\.[0-9]{1,3})|(54\.23[01]\.[0-9]{1,3}\.[0-9]{1,3})|(52\.(3[2-9]|[4-5][0-9]|6[0-3])(\.[0-9]{1,3}){2})"
	GOOGLE_SERVERS="\b(173.194\.[0-9]{1,3}\.[0-9]{1,3})|(64\.233\.(1[6-8][0-9]|19[01])\.[0-9]{1,3})\b"
	MSFT_SERVERS="\b(52\.(1((4[5-9])|([5-8][0-9])|(9[0-1]))))|(52\.(2(2[4-9]|[3-5][0-9])))|(52\.(9[6-9]|10[0-9]|11[1-5]))|(131\.253\.1[2-8]\.[0-9]{1,3})\b"
	LINODE="\b(173\.255\.((19[2-9])|(2[0-9]{2})\.))\b"
	CLOUDFLARE="\b(162\.15[89]\.[0-9]{1,3}\.[0-9]{1,3})\b"
	LEVEL_3_SERVERS="\b(8\.(2((2[4-9])|[3-9][0-9]))\.[0-9]{1,3}\.[0-9]{1,3})\b"
	IANA_IPs="\b(10(\.[0-9]{1,3}){3})|(2(2[4-9]|3[0-9])(\.[0-9]{1,3}){3})|(255(\.([0-9]){1,3}){3})|(0\.)|(100\.((6[4-9])|[7-9][0-9]|1(([0-1][0-9])|(2[0-7]))))|(172\.((1[6-9])|(2[0-9])|(3[0-1])))\b"
	ARIN="\b(192\.136\.136\.[0-9]{1,3})\b"
	AKAMAI="\b((23.(3[2-9]|[4-5][0-9]|6[0-7])(\.[0-9]{1,3}){2})|(23\.7[2-9](\.[0-9]{1,3}){2})|(64\.86\.206\.[0-9]{1,3})|(184\.(2[4-9]|3[0-1])(\.[0-9]{1,3}){2}))\b"
	ONTHEFLYFILTER_IPs="${IANA_IPs}|${ARIN}|${MSFT_SERVERS}|${LINODE}|${CLOUDFLARE}|${AMAZON_SERVERS}|${GOOGLE_SERVERS}|${LEVEL_3_SERVERS}|${AKAMAI}|1\.0\.0\.1|1\.1\.1\.1|127\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|(151\.101\.[0-9]{1,3}\.[0-9]{1,3})|(148\.25[123]{1}\.[0-9]{1,3}\.[0-9]{1,3})" #Ignores these IPs, usually IANA reserved or something
	GOTTOTESTING="(Buckeye Cablevision|Google Fiber|Comcast Cable Communications|Charter Communications Inc|fios|SBC[A-Z0-9]{2}-[A-Z0-9]{4}-[A-Z0-9]{4}|AT&T Corp|Vodafone|Cogent Communications|Adams CATV|Movistar Fibra)" #Should prevent incidental misses.
else
	ONTHEFLYFILTER="${RANDOMGET}"
	ONTHEFLYFILTER_IPs="${RANDOMGET}"
	GOTTOTESTING="${RANDOMGET}"
fi
##### Filter #####
##### TWEAKS #####
if [ $MAKE_TWEAK = 1 ]; then
if [ ! -f "$DIR"/42Kmi/tweak.txt ]; then
echo -e "TWEAK_PINGRESOLUTION=1 #Number of pings sent
TWEAK_TRGETCOUNT=8 #Total number of Traceroute runs
TWEAK_SMARTLINECOUNT=8 #Number of lines before averaging
TWEAK_SMARTPERCENT=155 #Percentage of average before using average
TWEAK_SMART_AVG_COND=2 #Number of items that must be higher than average before using average
TWEAK_SENTMODE=5 #0 or 1=Difference, 2=X^2, 3=Difference or X^2, 4=Difference & X^2, 5=Difference & X^2 & StdDev
TWEAK_SENTLOSSLIMIT= #Number before Sentinel takes action
TWEAK_SENTINELDELAYSMALL=1 #Interval to record difference
TWEAK_ABS_VAL=1 #0 to disable absolute value in Sentinel calculation, 1 to enable"|sed -E "s/^(\s)*//g" > "$DIR"/42Kmi/tweak.txt
fi
fi
if [ -f "$DIR"/42Kmi/tweak.txt ]; then
	TWEAK_SETTINGS="$(tail +1 "$DIR"/42Kmi/tweak.txt|sed -E "s/(\s*)?#.*$//g"|sed -E "/(^#.*#$|^$|\;|#^[ \t]*$)|#/d"|sed -E 's/^.*=//g')" #Settings stored here, called from memory
	TWEAK_PINGRESOLUTION="$(echo "$TWEAK_SETTINGS"|sed -n 1p)"
	TWEAK_TRGETCOUNT="$(echo "$TWEAK_SETTINGS"|sed -n 2p)"
	TWEAK_SMARTLINECOUNT="$(echo "$TWEAK_SETTINGS"|sed -n 3p)"
	TWEAK_SMARTPERCENT="$(echo "$TWEAK_SETTINGS"|sed -n 4p)"
	TWEAK_SMART_AVG_COND="$(echo "$TWEAK_SETTINGS"|sed -n 5p)"
	TWEAK_SENTMODE="$(echo "$TWEAK_SETTINGS"|sed -n 6p)"
	TWEAK_SENTLOSSLIMIT="$(echo "$TWEAK_SETTINGS"|sed -n 7p)"
	TWEAK_SENTINELDELAYSMALL="$(echo "$TWEAK_SETTINGS"|sed -n 8p)"
	TWEAK_ABS_VAL="$(echo "$TWEAK_SETTINGS"|sed -n 9p)"
fi
##### TWEAKS #####
##### Get Country via ipapi.co #####
panama(){
	ROUND_TRIP=1
	VACATION="$1"
	for destination in "$VACATION"; do
		if [ $ROUND_TRIP -gt 0 ]; then
			n=0; while [[ $n -lt $ROUND_TRIP ]]; do { destination_new=$(echo -n $(echo -n "$destination"|openssl enc -base64)|sed "s/\s//g"); destination=$destination_new; } ; n=$((n+1)); done
			wait $!
			printf $destination_new
		else
			printf $destination
		fi
	done
	wait $!
}
if [ $SHOWLOCATION = 1 ]; then
	getcountry(){
		BANCOUNTRY="" #Reinitialize
		if [ -f "$DIR"/42Kmi/bancountry.txt ]; then
			#Country
			BANCOUNTRY="$(echo $(echo "$(tail +1 ""${DIR}"/42Kmi/bancountry.txt"|sed -E "s/$/|/g")")|sed -E "s/\|$//g"|sed -E "s/\| /|/g"|sed 's/,/\\,/g'|sed -E "s/\|$//")" # "CC" format for Country only; "RR, CC" format for Region by Country; "(RR|GG), CC" format for multiple regions by country
		fi
		LDCOUNTRY="" #Reinitialize
		checkcountry(){
			GEOMEM="$(tail +1 ""$DIR"/42Kmi/${GEOMEMFILE}")"
			if { echo "$GEOMEM"|grep -Eoq "^("$peer"|"$peerenc")#"; };then
				LDCOUNTRY=$(echo "$GEOMEM"|grep -E "^("$peer"|"$peerenc")#"|sed -n 1p|sed -E "s/^($peer|$peerenc)#//g")
			else
				{
					LOCATION_DATA_STORE="$(curl --no-keepalive --no-buffer --connect-timeout ${CURL_TIMEOUT} -sk -A "${RANDOMGET_GET}" "https://ipapi.co/"$peer"/json/"|sed -E "/\{|\}/d"|sed -E "s/^\s*//g"|sed "s/,$//g"|sed "s/^.*:\s*//g"|sed -E "s/\"//g")"
					if ! { echo "$LOCATION_DATA_STORE"|grep -Eqi "RateLimited"; }; then
						LOCATE_STORE_CITY="$(echo "$LOCATION_DATA_STORE"|sed -n 2p)"
						LOCATE_STORE_REGION="$(echo "$LOCATION_DATA_STORE"|sed -n 3p)"
						LOCATE_STORE_REGION_CODE="$(echo "$LOCATION_DATA_STORE"|sed -n 4p)"
						LOCATE_STORE_COUNTRY="$(echo "$LOCATION_DATA_STORE"|sed -n 5p)"
						LOCATE_STORE_COUNTRY_CODE="$(echo "$LOCATION_DATA_STORE"|sed -n 6p)"
						LOCATE_STORE_COUNTRY_CODE_ISO="$(echo "$LOCATION_DATA_STORE"|sed -n 7p)"
						LOCATE_STORE_COUNTRY_CODE_TLD="$(echo "$LOCATION_DATA_STORE"|sed -n 9p|sed -E "/\.//"|awk '{print toupper($0)}')"
						LOCATE_STORE_CONTINENT_CODE="$(echo "$LOCATION_DATA_STORE"|sed -n 11p)"
					fi
					LOC1="$LOCATE_STORE_CITY" #City
					if { echo "$LOCATE_STORE_REGION_CODE"|grep -Eiq "(null|[0-9]{2,})"; }; then LOC2="$LOCATE_STORE_REGION";else LOC2="$LOCATE_STORE_REGION_CODE";fi #Region
					if { echo "$LOC2"|grep -iq "null"; }; then LOC2="";fi #Region
					LOC3="$LOCATE_STORE_COUNTRY_CODE" #Country
					LOC4="$LOCATE_STORE_CONTINENT_CODE" #Continent
				}
				LDCOUNTRY="${LOC1}, ${LOC2}, ${LOC3}, ${LOC4}"
				wait $!
				location_corrections(){
					#Add corrections for formatting.
					case "${LDCOUNTRY}" in
					#Blank
						"$(echo "${LDCOUNTRY}"|grep -Eo "^$")")
							LDCOUNTRY="NOT FOUND - CANNOT CONNECT"
							;;
					#All
						"$(echo "${LDCOUNTRY}"|grep -F "City of ")")
							LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/City of //g")"
							;;
						"$(echo "${LDCOUNTRY}"|grep -F "Township of ")")
							LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/Township of //g")"
							;;
						"$(echo "${LDCOUNTRY}"|grep -F "Fort ")")
							LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/Fort /Ft. /g")"
							;;
						"$(echo "${LDCOUNTRY}"|grep -F "Mount ")")
							LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/Mount /Mt. /g")"
							;;
						"$(echo "${LDCOUNTRY}"|grep -F "Saint ")")
							LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/Saint /St. /g")"
							;;
						"$(echo "${LDCOUNTRY}"|grep -F "St ")")
							LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/St /St. /g")"
							;;
					#AF
					#AS
						"$(echo "${LDCOUNTRY}"|grep -Eo "^Taipei\, TPE\, TW\, AS\, Peicity Digital Cable Television\.\, LTD")")
							LDCOUNTRY="Taipei, TPE, TW, AS"
							;;
						"$(echo "${LDCOUNTRY}"|grep -Eo "^水果湖街道\, CN\, AS")")
							LDCOUNTRY="Wuhan, HB, CN, AS" #Shuiguo Lake, HB, CN, AS
							;;
					#AT
					#EU
						"$(echo "${LDCOUNTRY}"|grep -Eo "^Moscow\, MOW\, RU\, EU\, [a-zA-Z]{3,} Moscow city telephone network")")
							LDCOUNTRY="Moscow, MOW, RU, EU"
							;;
						"$(echo "${LDCOUNTRY}"|grep -Eo "RU\, EU\, [a-zA-Z]{3,} Moscow city telephone network")")
							LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/(\, RU\, EU).*$/\1/g")"
							;;
					#NA
						"$(echo "${LDCOUNTRY}"|grep -Eo "^Emigrant Gap\, US\, NA")")
							LDCOUNTRY="Emigrant Gap, CA, US, NA"
							;;
						"$(echo "${LDCOUNTRY}"|grep -Eo "^Research Triangle Park, US, NA")")
							LDCOUNTRY="Research Triangle Park, NC, US, NA"
							;;
						"$(echo "${LDCOUNTRY}"|grep -Eo "^(Newcastle\, US\, NA)|(Newcastle\, Washington\, US\, NA)")")
							LDCOUNTRY="Newcastle, WA, US, NA"
							;;
						"$(echo "${LDCOUNTRY}"|grep -Eo "^Maplewood\, US\, NA")")
							LDCOUNTRY="Maplewood, MN, US, NA"
							;;
						"$(echo "${LDCOUNTRY}"|grep -Eo "^(Northlake\, US\, NA)|(Northlake\, Illinois\, US)")")
							LDCOUNTRY="Northlake, Il, US, NA"
							;;
						"$(echo "${LDCOUNTRY}"|grep -Eo "^Tysons\, Virginia\, US\, NA")")
							LDCOUNTRY="Tysons, VA, US, NA"
							;;
						#UnitedStates
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Alabama\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Alabama\,/, AL,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Alaska\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Alaska\,/, AK,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Arizona\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Arizona\,/, AZ,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Arkansas\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Arkansas\,/, AR,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, California\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, California\,/, CA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Colorado\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Colorado\,/, CO,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Delaware\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Delaware\,/, DE,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Florida\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Florida\,/, FL,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Georgia\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Georgia\,/, GA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Hawaii\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Hawaii\,/, HI,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Idaho\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Idaho\,/, ID,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Illinois\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Illinois\,/, IL,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Indiana\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Indiana\,/, IN,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Iowa\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Iowa\,/, IA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Kansas\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Kansas\,/, KS,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Kentucky\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Kentucky\,/, KY,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Louisiana\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Louisiana\,/, LA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Maine\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Maine\,/, ME,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Maryland\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Maryland\,/, MD,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Massachusetts\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Massachusetts\,/, MA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Michigan\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Michigan\,/, MI,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Minnesota\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Minnesota\,/, MN,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Mississippi\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Mississippi\,/, MS,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Missouri\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Missouri\,/, MO,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Montana\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Montana\,/, MT,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Nebraska\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Nebraska\,/, NE,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Nevada\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Nevada\,/, NV,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, New Hampshire\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, New Hampshire\,/, NH,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, New Jersey\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, New Jersey\,/, NJ,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, New Mexico\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, New Mexico\,/, NM,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, New York\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, New York\,/, NY,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, North Carolina\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, North Carolina\,/, NC,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, North Dakota\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, North Dakota\,/, ND,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Ohio\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Ohio\,/, OH,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Oklahoma\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Oklahoma\,/, OK,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Oregon\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Oregon\,/, OR,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Pennsylvania\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Pennsylvania\,/, PA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Rhode Island\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Rhode Island\,/, RI,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, South Carolina\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, South Carolina\,/, SC,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, South Dakota\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, South Dakota\,/, SD,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Tennessee\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Tennessee\,/, TN,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Texas\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Texas\,/, TX,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Utah\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Utah\,/, UT,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Vermont\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Vermont\,/, VT,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Virginia\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Virginia\,/, VA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Washington\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Washington\,/, WA,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, West Virginia\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, West Virginia\,/, WV,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Wisconsin\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Wisconsin\,/, WI,/g")"
									;;
								"$(echo "${LDCOUNTRY}"|grep -Eoi "^(.*)\, Wyoming\, US\, NA")")
									LDCOUNTRY="$(echo "$LDCOUNTRY"|sed -E "s/\, Wyoming\,/, WY,/g")"
									;;
					#SA
						"$(echo "${LDCOUNTRY}"|grep -Eo "^Manguinhos\, BR\, SA")")
							LDCOUNTRY="Manguinhos, RJ, BR, SA"
							;;
					#OC
					#General null region
						"$(echo "${LDCOUNTRY}"|grep -Eo "^([a-zA-Z -]{1,})\, ([A-Z]{2})\, ([A-Z]{2})$")")
							LDCOUNTRY="$(echo "${LDCOUNTRY}"|sed -E "s/([a-zA-Z -]{1,})\, ([A-Z]{2})\, ([A-Z]{2})/\1, 0null0, \2, \3/g")"
							;;
					esac
				}
					location_corrections
				if ! { grep -Eoq "^("$peer"|"$peerenc")#" ""$DIR"/42Kmi/${GEOMEMFILE}"; }; then echo ""$peerenc"#"$LDCOUNTRY"" >> ""$DIR"/42Kmi/${GEOMEMFILE}"; fi
				LDCOUNTRYCHECK="$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")"
				CONTINENT="$(echo $LDCOUNTRY|sed -E "s/.{4}$//g")"
			fi
			if echo "$LDCOUNTRY"|grep -E "AF$"; then
				LDCOUNTRY_toLog="${GREEN}$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")${NC}"
				elif echo "$LDCOUNTRY"|grep -E "AN$"; then
				LDCOUNTRY_toLog="${WHITE}$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")${NC}"
				elif echo "$LDCOUNTRY"|grep -E "AS$"; then
				LDCOUNTRY_toLog="${LIGHTRED}$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")${NC}"
				elif echo "$LDCOUNTRY"|grep -E "EU$"; then
				LDCOUNTRY_toLog="${LIGHTBLUE}$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")${NC}"
				elif echo "$LDCOUNTRY"|grep -E "NA$"; then
				LDCOUNTRY_toLog="${MAGENTA}$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")${NC}"
				elif echo "$LDCOUNTRY"|grep -E "OC$"; then
				LDCOUNTRY_toLog="${CYAN}$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")${NC}"
				elif echo "$LDCOUNTRY"|grep -E "SA$"; then
				LDCOUNTRY_toLog="${YELLOW}$(echo "$LDCOUNTRY"|sed -E "s/.{4}$//g")${NC}"
			fi
			LDCOUNTRY_toLog="${LDCOUNTRY_toLog// /%}"
		}
		##### Regional & Country Bans #####
			bancountry(){
				BANCOUNTRY="" #Reinitialize
				if [ -f "$DIR"/42Kmi/bancountry.txt ]; then
					#Country
					BANCOUNTRY="$(echo $(echo "$(tail +1 ""${DIR}"/42Kmi/bancountry.txt"|sed -E "s/$/|/g")")|sed -E "s/\|$//g"|sed -E "s/\| /|/g"|sed 's/,/\\,/g'|sed -E "s/\|$//"|sed -E "s/\s/\%/g")" # "CC" format for Country only; "RR, CC" format for Region by Country; "(RR|GG), CC" format for multiple regions by country
					if { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"| grep -Ei "($BANCOUNTRY)"; }; then
						BANCOUNTRYIP=$(tail +1 "/tmp/$RANDOMGET"|grep -Ei "($BANCOUNTRY).\[.*$"|grep -Eo "(([0-9]{1,3}\.){3})([0-9]{1,3})\b""${ADDWHITELIST}")
						for ip in $BANCOUNTRYIP; do
							if ! { iptables -nL LDBAN|grep -Eoq "\b${ip}\b"; }; then
								eval "iptables -A LDBAN -s $ip -d $CONSOLE -j REJECT --reject-with icmp-host-prohibited "${WAITLOCK}""; wait $!
							fi
							TABLENAMES="LDACCEPT LDREJECT LDTEMPHOLD"
							for tablename in $TABLENAMES; do
								TABLELINENUMBER=$(iptables --line-number -nL $tablename|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
								if iptables -nL $tablename "$WAITLOCK"; then
									eval "iptables -D $tablename "$TABLELINENUMBER""
								fi
							done
							sed -i -E "s/#(.\[[0-9]{1}\;[0-9]{2}m)?(${ip})\b/$(echo -e "#${BG_RED}")\2/g" "/tmp/$RANDOMGET"; sleep 5 #Background color notification for banned country/region
							sed -i -E "/(m)?${ip}#/d" "/tmp/$RANDOMGET"
						done &
					fi &
				fi
			}
		##### Regional & Country Bans #####
		checkcountry; bancountry
	}
fi
##### Get Country via ipapi.co #####
timestamps(){ EPOCH="$(date +%s)";DATETIME="$(date -d "@$EPOCH" +"%Y-%m-%d#%X")"; }
remove_tmp_data(){
	IP_FILENAME="$(panama ${ip})"
	rm -f "/tmp/${LDTEMPFOLDER}/ld_act_state/${IP_FILENAME}#"
	rm -f "/tmp/${LDTEMPFOLDER}/ld_state_counter/${IP_FILENAME}#"
	rm -f "/tmp/${LDTEMPFOLDER}/oldval/${IP_FILENAME}#"
}
cleanliness(){
	#Check tables, delete from tables if not in log.
	cleantable(){
		TABLENAMES="LDACCEPT LDREJECT LDTEMPHOLD"
		for tablename in $TABLENAMES; do
			IPLIST="$(iptables -nL $tablename|tail +3|grep -E "\b${CONSOLE}\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|grep -Ev "\b(${CONSOLE}|0.0.0.0)\b")"
				for ip in $IPLIST; do
				if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -E "\b${ip}#"; }; then
					case $tablename in
					LDACCEPT)
						TABLELINENUMBER=$(iptables --line-number -nL $LDACCEPT|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
						remove_tmp_data
						eval "iptables -D LDACCEPT $TABLELINENUMBER"
						;;
					LDREJECT)
						TABLELINENUMBER=$(iptables --line-number -nL $LDREJECT|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
						eval "iptables -D LDREJECT $TABLELINENUMBER"
					;;
					LDTEMPHOLD)
						TABLELINENUMBER=$(iptables --line-number -nL $LDTEMPHOLD|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
						eval "iptables -D LDTEMPHOLD $TABLELINENUMBER"
					;;
					esac
				fi
			done
		done &
	}
	#Check log, delete from log if not in iptable
	cleanlog(){
		TABLENAMES="LDACCEPT LDREJECT"
		for tablename in $TABLENAMES; do
			case $tablename in
				LDACCEPT)
					IPLISTACCEPT="$(tail +1 "/tmp/$RANDOMGET"|sed -E "/\b${SENTINEL_BAN_MESSAGE}\b/d"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Ev "\b(${RESPONSE3}|${SENTINEL_BAN_MESSAGE})\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
					for ip in $IPLISTACCEPT; do
						if [ "${SHELLIS}" != "ash" ]; then
							if ! { iptables -nL $LDACCEPT|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
								remove_tmp_data
								sed -i -E "/(m)?(${ip})\b/d" "/tmp/$RANDOMGET"
							fi
						else
							if ! { iptables -nL $LDACCEPT "$WAITLOCK"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
								remove_tmp_data
								sed -i -E "/(m)?(${ip})\b/d" "/tmp/$RANDOMGET"
							fi
						fi
					done
				;;
				LDREJECT)
					IPLISTREJECT="$(tail +1 "/tmp/$RANDOMGET"|sed -E "/\b${SENTINEL_BAN_MESSAGE}\b/d"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -E "\b${RESPONSE3}\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
					for ip in $IPLISTREJECT; do
						if [ "${SHELLIS}" != "ash" ]; then
							if ! { iptables -nL $LDREJECT|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
								sed -i -E "/(m)?(${ip})\b/d" "/tmp/$RANDOMGET"
							fi
						else
							if ! { iptables -nL $LDREJECT "$WAITLOCK"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
								sed -i -E "/(m)?(${ip})\b/d" "/tmp/$RANDOMGET"
							fi
						fi
					done
				;;
			esac
		done &
	}
	#If IP is in ban table, remove from other tables.
	bantidy(){
		BANDTIDYLIST="$(iptables -nL LDBAN|grep -E "\b${CONSOLE}\b"|awk '{printf $4"\n"}'|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
		for ip in $BANDTIDYLIST; do
			LINENUMBERBANDTIDYLISTACCEPTIP=$(iptables --line-number -nL LDACCEPT|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
			LINENUMBERBANDTIDYLISTREJECTIP=$(iptables --line-number -nL LDREJECT|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
			LINENUMBERBANDTIDYLISTTEMPHOLDIP=$(iptables --line-number -nL LDTEMPHOLD|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
			LINENUMBERBANDTIDYLISTSENTSTRIKEIP="$(iptables --line-number -nL LDSENTSTRIKE|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}"|sort -nr)"
			if { iptables -nL LDACCEPT "$WAITLOCK"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
				eval "iptables -D LDACCEPT "$LINENUMBERBANDTIDYLISTACCEPTIP""
				sed -i -E "/(m)?(${ip})\b/d" "/tmp/$RANDOMGET"
				remove_tmp_data
			fi
			if { iptables -nL LDREJECT "$WAITLOCK"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
				eval "iptables -D LDREJECT "$LINENUMBERBANDTIDYLISTREJECTIP""
				sed -i -E "/(m)?(${ip})\b/d" "/tmp/$RANDOMGET"
			fi
			if { iptables -nL LDTEMPHOLD "$WAITLOCK"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
				eval "iptables -D LDTEMPHOLD "$LINENUMBERBANDTIDYLISTTEMPHOLDIP""
			fi
			if { iptables -nL LDSENTSTRIKE "$WAITLOCK"|grep -Eoq "\b${ip}\b"; }; then
				for line in $LINENUMBERBANDTIDYLISTSENTSTRIKEIP; do
					eval "iptables -D LDSENTSTRIKE "$line""
				done
			fi
		done &
	}
	##### Clean Hold #####
	CLEANLDTEMPHOLDLIST="$(iptables -nL LDTEMPHOLD|tail +3|awk '{printf $3"\n"}')"
	for ip in $CLEANLDTEMPHOLDLIST; do
		CLEANLDTEMPHOLDNUM=$(iptables --line-number -nL LDTEMPHOLD|grep -E "\b${CONSOLE}\b"|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
		if { ! { echo "$(iptables -nL LDACCEPT; iptables -nL LDREJECT)"|grep -Eoq "\b${ip}\b"; } || { iptables -nL LDBAN|grep -Eoq "\b${ip}\b"; }; }; then
			eval "iptables -D LDTEMPHOLD "$CLEANLDTEMPHOLDNUM"";
		fi
		wait $!
	done
	##### Clean Hold #####
	#cleansentinel
	sentinel_bans &
	zerotables(){
		for tablename in LDREJECT LDBAN LDIGNORE LDSENTSTRIKE LDTEMPHOLD LDKTA; do
			iptables -Z $tablename
		done
	}
bantidy
cleantable
cleanlog
}
	cleansentinel(){
		cleanup_sentinel(){
			##### Clear LDSENTSTRIKE #####
			CLEANLDSENTSTRIKENUM="$(echo $(iptables --line-number -nL LDSENTSTRIKE|grep -E "\b(${ip})\b"|grep -Eo "^(\s*)?[0-9]{1,}"|sort -nr))"
			for line in $CLEANLDSENTSTRIKENUM; do
				eval "iptables -D LDSENTSTRIKE $line" &
			done
			##### Clear LDSENTSTRIKE #####
		}
		##### Clean Sentinel #####
		CLEANLDSENTSTRIKELIST="$(iptables -nL LDSENTSTRIKE|tail +3|awk '{printf $3"\n"}'|awk '!a[$0]++')"
		for ip in $CLEANLDSENTSTRIKELIST; do
			STRIKE_MARK_COUNT_GET_CLEAN="$(grep -E "#(.\[[0-9]{1}\;[0-9]{2}m)?(${ip})\b" "/tmp/$RANDOMGET"|sed "/${SENTINEL_BAN_MESSAGE}/d"|grep -Eo "(${STRIKE_MARK_SYMB}{1,}$)"|wc -c)"
			if [ $STRIKE_MARK_COUNT_GET_CLEAN -le 0 ]; then STRIKE_MARK_COUNT_GET_CLEAN=0; else STRIKE_MARK_COUNT_GET_CLEAN=$(( STRIKE_MARK_COUNT_GET_CLEAN - 1 )); fi
			#If IP exists in LDACCEPT and has zero strikes
			if [ $STRIKE_MARK_COUNT_GET_CLEAN -le 0 ] || [ $STRIKE_MARK_COUNT_GET_CLEAN = "" ] || [ -z $STRIKE_MARK_COUNT_GET_CLEAN  ] ; then
				cleanup_sentinel
			fi
			if { iptables -nL LDACCEPT "$WAITLOCK"|grep -Eoq "\b(${ip})\b"; }; then
				if [ $STRIKE_MARK_COUNT_GET_CLEAN -le 0 ] || [ $STRIKE_MARK_COUNT_GET_CLEAN = "" ] || [ -z $STRIKE_MARK_COUNT_GET_CLEAN  ] ; then
					cleanup_sentinel
				fi
			fi
			if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b(${ip})\b"; }; then
				cleanup_sentinel
			fi
			# If IP does not exist in LDACCEPT
			if ! { iptables -nL LDACCEPT "$WAITLOCK"|grep -Eoq "\b(${ip})\b"; }; then
				#cleanup_sentinel
				iptables -D LDSENTSTRIKE -s $ip
			fi
		done
		##### Clean Sentinel #####
	}
	##### SENTINEL BANS #####
	sentinel_bans(){
		SENTINEL_BANS_LIST_GET="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Ev "(${RESPONSE1}|${RESPONSE2}|${RESPONSE3})"|grep -E "${SENTINEL_BAN_MESSAGE}"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
		for ip in $SENTINEL_BANS_LIST_GET; do
			CONSOLE=$(grep -E "\b($CONSOLE)\b" "$IPCONNECT_SOURCE"|grep -E "\b($ip)\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++'|grep -E "\b($CONSOLE)\b")
			if ! { iptables -nL LDBAN "$WAITLOCK"|grep -Eoq "\b${ip}\b"; }; then
				eval "iptables -A LDBAN -s $ip -d $CONSOLE -j REJECT "${WAITLOCK}""
			fi
		done
	}
	##### SENTINEL BANS #####
ping_tr_results(){
	#PING-TR RESULTS
	LIMITPERCENT="85"
	if { [ $PINGFULL -gt $(( LIMIT )) ] || [ $TRAVGFULL -gt $(( TRACELIMIT )) ]; }; then
		RESULT="${RED}${RESPONSE3}${NC}"
	else
		if [ $PINGFULL -le $(( LIMIT * LIMITPERCENT / 100 )) ] && [ $TRAVGFULL -le $(( TRACELIMIT * LIMITPERCENT / 100 )) ]; then
			RESULT="${LIGHTGREEN}${RESPONSE1}${NC}"
		else
			if [ $PINGFULL -gt $(( LIMIT * LIMITPERCENT / 100 )) ] && [ $PINGFULL -le $(( LIMIT )) ] && [ $TRAVGFULL -le $(( TRACELIMIT )) ] || [ $TRAVGFULL -gt $(( TRACELIMIT * LIMITPERCENT / 100 )) ] && [ $TRAVGFULL -le $(( TRACELIMIT )) ] && [ $PINGFULL -le $(( LIMIT )) ]; then
				RESULT="${YELLOW}${RESPONSE2}${NC}"
			fi
		fi
	fi
}
pingavgfornull(){
	if [ $SHOWLOCATION = 1 ]; then
		CALL_PING_MEM="$(tail +1 ""$DIR"/42Kmi/${PINGMEM}")"
		PING_HIST_AVG="" #Resets Ping history average to prevent unneeded multiple use
		if [ $POPULATE = 1 ]; then
			if ! { [ "${PINGFULL}" = "--" ] || [ "${PINGFULL}" = "0" ] || [ $PINGFULLDECIMAL = "0" ] || [ $PINGFULLDECIMAL = "--" ] || [ $PINGFULLDECIMAL = "\-\-" ]; } && ! { grep -F "$(echo -e "${PINGFULLDECIMAL}#${LDCOUNTRY}#"|sed "s/ms#/#/g")" ""$DIR"/42Kmi/${PINGMEM}"; }; then
				echo -e "${PINGFULLDECIMAL}#${LDCOUNTRY}#"|sed "s/ms#/#/g"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g" >> ""$DIR"/42Kmi/${PINGMEM}"
			fi
		else
			if ! { [ "${PINGFULL}" = "--" ] || [ "${PINGFULL}" = "0" ] || [ $PINGFULLDECIMAL = "0" ] || [ $PINGFULLDECIMAL = "--" ] || [ $PINGFULLDECIMAL = "\-\-" ]; }; then
				echo -e "${PINGFULLDECIMAL}#${LDCOUNTRY}#"|sed "s/ms#/#/g"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g" >> ""$DIR"/42Kmi/${PINGMEM}"
			fi
		fi
		PING_HIST_AVG_MIN=5 #Minimum number of similar regions to count before taking average
		if { [ "${PINGFULL}" = "--" ] || [ "${PINGFULL}" = "0" ] || [ $PINGFULLDECIMAL = "0" ] || [ $PINGFULLDECIMAL = "--" ] || [ $PINGFULLDECIMAL = "\-\-" ]; }; then
			LOCATION_filter=$(echo -e "#${LDCOUNTRY}#"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g")
			LOCATION_filter_Continent=$(echo "${LOCATION_filter}"|grep -Eo "[A-Z]{2}#$")
			LOCAL_LINES_count=$(echo "${CALL_PING_MEM}"|grep -Ec "${LOCATION_filter}")
			PING_HIST_AVG_COLOR=0 #Green for same city average
				if [ $LOCAL_LINES_count -lt $PING_HIST_AVG_MIN ]; then
					REGION_filter=$(echo -e "$LOCATION_filter"|grep -Eo "(,\ (.*\,)? [A-Z]{2}, [A-Z]{2}#)"|sed -E "s/(^\s\,)//g")
					REGION_LINES_count=$(echo "${CALL_PING_MEM}"|grep -Ec "${REGION_filter}")
					PING_HIST_AVG_COLOR=1 #Yellow for same region average
					if [ $REGION_LINES_count -lt $(( $PING_HIST_AVG_MIN * 2 )) ]; then
						COUNTRY_filter=$(echo -e "$REGION_filter"|grep -Eo "[A-Z]{2}, [A-Z]{2}#$")
						COUNTRY_LINES_count=$(echo "${CALL_PING_MEM}"|grep -Ec "${COUNTRY_filter}")
						PING_HIST_AVG_COLOR=2 #Cyan for same country average
							if [ $COUNTRY_LINES_count -lt $(( $PING_HIST_AVG_MIN * 5 )) ]; then
								CONTINENT_filter=$(echo -e "$COUNTRY_filter"|grep -Eo "[A-Z]{2}#$")
								CONTINENT_LINES_count=$(echo "${CALL_PING_MEM}"|grep -Ec "${CONTINENT_filter}")
								PING_HIST_AVG_COLOR=3 #Magenta for same continent average
								if [ $CONTINENT_LINES_count -lt $(( $PING_HIST_AVG_MIN * 12 )) ]; then
									PING_HIST_AVG_COLOR="XXXXXXXXXX"
									PINGFULL=""
									PINGFULLDECIMAL="$NULLTEXT"
								else
									GET_PING_VALUES=$(echo $(echo "${CALL_PING_MEM}"|grep "$LOCATION_filter_Continent"|grep "${CONTINENT_filter}"|sed -E "s/(ms)?#.*$//g"|sed "s/\.//g"|sed -E "s/$/+/g")|sed -E "s/(\+$)//g")
								fi
						else
							GET_PING_VALUES=$(echo $(echo "${CALL_PING_MEM}"|grep "$LOCATION_filter_Continent"|grep "${COUNTRY_filter}"|sed -E "s/(ms)?#.*$//g"|sed "s/\.//g"|sed -E "s/$/+/g")|sed -E "s/(\+$)//g")
							fi
					else
						GET_PING_VALUES=$(echo $(echo "${CALL_PING_MEM}"|grep "$LOCATION_filter_Continent"|grep "${REGION_filter}"|sed -E "s/(ms)?#.*$//g"|sed "s/\.//g"|sed -E "s/$/+/g")|sed -E "s/(\+$)//g")
					fi
				else
					GET_PING_VALUES=$(echo $(echo "${CALL_PING_MEM}"|grep "$LOCATION_filter_Continent"|grep "${LOCATION_filter}"|sed -E "s/(ms)?#.*$//g"|sed "s/\.//g"|sed -E "s/$/+/g")|sed -E "s/(\+$)//g")
				fi
			GET_PING_VALUES_COUNT=$(echo "$GET_PING_VALUES"|wc -w); if [ $GET_PING_VALUES_COUNT = 0 ]; then GET_PING_VALUES_COUNT=1; fi
			GET_PING_VALUES_SUM=$(( $(echo "$GET_PING_VALUES") ))
			PING_HIST_AVG=$(( GET_PING_VALUES_SUM / GET_PING_VALUES_COUNT ))
			PING_HIST_AVG_DECIMAL=$(echo "$(echo "$PING_HIST_AVG" | sed 's/.\{3\}$/.&/'| sed -E 's/^\./0./g'|sed -E 's/$/ms/g')");PING_HIST_AVG_DECIMAL=$(echo -n "$PING_HIST_AVG_DECIMAL"|sed -E "s/-//g")
		fi
			if [ $FORNULL = 1 ] && { [ $PINGFULLDECIMAL = "$PINGFULLDECIMAL" ] || [ $PINGFULLDECIMAL = "0" ]; }; then
				if [ $PING_HIST_AVG != 0 ]; then
					PINGFULL=$PING_HIST_AVG
					case "$PING_HIST_AVG_COLOR" in
						0) #City
							PINGFULLDECIMAL=$(echo -e "${GREEN}${CUSSORLEFT1}¹${PING_HIST_AVG_DECIMAL}${NC}")
							;;
						1) #State/Provence/Territory
							PINGFULLDECIMAL=$(echo -e "${YELLOW}${CUSSORLEFT1}²${PING_HIST_AVG_DECIMAL}${NC}")
							;;
						2) #Country
							PINGFULLDECIMAL=$(echo -e "${CYAN}${CUSSORLEFT1}³${PING_HIST_AVG_DECIMAL}${NC}")
							;;
						3) #Continent
							PINGFULLDECIMAL=$(echo -e "${MAGENTA}${CUSSORLEFT1}*${PING_HIST_AVG_DECIMAL}${NC}")
							;;
						XXXXXXXXXX)
							PINGFULLDECIMAL="$NULLTEXT"
							;;
					esac
					ping_tr_results
				else
					PINGFULLDECIMAL="$NULLTEXT"
				fi
			fi
	fi
}
export STRIKE_MARK_SYMB="~"
export CONNECT_MARK_SYMB="●"
export NOT_CONNECT_MARK_SYMB="×"
export CONNECT_MARK="$(echo -e "${GREEN}${CONNECT_MARK_SYMB}${NC}")"
export NOT_CONNECT_MARK="$(echo -e "${RED}${NOT_CONNECT_MARK_SYMB}${NC}")"
export PENDING="$(echo -e "${YELLOW}¤${NC}")"
export STANDBY_SYMB="$(echo -e "${MAGENTA}■${NC}")"
export ACT_PLACEHOLD="@"
meatandtatoes(){
	borneopeer="$peer"
	if ! { iptables -nL LDIGNORE "$WAITLOCK"|grep -Eoq "\b($peer)\b"; }; then
	{
		# Add FILTERIP to LDIGNORE
		if { echo "$peer"|grep -Eoq "\b(${FILTERIP})\b"; }; then
			if ! { iptables -nL LDIGNORE "$WAITLOCK"|grep -Eoq "\b($peer)\b"; }; then
				for ip in $CONSOLE_SEPARATE; do
					eval "iptables -A LDIGNORE -p all -s $peer -d $ip -j ACCEPT "${WAITLOCK}""
				done
			fi
		fi &
		# Checks filterignore cache, adds to LDIGNORE to prevent unnecessary checking
		if ! { echo "$EXIST_LIST_GET"|grep -Eoq "\b(${peer})\b"; }; then
			if { grep -Eoq "^(${peer}|${peerenc})$" ""$DIR"/42Kmi/${FILTERIGNORE}"; }; then
				if ! { iptables -nL LDIGNORE "$WAITLOCK"|grep -Eoq "\b($peer)\b"; }; then
					for ip in $CONSOLE_SEPARATE; do
						eval "iptables -A LDIGNORE -p all -s $peer -d $ip -j ACCEPT "${WAITLOCK}""
					done
				fi
			fi
		fi &
		#Do you believe in magic?
		##### Whitelisting/ NSLookup #####
		SERVERS="${ONTHEFLYFILTER}"
		if ! { { echo "$EXIST_LIST_GET"|grep -Eoq "\b(${peer})\b"; } || { grep -Eoq "^("$peer"|"$peerenc")$" ""$DIR"/42Kmi/${FILTERIGNORE}"; }; }; then
			WHOIS="$(curl -sk --no-keepalive --no-buffer --connect-timeout ${CURL_TIMEOUT} "https://rdap.arin.net/registry/ip/"$peer""|sed -E "s/^\s*//g"|sed "s/\"//g"| sed -E "s/(\[|\]|\{|\}|\,)//g"|sed "s/\\n/,/g"|sed  "s/],/]\\n/g"|sed -E "s/(\[|\]|\{|\})//g"|sed -E "s/(\")\,(\")/\1\\n\2/g"|sed -E '/^\"\"$/d'|sed 's/"//g')"
			if { { echo "$WHOIS"; }|grep -Ev "\b(${IGNORE})\b"|grep -Eoi "\b(${SERVERS})\b"; } && ! { echo "$WHOIS"|grep -Ei "$GOTTOTESTING"; }; then
				if ! { iptables -nL LDIGNORE "$WAITLOCK"|grep -Eoq "\b($peer)\b"; }; then
					for ip in $CONSOLE_SEPARATE; do
						eval "iptables -A LDIGNORE -p all -s $peer -d $ip -j ACCEPT "${WAITLOCK}""
					done
				fi
				if ! { grep -Eo "^(${peer}|${peerenc})$" ""$DIR"/42Kmi/${FILTERIGNORE}"; }; then echo "$peerenc" >> ""$DIR"/42Kmi/${FILTERIGNORE}"; fi
			fi
		fi &
		##### Whitelisting/ NSLookup #####
		##### Get Country #####
		if ! { { echo "$EXIST_LIST_GET"|grep -Eoq "\b(${peer})\b"; } || { grep -Eoq "^("$peer"|"$peerenc")$" ""$DIR"/42Kmi/${FILTERIGNORE}"; }; }; then
			if [ $SHOWLOCATION = 1 ]; then getcountry; fi
		fi
	}
		fi
		##### Get Country #####
		if ! { { echo "$EXIST_LIST_GET"|grep -Eoq "\b(${peer})\b"; } || { grep -Eoq "^("$peer"|"$peerenc")$" ""$DIR"/42Kmi/${FILTERIGNORE}"; }; }; then
			##### The Ping #####
			theping(){
				#Rapid Ping, New Ping Method
				if [ $SMARTMODE = 1 ]; then
					##### Smart Limit #####
					# Dynamically adjusts limit value for smarter limit control
					if tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eioq "\b(${RESPONSE1}|${RESPONSE2})\b"; then
						SMARTLINES="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed -E "/\b(${RESPONSE3}|\-\-)\b/d"|wc -l)"
						GETSMARTLIMIT="$(( $(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed "s/#/\ /g"|sed -E "/\b(${RESPONSE3}|\-\-)\b/d"|sed -E "s/(ms|\.)//g"|awk '{printf "%s\+" $4}'| sed -E 's/^\+//g') ))"
						LIMIT="$(echo "$(( (( GETSMARTLIMIT )) / SMARTLINES ))"|sed -E "s/(.{3})$/.\1/g")"; if [ $LIMIT = 0 ]; then LIMIT=$(echo "$SETTINGS"|sed -n 2p); fi; if echo "$LIMIT"| grep -Eo "\.([0-9]{3})$"; then LIMIT="$(echo "$LIMIT"|sed -E "s/\.//g")"; else LIMIT="$(( LIMIT * 1000 ))"; fi
						if [ $LIMITTEST = "" ]; then
							LIMITTEST=$(echo "$SETTINGS"|sed -n 2p); if echo "$LIMITTEST"| grep -Eo "\.([0-9]{3})$"; then LIMITTEST="$(echo "$LIMITTEST"|sed -E "s/\.//g")"; else LIMITTEST="$(( LIMITTEST * 1000 ))"; fi
						fi
						LIMITXSQ=$(echo $(( (( 2 * (( (( LIMITTEST - LIMIT )) * (( LIMITTEST - LIMIT )) )) )) / (( LIMITTEST + LIMIT )) ))|sed "s/\-//g")
						if { { [ $SMARTLINES -lt $SMARTLINECOUNT ] || [ $LIMITTEST = "" ]; } || ! [ $(echo "$(for item in $(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed "s/#/\ /g"|sed -E "/\b(${RESPONSE3}|\-\-)\b/d"|sed -E "s/(ms|\.)//g"|awk '{printf $4"\n"}'); do echo $(( $item > $(( LIMIT * SMARTPERCENT / 100 )) )); done)"|grep -c "1") -ge $SMART_AVG_COND ]; }; then LIMIT=$(echo "$SETTINGS"|sed -n 2p); if echo "$LIMIT"| grep -Eo "\.([0-9]{3})$"; then LIMIT="$(echo "$LIMIT"|sed -E "s/\.//g")"; else LIMIT="$(( LIMIT * 1000 ))"; fi; else LIMIT="$(( LIMIT + LIMITXSQ ))"; fi
						LIMITTEST=$LIMIT
					else
					LIMIT=$(echo "$SETTINGS"|sed -n 2p) ### Your max average millisecond limit. Peers returning values higher than this value are blocked.
						if echo "$LIMIT"| grep -Eo "\.([0-9]{3})$"; then LIMIT="$(echo "$LIMIT"|sed -E "s/\.//g")"; else LIMIT="$(( LIMIT * 1000 ))"; fi
				fi
					if [ $SHOWSMART = 1 ]; then SHOWSMARTLOG=$(echo "$LIMIT"|sed -E "s/(.{3})$/.\1/g"); fi
				##### Smart Limit #####
				else
					LIMIT=$(echo "$SETTINGS"|sed -n 2p) ### Your max average millisecond limit. Peers returning values higher than this value are blocked.
					if echo "$LIMIT"| grep -Eo "\.([0-9]{3})$"; then LIMIT="$(echo "$LIMIT"|sed -E "s/\.//g")"; else LIMIT="$(( LIMIT * 1000 ))"; fi
				fi
				COUNT=$(echo "$SETTINGS"|sed -n 3p) ### How pings to run. Default is 5
				if [ -f "$DIR"/42Kmi/tweak.txt ]; then PINGRESOLUTION="${TWEAK_PINGRESOLUTION}"; else PINGRESOLUTION=1; fi #3
				PINGTTL=255
				allinoneping(){
					for bytesizes in $SIZES;
						do ping${PING_A} -c "${PINGRESOLUTION}" -W 1 -t "${PINGTTL}" -s "${bytesizes}" "${peer}" &
					done
				}
				PINGGET="$(echo $(echo "$(n=0; while [[ $n -lt "${COUNT}" ]]; do { allinoneping; } & n=$((n+1)); done )"|grep -Eo "time=(.*)$"|sed -E 's/( ms|\.|time=)//g'|sed -E 's/(^|\b)(0){1,}//g'|sed -E 's/$/+/g')|sed -E 's/(\+){1,}/+/g'|sed -E "s/\s?\'?\(DUP\!\)+\'/+/g"|sed -E "/[a-zA-Z]{1,}/d"|sed -E 's/\+$//g')" &> /dev/null; wait $!
				PINGCOUNT=$(echo "$PINGGET"|wc -w)
				if ! [ "${PINGCOUNT}" != "$(echo -n "$PINGCOUNT" | grep -Eio "(0|)")" ]; then PINGCOUNT=$(( COUNT * PINGRESOLUTION )); fi #Fallback
				PINGSUM=$(( $PINGGET ))
				if [ $PINGSUM = 0 ]; then PINGSUM=$(( $(( LIMIT / 1000 + 1 )) * PINGRESOLUTION * COUNT )); FORNULL=1; else FORNULL=0; fi
				PINGFULL=$(( PINGSUM / PINGCOUNT ))
				PING=$(echo "$PINGFULL"|sed -E 's/.{3}$//g' )
				PINGFULLDECIMAL=$(echo "$(echo "$PINGFULL" | sed 's/.\{3\}$/.&/'| sed -E 's/^\./0./g'|sed -E 's/$/ms/g')")
			}
			##### The Ping #####
			##### TRACEROUTE #####
			thetraceroute(){
				##### PARAMETERS #####
				TTL=$COUNT
				PROBES=1
				if [ $SMARTMODE = 1 ]; then
					##### Smart TRACELIMIT #####
					# Dynamically adjusts TRACELIMIT value for smarter TRACELIMIT control
					if tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eioq "\b(${RESPONSE1}|${RESPONSE2})\b"; then
						SMARTLINES="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed -E "/\b(${RESPONSE3}|\-\-)\b/d"|wc -l)"
						GETSMARTTRACELIMIT="$(( $(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed "s/#/\ /g"|sed -E "/\b(${RESPONSE3}|\-\-)\b/d"|sed -E "s/(ms|\.)//g"|awk '{printf "%s\+" $5}'| sed -E 's/^\+//g') ))"
						TRACELIMIT="$(echo "$(( (( GETSMARTTRACELIMIT )) / SMARTLINES ))"|sed -E "s/(.{3})$/.\1/g")"; if [ $TRACELIMIT = 0 ]; then TRACELIMIT=$(echo "$SETTINGS"|sed -n 8p); fi; if echo "$TRACELIMIT"| grep -Eo "\.([0-9]{3})$"; then TRACELIMIT="$(echo "$TRACELIMIT"|sed -E "s/\.//g")"; else TRACELIMIT="$(( TRACELIMIT * 1000 ))"; fi
						if [ $TRACELIMITTEST = "" ]; then
							TRACELIMITTEST=$(echo "$SETTINGS"|sed -n 8p); if echo "$TRACELIMITTEST"| grep -Eo "\.([0-9]{3})$"; then TRACELIMITTEST="$(echo "$TRACELIMITTEST"|sed -E "s/\.//g")"; else TRACELIMITTEST="$(( TRACELIMITTEST * 1000 ))"; fi
						fi
						TRACELIMITXSQ=$(echo $(( (( 2 * (( (( TRACELIMITTEST - TRACELIMIT )) * (( TRACELIMITTEST - TRACELIMIT )) )) )) / (( TRACELIMITTEST + TRACELIMIT )) ))|sed "s/\-//g")
						if { { [ $SMARTLINES -lt $SMARTLINECOUNT ] || [ $TRACELIMITTEST = "" ]; } || ! [ $(echo "$(for item in $(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed "s/#/\ /g"|sed -E "/\b(${RESPONSE3}|\-\-)\b/d"|sed -E "s/(ms|\.)//g"|awk '{printf $5"\n"}'); do echo $(( $item > $(( TRACELIMIT * SMARTPERCENT / 100 )) )); done)"|grep -c "1") -ge $SMART_AVG_COND ]; }; then TRACELIMIT=$(echo "$SETTINGS"|sed -n 8p); if echo "$TRACELIMIT"| grep -Eo "\.([0-9]{3})$"; then TRACELIMIT="$(echo "$TRACELIMIT"|sed -E "s/\.//g")"; else TRACELIMIT="$(( TRACELIMIT * 1000 ))"; fi; else TRACELIMIT="$(( TRACELIMIT + TRACELIMITXSQ ))"; fi
						TRACELIMITTEST=$TRACELIMIT
					else
						TRACELIMIT=$(echo "$SETTINGS"|sed -n 5p) ### Your max average millisecond TRACELIMIT. Peers returning values higher than this value are blocked.
						if echo "$TRACELIMIT"| grep -Eo "\.([0-9]{3})$"; then TRACELIMIT="$(echo "$TRACELIMIT"|sed -E "s/\.//g")"; else TRACELIMIT="$(( TRACELIMIT * 1000 ))"; fi
					fi
					if [ $SHOWSMART = 1 ]; then SHOWSMARTLOGTR=$(echo "$TRACELIMIT"|sed -E "s/(.{3})$/.\1/g"); fi
					##### Smart TRACELIMIT #####
				else TRACELIMIT=$(echo "$SETTINGS"|sed -n 5p)
					if echo "$TRACELIMIT"| grep -Eo "\.([0-9]{3})$"; then TRACELIMIT="$TRACELIMIT"; else TRACELIMIT="$(( TRACELIMIT * 1000 ))"; fi
				fi
				##### PARAMETERS #####
				if [ -f "$DIR"/42Kmi/tweak.txt ]; then TRGETCOUNT="${TWEAK_TRGETCOUNT}"; else TRGETCOUNT=8; fi #8
				FIRST_START=6 #5
				MXP=$(( TTL * PROBES * TRGETCOUNT ))
				#New TraceRoute
				allinonetr(){
						for port in $IDENTPORTS; do
							for bytesizes in $SIZES; do
								traceroute -Fn -I -f ${FIRST_START} -p $port -t 8 -m "${TRGETCOUNT}" -q "${PROBES}" -w 1 "${peer}" "${bytesizes}" &
								traceroute -Fn -f ${FIRST_START} -p $port -t 16 -m "${TRGETCOUNT}" -q "${PROBES}" -w 1 "${peer}" "${bytesizes}" &
							done &
						done
				}
				TRGET="$(echo $(echo "$(n=0; while [[ $n -lt "${TTL}" ]]; do { allinonetr; } & n=$((n+1)); done )"|grep -Eo "([0-9]{1,}\.[0-9]{3}\ ms)"|sed -E 's/(\/|\.|\ ms)//g'|sed -E 's/(^|\b)(0){1,}//g'|sed -E 's/$/+/g')|sed -E 's/(\+){1,}/+/g'|sed -E "s/\s?\'?\(DUP\!\)+\'/+/g"|sed -E "/[a-zA-Z]{1,}/d"|sed -E 's/\+$//g')" &> /dev/null; wait $!
				TRCOUNT=$(echo -n "$TRGET"|wc -w) #Counts for average
				if [ "${TRCOUNT}" = 0 ]; then TRCOUNT=$(( TTL * PROBES)); fi #Fallback
				TRSUM=$(( $TRGET ))
				if [ $TRGET = 0 ]; then TRGET=$(( $(( TRACELIMIT / 1000 + 1 )) * MXP )); FORNULLTR=1 ;else FORNULLTR=0; fi
				if [ "${TRCOUNT}" != 0 ]; then
					TRAVGFULL=$(( TRSUM / TRCOUNT )); #TRACEROURTE sum for math
					TRAVG=$(echo $TRAVGFULL | sed -E 's/.{3}$//g')
				else
					TRAVGFULL=$(( TRSUM / MXP )); #TRACEROURTE sum for math
					TRAVG=$(echo $TRAVGFULL | sed -E 's/.{3}$//g')
				fi
				TRAVGFULLDECIMAL=$(echo "$(echo "$TRAVGFULL" | sed 's/.\{3\}$/.&/'| sed -E 's/^\./0./g'|sed -E 's/$/ms/g')")
			}
			##### TRACEROUTE #####
			if ! { { echo "$EXIST_LIST_GET"|grep -Eoq "\b(${peer})\b"; } && { grep -Eoq "^("$peer"|"$peerenc")$" ""$DIR"/42Kmi/${FILTERIGNORE}"; } && { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b?(${peer})\b"; }; }; then
				{ theping; thetraceroute; }
			fi
		fi
		##### ACTION of IP Rule #####
		ACTION=$(echo "$SETTINGS"|sed -n 6p) ### DROP (1)/REJECT(0)
		ACTION1=$(if [ "$ACTION" = "$(echo -n "$ACTION" | grep -Eio "(drop|1)")" ]; then echo "DROP"; else echo "REJECT"; fi)
		##### ACTION of IP Rule #####
		ping_tr_results
	##### NULL/NO RESPONSE PEERS #####
	NULLTEXT="--"
	if [ $FORNULL = 1 ] && { [ $PINGFULLDECIMAL = "$PINGFULLDECIMAL" ] || [ $PINGFULLDECIMAL = "0" ]; }; then PINGFULLDECIMAL="$NULLTEXT"; fi
	if [ $FORNULLTR = 1 ] && { [ $TRAVGFULLDECIMAL = "$TRAVGFULLDECIMAL" ] || [ $TRAVGFULLDECIMAL = "0" ]; }; then TRAVGFULLDECIMAL="$NULLTEXT"; fi
	if ! { echo "$TRAVGFULLDECIMAL" |grep -Eoq "\."; }; then TRAVGFULLDECIMAL="${TRAVGFULLDECIMAL}.000"; fi; if { echo "$TRAVGFULLDECIMAL"|grep -E "\b(0.000)\b"; }; then TRAVGFULLDECIMAL="--"; fi
	if [ $PINGFULLDECIMAL = "$NULLTEXT" ] && [ TRAVGFULLDECIMAL = "$NULLTEXT" ]; then eval "iptables -A LDBAN -p all -s $peer -d $CONSOLE -j REJECT "${WAITLOCK}""; fi
	##### NULL/NO RESPONSE PEERS #####
		##### Count Connected IPs #####
		NUMBEROFPEERS=$(echo "$SETTINGS"|sed -n 17p)
		IPCONNECTCOUNT=$(echo -ne "$IPCONNECT"| grep -Ev "\b${EXIST_LIST}\b"|wc -l)
		##### Count Connected IPs #####
		#Rest on Multiplayer
	{
		if ! { { echo "$EXIST_LIST_GET"|grep -Eoq "\b(${peer})\b"; } || { grep -Eoq "^("$peer"|"$peerenc")$" ""$DIR"/42Kmi/${FILTERIGNORE}"; }; }; then
			if ! { [ "$RESTONMULTIPLAYER" = 1 ] && [ "${IPCONNECTCOUNT}" -ge "${NUMBEROFPEERS}" ]; }; then
			##### BLOCK #####
			# Store ping histories for future approximating of null pings
			if [ $SHOWLOCATION = 1 ]; then pingavgfornull; fi
				if ! { echo "$EXIST_LIST_GET"|grep -Eoq "\b(${peer})\b"; } && ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b?(${peer})\b"; }; then
					ldtemphold_add(){
						if ! { echo "$(iptables -nL LDTEMPHOLD; iptables -nL LDIGNORE; iptables -nL LDBAN)"| grep -Eoq "\b${peer}\b"; }; then
							eval "iptables -A LDTEMPHOLD -s $peer -d $CONSOLE"
						fi
					}
					lagdrop_accept_condition(){
						CONSOLE=$(grep -E "\b($CONSOLE)\b" "$IPCONNECT_SOURCE"|grep -E "\b($peer)\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++'|grep -E "\b($CONSOLE)\b"); if [ $POPULATE = 1 ]; then CONSOLE=9999999999; break; fi
						if ! { echo "$(iptables -nL LDACCEPT|tail +3|awk '{printf $4"\n"}'|awk '!a[$0]++')"|grep -Eoq "\b(${peer})\b"; }; then
							eval "iptables -A LDACCEPT -p all -s $peer -d $CONSOLE -j ACCEPT "${WAITLOCK}""
							if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b(${peer})\b"; }; then
								echo -e "${ACT_PLACEHOLD}%\"$EPOCH\"$DATETIME#"$borneopeer"#"$PINGFULLDECIMAL"#"$TRAVGFULLDECIMAL"#"$RESULT"#"$SHOWSMARTLOG"#"$SHOWSMARTLOGTR"#"$LDCOUNTRY_toLog"#" >> "/tmp/$RANDOMGET"
							fi
						fi
						ldtemphold_add
					}
					lagdrop_reject_condition(){
						CONSOLE=$(grep -E "\b($CONSOLE)\b" "$IPCONNECT_SOURCE"|grep -E "\b($peer)\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++'|grep -E "\b($CONSOLE)\b"); if [ $POPULATE = 1 ]; then CONSOLE=9999999999; break; fi
						if ! { echo "$(iptables -nL LDREJECT|tail +3|awk '{printf $4"\n"}'|awk '!a[$0]++')"|grep -Eoq "\b(${peer})\b"; }; then
							eval "iptables -A LDREJECT -s $peer -d $CONSOLE -j $ACTION1 "${WAITLOCK}""
							if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b(${peer})\b"; }; then
								echo -e "${ACT_PLACEHOLD}%\"$EPOCH\"$DATETIME#"$borneopeer"#"$PINGFULLDECIMAL"#"$TRAVGFULLDECIMAL"#"$RESULT"#"$SHOWSMARTLOG"#"$SHOWSMARTLOGTR"#"$LDCOUNTRY_toLog"#" >> "/tmp/$RANDOMGET"
							fi
						fi
						ldtemphold_add
					}
					lagdrop_reject_condition_2_1(){
						#Warn
						CONSOLE=$(grep -E "\b($CONSOLE)\b" "$IPCONNECT_SOURCE"|grep -E "\b($peer)\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++'|grep -E "\b($CONSOLE)\b"); if [ $POPULATE = 1 ]; then CONSOLE=9999999999; break; fi
						#Warn
						if ! { echo "$(iptables -nL LDREJECT|tail +3|awk '{printf $4"\n"}'|awk '!a[$0]++')"|grep -Eoq "\b(${peer})\b"; }; then
							eval "iptables -A LDACCEPT -p all -s $peer -d $CONSOLE -j ACCEPT "${WAITLOCK}""
							if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b(${peer})\b"; }; then
								echo -e "${ACT_PLACEHOLD}%\"$EPOCH\"$DATETIME#"$borneopeer"#"$PINGFULLDECIMAL"#"$TRAVGFULLDECIMAL"#"${YELLOW}${RESPONSE2}${NC}"#"$SHOWSMARTLOG"#"$SHOWSMARTLOGTR"#"$LDCOUNTRY_toLog"#" >> "/tmp/$RANDOMGET"
							fi
						fi
						ldtemphold_add
					}
					lagdrop_reject_condition_2_2(){
						#Block
						CONSOLE=$(grep -E "\b($CONSOLE)\b" "$IPCONNECT_SOURCE"|grep -E "\b($peer)\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++'|grep -E "\b($CONSOLE)\b"); if [ $POPULATE = 1 ]; then CONSOLE=9999999999; break; fi
						if ! { echo "$(iptables -nL LDREJECT|tail +3|awk '{printf $4"\n"}'|awk '!a[$0]++')"|grep -Eoq "\b(${peer})\b";}; then
							eval "iptables -A LDREJECT -s $peer -d $CONSOLE -j $ACTION1 "${WAITLOCK}""
							if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b(${peer})\b"; }; then
								echo -e "${ACT_PLACEHOLD}%\"$EPOCH\"$DATETIME#"$borneopeer"#"$PINGFULLDECIMAL"#"$TRAVGFULLDECIMAL"#"${RED}${RESPONSE3}${NC}"#"$SHOWSMARTLOG"#"$SHOWSMARTLOGTR"#"$LDCOUNTRY_toLog"#" >> "/tmp/$RANDOMGET"
							fi
						fi
						ldtemphold_add
					}
					{
						timestamps
						#5=TraceRoute if Ping is null
						if [ "${PINGFULL}" = "--" ] || [ "${PINGFULL}" = "0" ] || [ $PINGFULLDECIMAL = "0" ] || [ $PINGFULLDECIMAL = "--" ] || [ $PINGFULLDECIMAL = "\-\-" ]; then #If ping is zero/null, use TR value instead
							BLOCK=$({ if [ "${TRAVGFULL}" -gt "${TRACELIMIT}" ]; then { { lagdrop_reject_condition; } }; else { { lagdrop_accept_condition; } } fi; } &)
						else
							LIMIT=$(( LIMIT + 5000 ))
							BLOCK=$({ if  { [ "${PINGFULL}" -le "${LIMIT}" ] && [ "${TRAVGFULL}" -gt "${TRACELIMIT}" ]; }; then lagdrop_reject_condition_2_1; elif { [ "${PINGFULL}" -gt "${LIMIT}" ] && [ "${TRAVGFULL}" -gt "${TRACELIMIT}" ]; } || { [ "${PINGFULL}" -gt "${LIMIT}" ] && [ "${TRAVGFULL}" -le "${TRACELIMIT}" ]; } || { [ "${PINGFULL}" -lt "1000" ] && [ "${TRAVGFULL}" -gt "${TRACELIMIT}" ]; }; then lagdrop_reject_condition_2_2; else { { lagdrop_accept_condition; } } fi; } &)
						 fi
					}
						if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eo "\b${peer}\b"; } && ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b?(${peer})\b"; }; then
							if ! { echo "$EXIST_LIST_GET"| grep -Eoq "\b(${peer})\b"; } && ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b?(${peer})\b"; }; then $BLOCK
							fi
						fi
				fi
			fi
		fi
	}
		##### BLOCK #####
}
clear_old(){
	remove_tmp_data_co(){
		IP_FILENAME="$(panama ${allowed1})"
		rm -f "/tmp/${LDTEMPFOLDER}/ld_act_state/${IP_FILENAME}#"
		rm -f "/tmp/${LDTEMPFOLDER}/ld_state_counter/${IP_FILENAME}#"
		rm -f "/tmp/${LDTEMPFOLDER}/coef/${IP_FILENAME}#"
		rm -f "/tmp/${LDTEMPFOLDER}/oldval/${IP_FILENAME}#"
	}
	DELETEDELAY=5 #30 #150
	DELAY_DELETE_CHECK=1 #10
	#Allow
	if [ "$CLEARALLOWED" = 1 ]; then
		COUNTALLOW=$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Ev "\b(${RESPONSE3}|${SENTINEL_BAN_MESSAGE})\b"|wc -l)
		if [ "${COUNTALLOW}" -gt "${CLEARLIMIT}" ]; then
		clearallow(){
			LINENUMBERACCEPTED=$(iptables --line-number -nL LDACCEPT|grep -E "\b${allowed1}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
			sleep $DELAY_DELETE_CHECK
			eval "iptables -D LDACCEPT "$LINENUMBERACCEPTED""
			sed -i -E "s/#(.\[[0-9]{1}\;[0-9]{2}m)(${allowed1})\b/$(echo -e "#${BG_MAGENTA}")\2/g" "/tmp/$RANDOMGET"; sleep 5 #Clear warning
			wait $!; sed -i -E "/#((.\[[0-9]{1}(\;[0-9]{2})m))?${allowed1}\b/d" "/tmp/$RANDOMGET"
			remove_tmp_data_co
		}
			clearallow_check(){
				getiplist
				sleep $DELAY_DELETE_CHECK
				if ! { echo "$IPCONNECT"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${allowed1}\b"; }; then
					clearallow
				fi
		}
			#Allowed List Clear
			ACCEPTED1=$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Ev "\b(${RESPONSE3}|${SENTINEL_BAN_MESSAGE})\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b") #|sed -n 1p)
			for allowed1 in $ACCEPTED1; do
				getiplist; wait $!
				{
					if ! { echo "$IPCONNECT"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${allowed1}\b"; }; then
						sleep $DELAY_DELETE_CHECK
						if iptables -nL LDTEMPHOLD| grep -Eoq "\b${allowed1}\b"; then
							if ! { echo "$IPCONNECT"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${allowed1}\b"; }; then
								LINENUMBERHOLD1=$(iptables --line-number -nL LDTEMPHOLD|grep -E "\b${allowed1}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
								iptables -D LDTEMPHOLD "$LINENUMBERHOLD1"
								sleep $DELETEDELAY
								clearallow_check
							else
								if ! { iptables -nL LDTEMPHOLD "$WAITLOCK"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${allowed1}\b";}; then
									iptables -A LDTEMPHOLD "$allowed1"
								fi
							fi
						fi
					fi #& #Must not parallel. Parallelling cause problems.
				} #&
			done & #Must not parallel. Parallelling cause problems.
		fi
	fi &
	#Blocked
	if [ "$CLEARBLOCKED" = 1 ]; then
			COUNTBLOCKED=$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -E "\b${RESPONSE3}\b"|wc -l)
			if [ "${COUNTBLOCKED}" -gt "${CLEARLIMIT}" ]; then
		clearreject(){
			LINENUMBERREJECTED=$(iptables --line-number -nL LDREJECT|grep -E "\b${refused1}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
			sleep $DELAY_DELETE_CHECK
			eval "iptables -D LDREJECT "$LINENUMBERREJECTED""
			sed -i -E "s/#(.\[[0-9]{1}\;[0-9]{2}m)(${refused1})\b/$(echo -e "#${BG_MAGENTA}")\2/g" "/tmp/$RANDOMGET"; sleep 5 #Clear warning
			wait $!; sed -i -E "/((.\[[0-9]{1}(\;[0-9]{2})m))?${refused1}\b/d" "/tmp/$RANDOMGET"
		}
		clearreject_check(){
			getiplist
			sleep $DELAY_DELETE_CHECK
			if ! { echo "$IPCONNECT"|grep -q "\b${CONSOLE}\b"|grep -Eoq "\b${refused1}\b"; }; then
					clearreject
			fi
		}
			#Blocked List Clear
			REJECTED1=$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -E "\b${RESPONSE3}\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")
			for refused1 in $REJECTED1; do
				getiplist; wait $!
				{
				if ! { echo "$IPCONNECT"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${refused1}\b"; }; then
					sleep $DELAY_DELETE_CHECK
					if iptables -nL LDTEMPHOLD "$WAITLOCK"| grep -Eoq "\b${refused1}\b"; then
						if ! { echo "$IPCONNECT"|grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${refused1}\b"; }; then
							LINENUMBERHOLD2=$(iptables --line-number -nL LDTEMPHOLD|grep "\b${refused1}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
							iptables -D LDTEMPHOLD "$LINENUMBERHOLD2"
							sleep $DELETEDELAY
							clearreject_check
						fi
					else
						clearreject_check
					fi
				fi #& #Must not parallel. Parallelling cause problems.
				} #&
			done & #Must not parallel. Parallelling cause problems.
		fi
	fi &
}
txqueuelen_adjust(){
	QUELENGTH_NEW_VALUE=2
	IFCONFIG_INTERFACES="$(ifconfig|grep -Eo "^[a-z0-9\.]{1,}\b"|grep -Ev "^(br.*|lo.*)\b")"
	for interface in $IFCONFIG_INTERFACES; do
		TXQUEUELEN_GET=$(ifconfig $interface| grep -Eo "txqueuelen:[0-9]{1,}"|sed -E "s/txqueuelen://g")
		if [ ${TXQUEUELEN_GET} != ${QUELENGTH_NEW_VALUE} ]; then
			eval "ifconfig ${interface} txqueuelen ${QUELENGTH_NEW_VALUE}"
		fi
	done
}
txqueuelen_restore(){
	IFCONFIG_INTERFACES="$(ifconfig|grep -Eo "^[a-z0-9\.]{1,}\b"|grep -Ev "^(br.*|lo.*)\b")"
	for interface in $IFCONFIG_INTERFACES; do
		TXQUEUELEN_GET=$(ifconfig $interface| grep -Eo "txqueuelen:[0-9]{1,}"|sed -E "s/txqueuelen://g")
		if [ ${TXQUEUELEN_GET} != 1000 ]; then
			eval "ifconfig ${interface} txqueuelen 1000"
		fi
	done
}
write_null_to_log(){
	echo -en "\0" >> "/tmp/$RANDOMGET" # Adds null byte to refresh log
}
#=================
	RESPONSE1="OK!!" #OK/GOOD
	RESPONSE2="Warn" #Pushing it...
	RESPONSE3="BLOCK" #BLOCKED
	SENTINEL_BAN_MESSAGE='‼‼‼‼‼%BANNED%-%SUSPECTED%CONNECTION%INSTABILITY%‼‼‼‼‼'
	SENTINEL_BAN_MESSAGE="${SENTINEL_BAN_MESSAGE// /%}"
{
	#Store Values
	if [ "${SHELLIS}" != "ash" ] && [ $NVRAM_EXISTS = 1 ]; then
		store_original_values(){
		ORIGINAL_DMZ="$(echo $(nvram get dmz_enable))"
		ORIGINAL_DMZ_IPADDR="$(echo $(nvram get dmz_ipaddr))"
		ORIGINAL_MULTICAST="$(echo $(nvram get block_multicast))"
		ORIGINAL_BLOCKWAN="$(echo $(nvram get block_wan))"
		}
		store_original_values
	fi
if [ ! -f "/tmp/LD_PUBLIC_IP" ]; then
	echo "$(curl -sk -A "${RANDOMGET_GET}" "https://api.ipify.org/"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b$")" > "/tmp/LD_PUBLIC_IP"
else
	PUBLIC_IP="$(tail +1 "/tmp/LD_PUBLIC_IP")"
fi
##### SETTINGS & TWEAKS #####
SETTINGS="$(tail +1 "$DIR"/42Kmi/options_"$CONSOLENAME".txt|sed -E "s/#.*$//g"|sed -E "/(^#.*#$|^$|\;|#^[ \t]*$)|#/d"|sed -E 's/^.*=//g')" #Settings stored here, called from memory
if [ -f "$DIR"/42Kmi/tweak.txt ]; then
	SMARTLINECOUNT=$TWEAK_SMARTLINECOUNT
	SMARTPERCENT=$TWEAK_SMARTPERCENT
	SMART_AVG_COND=$TWEAK_SMART_AVG_COND
else
	SMARTLINECOUNT=5 #8 #5
	SMARTPERCENT=155 #155
	SMART_AVG_COND=$(( SMARTLINECOUNT * 40 / 100 )) #2
fi
if [ $SHELLIS = "ash" ]; then
	CURL_TIMEOUT=20 #15 #For OpenWRT
else
	CURL_TIMEOUT=15 #10 #For DD-WRT
fi
SIZE="$(echo "$SETTINGS"|sed -n 4p)" ### User-defined packet size. Default is 7500
SIZE_1=64;SIZE_2=128;SIZE_3=256 #Additional bytes to run for ping and traceroute
SIZES="$(echo "${SIZE_1} ${SIZE_2} ${SIZE_3} ${SIZE}"|grep -Eo "[0-9]*"|awk '!a[$0]++')"
export SENTINEL="$(echo "$SETTINGS"|sed -n 7p)"; if [ "$SENTINEL" = "$(echo -n "$SENTINEL" | grep -Eio "(yes|1|on|enable(d?))")" ]; then export SENTINEL=1; else SENTINEL=0; fi
export SENTBAN="$(echo "$SETTINGS"|sed -n 8p)"; if [ "$SENTBAN" = "$(echo -n "$SENTBAN" | grep -Eio "(yes|1|on|enable(d?))")" ]; then export SENTBAN=1; else SENTBAN=0; fi
export STRIKECOUNT_LIMIT="$(echo "$SETTINGS"|sed -n 9p)"
export STRIKERESET="$(echo "$SETTINGS"|sed -n 10p)"; if [ "$STRIKERESET" = "$(echo -n "$STRIKERESET" | grep -Eio "(yes|1|on|enable(d?))")" ]; then export STRIKERESET=1; else STRIKERESET=0; fi
CLEARALLOWED=$(echo "$SETTINGS"|sed -n 11p); if [ "$CLEARALLOWED" = "$(echo -n "$CLEARALLOWED" | grep -Eio "(yes|1|on|enable(d?))")" ]; then CLEARALLOWED=1; else CLEARALLOWED=0; fi
CLEARBLOCKED=$(echo "$SETTINGS"|sed -n 12p); if [ "$CLEARBLOCKED" = "$(echo -n "$CLEARBLOCKED" | grep -Eio "(yes|1|on|enable(d?))")" ]; then CLEARBLOCKED=1; else CLEARBLOCKED=0; fi
CLEARLIMIT=$(echo "$SETTINGS"|sed -n 13p)
CHECKPORTS="$(echo "$SETTINGS"|sed -n 14p)"; if [ "$CHECKPORTS" = "$(echo -n "$CHECKPORTS" | grep -Eio "(yes|1|on|enable(d?))")" ]; then CHECKPORTS=1; else CHECKPORTS=0; fi
PORTS="$(echo "$SETTINGS"|sed -n 15p)"
RESTONMULTIPLAYER="$(echo "$SETTINGS"|sed -n 16p)"; if [ "$RESTONMULTIPLAYER" = "$(echo -n "$RESTONMULTIPLAYER" | grep -Eio "(yes|1|on|enable(d?))")" ]; then RESTONMULTIPLAYER=1; else RESTONMULTIPLAYER=0; fi
DECONGEST="$(echo "$SETTINGS"|sed -n 18p)"; if [ "$DECONGEST" = "$(echo -n "$DECONGEST" | grep -Eio "(yes|1|on|enable(d?))")" ]; then DECONGEST=1; else DECONGEST=0; fi
SWITCH="$(echo "$SETTINGS"|tail -1)"; if [ "$SWITCH" = "$(echo -n "$SWITCH" | grep -Eio "(yes|1|on|enable(d?))")" ]; then SWITCH=1; else SWITCH=0; fi ### Enable (1)/Disable(0) LagDrop
##### SETTINGS & TWEAKS #####
##### CONOSLE IP & DD-WRT OPTIMIZATIONS #####
if [ $POPULATE = 1 ]; then
	CONSOLE="${ROUTERSHORT_POP}[0-9]{1,3}\.[0-9]{1,3}"
else
	CONSOLE="$(echo "$SETTINGS"|sed -n 1p)" ### Your console's IP address. Change this in the options.txt file
fi
{
	#DD-WRT
	#Enable Multicast, Enable Anonymous Pings, Set to DMZ
	if ! [ "${SHELLIS}" = "ash" ] && [ $NVRAM_EXISTS = 1 ]; then
		#Set to DMZ
		CONSOLE_IP_END="$(echo "${CONSOLE}"|grep -Eo "[0-9]{1,3}$")"
		if ! [ "$(nvram get dmz_enable)" = 1 ]; then
			eval "nvram set dmz_enable=1"
			if ! [ "$(nvram get dmz_ipaddr)" = "${CONSOLE_IP_END}" ]; then
				eval "nvram set dmz_ipaddr=${CONSOLE_IP_END}"
			fi
		fi
		#Enable multicast
		if ! [ "$(nvram get block_multicast)" = 0 ]; then
			eval "nvram set block_multicast=0"
		fi
		#Enable Pings
		if ! [ "$(nvram get block_wan)" = 0 ]; then
			eval "nvram set block_wan=0"
		fi
		#Disable Shortcut Forwarding Engine
		if { "$(nvram show sfe)"; }; then
			if ! [ "$(nvram get sfe)" = 0 ]; then
				eval "nvram set sfe=0"
			fi
		fi
	fi
}
##### CONOSLE IP & DD-WRT OPTIMIZATIONS #####
##### Check Ports #####
getiplist(){
	if [ "$CHECKPORTS" = 1 ]; then
		ADDPORTS='|grep -E "dport\=($PORTS)\b"'
	else
		ADDPORTS=""
	fi
	if [ -f "/proc/net/ip_conntrack" ]; then
		IPCONNECT_SOURCE='/proc/net/ip_conntrack'
		else
		IPCONNECT_SOURCE='/proc/net/nf_conntrack'
	fi
	export IPCONNECT="$(grep -E "\b(${CONSOLE})\b" "${IPCONNECT_SOURCE}""${ADDPORTS}")" ### IP connections stored here, called from memory
	}
	##### Check Ports #####
#####Decongest - Block all other connections#####
decongest(){
	if [ "$DECONGEST" = 1 ]; then
		if [ $IFCONFIG_EXISTS = 1 ]; then txqueuelen_adjust &> /dev/null; fi
		KTALIST="$(iptables -nL LDKTA|awk '{printf $4"\n"}'|awk '!a[$0]++')"
		KTALIST_COUNT="$(echo "$KTALIST"|wc -l)"
		if [ $KTALIST_COUNT -gt 0 ]; then
			DECONGEST_EXIST="$(echo $KTALIST|awk '!a[$0]++'|sed -E "s/\s/|/g")"
		else
			DECONGEST_EXIST="${CONSOLE}"
		fi
		DECONGEST_FILTER="$(echo $(grep -E "\b${CONSOLE}\b" "${IPCONNECT_SOURCE}"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++')|sed -E "s/\s/|/g")"
		DECONGESTLIST="$(tail +1 "${IPCONNECT_SOURCE}"|grep -Ev "\b(${CONSOLE}|${ROUTER})\b"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|grep -Ev "\b(${DECONGEST_FILTER}|${ARIN}|${FILTERIP}|${DECONGEST_EXIST}|${PUBLIC_IP}|(198\.11\.209\.(22[4-9]|23[0-1])))\b"|grep -Ev "^${ROUTERSHORT}"|awk '!a[$0]++')"
		for kta in $DECONGESTLIST; do
			if ! { echo "$KTALIST"|grep -Eo "\b${kta}\b"; } &> /dev/null; then
				eval "iptables -A LDKTA -s $kta -j DROP "${WAITLOCK}""
			fi
		done
	else
		iptables -F LDKTA
	fi
		}
lagdrop(){
	while "$@" &> /dev/null; do
		exit_trap
		{
			#magic Happens Here
			# Everything below depends on power switch
			if ! [ "$SWITCH" = 0 ]; then
				export CONSOLE_SEPARATE="$(echo "$CONSOLE"|sed 's/|/ /g')"
				getiplist
				EXIST_LIST_GET="$({ echo "$(iptables -nL LDACCEPT; iptables -nL LDREJECT; iptables -nL LDBAN; iptables -nL LDIGNORE; iptables -nL LDKTA)"; }|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++')"
				#if [ $(echo "$EXIST_LIST_GET") != 0 ] || [ $(echo "$EXIST_LIST_GET") != "" ]; then
				if [ "$EXIST_LIST_GET" != "" ]; then
					EXIST_LIST="$(echo ${EXIST_LIST_GET}|sed -E "s/\s/|/g"|sed -E "s/\|$//g")"
				else
					EXIST_LIST="${CONSOLE}"
				fi
				IGNORE="$(echo $({ if { { { echo "$EXIST_LIST_GET" && tail +1 ""$DIR"/42Kmi/${FILTERIGNORE}"; } ; }|grep -Eoq "([0-9]{1,3}\.?){4}"; } then echo "$({ { echo "$EXIST_LIST_GET" && tail +1 ""$DIR"/42Kmi/${FILTERIGNORE}"; } ; }|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|awk '!a[$0]++'|grep -Ev "\b(${CONSOLE})\b"|grep -v "127.0.0.1"|sed 's/\./\\\./g')"|sed -E 's/$/\|/g'; else echo "${ROUTER}"; fi; })|sed -E 's/\|$//g'|sed -E 's/\ //g')"
				{
					#WHITELIST: Additional IPs to filter out. Make whitelist.txt in 42Kmi folder, add IPs there.
					if [ -f "$DIR"/42Kmi/whitelist.txt ] && [ $(wc -c ""$DIR"/42Kmi/whitelist.txt") -gt 1 ]; then
						WHITELIST="$(echo $(echo "$(tail +1 "${DIR}"/42Kmi/whitelist.txt|awk '!a[$0]++'|sed -E -e "/(#.*$|^$|\;|#^[ \t]*$)|#/d" -e "s/^/\^/g" -e "s/\^#|\^$//g" -e "s/\^\^/^/g" -e "s/$/|/g")")|sed -e 's/\|$//g' -e "s/(\ *)//g" -e 's/\b\.\b/\\./g')"
						ADDWHITELIST="|grep -Ev "$WHITELIST""
					else
						ADDWHITELIST=""
					fi
						whitelist(){
							if { grep -E "\b(${peer})\b" "${DIR}"/42Kmi/whitelist.txt; }; then
								for ip in $CONSOLE_SEPARATE; do
									if ! { iptables -nL LDIGNORE "$WAITLOCK"|grep -Eoq "\b($peer)\b"; }; then
										eval "iptables -I LDIGNORE -s $peer -d $ip -j ACCEPT "${WAITLOCK}";"
									fi
								done
							fi
						}
					#BLACKLIST: Permananent ban. If encountered, immediately blocked.
					if [ -f "$DIR"/42Kmi/blacklist.txt ]; then
						BLACKLIST="$(echo $(echo "$(tail +1 ""${DIR}"/42Kmi/blacklist.txt"|awk '!a[$0]++'|sed -E "s/#.*$//g"|sed -E -e "/(#.*$|^$|\;|#^[ \t]*$)|#/d" -e "s/^/\^/g" -e "s/\^#|\^$//g" -e "s/\^\^/^/g" -e "s/$/|/g")")| sed -E 's/\|$//g')"
						blacklist(){
							if { grep -E "\b(${peer})\b" "${DIR}"/42Kmi/blacklist.txt; }; then
								for ip in $CONSOLE_SEPARATE; do
									if ! { iptables -nL LDBAN "$WAITLOCK"|grep -Eoq "\b($peer)\b"; }; then
										eval "iptables -I LDBAN -s $peer -d $ip -j DROP "${WAITLOCK}";"
									fi
								done
							fi
						}
					fi
				} &
				PEERIP="$(echo "$IPCONNECT"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b"|grep -Ev "^\b(${CONSOLE}|${ROUTER}|${IGNORE}|${EXIST_LIST}|${ROUTERSHORT}|${FILTERIP}|${ONTHEFLYFILTER_IPs}|${PUBLIC_IP})\b""${ADDWHITELIST}"|awk '!a[$0]++'|sed -E "s/(\s)*//g")" ### Get console Peer's IP DON'T TOUCH!
					if [ -f ""$DIR"/42Kmi/blacklist.txt" ] && [ -n ""$DIR"/42Kmi/blacklist.txt" ]; then blacklist; fi
					if [ -f ""$DIR"/42Kmi/whitelist.txt" ] && [ -n ""$DIR"/42Kmi/whitelist.txt" ]; then whitelist; fi
					if [ "$PEERIP" != "" ]; then
						{
						for peer in $PEERIP; do
						(
							#Get ports established by peer for traceroute testing
							if ! { tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eoq "\b?(${peer})\b"; }; then
								IDENTPORTS="$(echo $(echo "$IPCONNECT"|grep -E "\b(${peer})\b"|grep -Eo ".port=[0-9]*"|sed -E "s/^.*=//g"|awk '!a[$0]++'))"
								peerenc="$(panama $peer)"
								meatandtatoes
								if [ $POPULATE = 1 ]; then
									iptables -A LDIGNORE -s ${peer}
								fi
								cleanliness &> /dev/null &
								bancountry &> /dev/null &
							fi
						PEERIP="$(echo "${PEERIP}"|sed -E "s/\b${peer}\b//g")"
						)
						wait $!
						done
						}
					fi
				#end of LagDrop loops
			fi
			{
				#####Decongest - Block all other connections#####
				if [ "$DECONGEST" = 1 ]; then
					decongest &> /dev/null
				fi
				##### Clear Old #####
				clear_old &
			}
			cleanliness &> /dev/null &
			bancountry &> /dev/null &
		}
	done &> /dev/null &
	#exit
	}
lagdrop &
}
#==========================================================================================================
###### SENTINELS #####
if [ "$SENTINEL" = 1 ]; then
SENTON_SIG=1
{
	#Sentinel: Checks against intrinsic/extrinsic peer lag by comparing difference in transmitted data at 2 sequential time points
	if [ ! -d "/tmp/${LDTEMPFOLDER}/oldval" ]; then mkdir -p "/tmp/${LDTEMPFOLDER}/oldval" ; fi
	#1 for packets, 2 for bytes (referred to as delta)
	if [ $USE_BYTES = 1 ]; then
		PACKET_OR_BYTE=2
	else
		PACKET_OR_BYTE=1
	fi
	if [ $ENABLE_VERIFY = 1 ]; then
		VERIFY_VALUES=1 #Creates verifyvalues.txt in 42Kmi/verify to check Sentinel values.
		VV_APPEND=':V'
	else
		VERIFY_VALUES=0
		VV_APPEND=''
	fi
	if [ $PACKET_OR_BYTE = 2 ]; then
		SENT_APPEND=':B'
	else
		SENT_APPEND=':P'
	fi
		#Functions
	get_the_values(){
		#Get iptables LDACCEPT values
		GET_DATE_INIT="$(date +%s)"
		GET_LDACCEPT_VALUES1="$(iptables -xvnL LDACCEPT)"
		if [ $USLEEP_EXISTS = 1 ]; then usleep $USLEEP_DELAY_TIME; else sleep $SENTINELDELAYSMALL; fi
		GET_LDACCEPT_VALUES2="$(iptables -xvnL LDACCEPT)"
		{
			echo "$GET_LDACCEPT_VALUES1" > "/tmp/${LDTEMPFOLDER}/ldacceptval1"
			echo "$GET_LDACCEPT_VALUES2" > "/tmp/${LDTEMPFOLDER}/ldacceptval2"
		}
	}
	continuous_mode(){
		DELTA_old=$(tail +1 "/tmp/${LDTEMPFOLDER}/oldval/${SENTIPFILENAME}#");
	}
	errata(){
		#Rescale DIFF_MIN is both DELTA_old and DELTA_new are significantly greater than expected
		POWER_DIV_FACTOR=333 #333 #18
		if [ $PACKET_OR_BYTE = 2 ]; then
			#Values for Bytes
			POWER_TEST=0
			POWER_SET='8 7 6 5 4' #Checks for values greater than or equal to 10000
				if [ $POWER_TEST = 0 ]; then
					for power in $POWER_SET; do
					POWER_MATH_THRESHOLD=$(( 10 ** $power )) #10-factor threshhold for dynamic rates/errata
					POWER_MATH_DIV_STEPUP=$(( 10 ** $(( $power + 1 )) ))
					POWER_MATH_AVG=$(( $(( $POWER_MATH_DIV_STEPUP - $POWER_MATH_THRESHOLD)) * $POWER_DIV_FACTOR / 1000 ))
					#eg, if Deltas A and B are greater than 10000; then diff min becomes 1350
						if [ $DELTA_old -ge $POWER_MATH_THRESHOLD ] && [ $DELTA_new -ge $POWER_MATH_THRESHOLD ]; then
							DELTA_OFFSET=0
							DIFF_MIN=$POWER_MATH_AVG #For high data transfer
							POWER_TEST=1
							#break
						fi
					done
				fi
		else
			#Values for Packets
			POWER_TEST=0
			POWER_SET='8 7 6 5 4 3 2' #Checks for values greater than or equal to 10000
				if [ $POWER_TEST = 0 ]; then
					for power in $POWER_SET; do
					POWER_MATH_THRESHOLD=$(( 10 ** $power )) #10-factor threshhold for dynamic rates/errata
					POWER_MATH_DIV_STEPUP=$(( 10 ** $(( $power + 1 )) ))
					POWER_MATH_AVG=$(( $(( $POWER_MATH_DIV_STEPUP - $POWER_MATH_THRESHOLD)) * $POWER_DIV_FACTOR / 1000 ))
					#eg, if Deltas A and B are greater than 10000; then diff min becomes 1350
						if [ $DELTA_old -ge $POWER_MATH_THRESHOLD ] && [ $DELTA_new -ge $POWER_MATH_THRESHOLD ]; then
							DELTA_OFFSET=0
							DIFF_MIN=$POWER_MATH_AVG #For high data transfer
							POWER_TEST=1
							#break
						fi
					done
				fi
		fi 2> /dev/null
	}
	add_strike(){
		wait $!
		if [ $STRIKE_MARK_COUNT_GET = $STRIKECOUNT_GET ]; then
			#Regular strike add
			sed -i -E "s/^.*${ip}\b.*$/&${STRIKE_MARK_SYMB}/g" "/tmp/$RANDOMGET" && #Adds mark for strikes
			eval "iptables -A LDSENTSTRIKE -s $ip" &&
			write_null_to_log
			#Resets ASR counter
			if [ $STRIKERESET = 1 ]; then
				echo -n "0" > "/tmp/${LDTEMPFOLDER}/ld_state_counter/${SENTIPFILENAME}#"
			fi
		fi
	}
	add_strike_fix(){
		wait $!
		#For Strike correction
		sed -i -E "s/^.*${ip}\b.*$/&${STRIKE_MARK_SYMB}/g" "/tmp/$RANDOMGET" #Adds mark for strikes
		write_null_to_log
	}
	fix_strikes(){
		strike_correction(){
		wait $!
			#Strike numbers correction; prevents incorrect strike numbers.
			if [ $STRIKECOUNT_GET != $STRIKE_MARK_COUNT_GET ]; then
				if [ $STRIKECOUNT_GET -lt $STRIKE_MARK_COUNT_GET ]; then
					#If the number of strikes recorded in LDSENTSTRIKE is less than number of strikes recorded in the log, add to SENTSTRIKE
					STRIKE_DIFF="$(( $STRIKE_MARK_COUNT_GET - $STRIKECOUNT_GET ))"
					if [ "$STRIKE_DIFF" -gt "0" ] && [ "$STRIKE_MARK_COUNT_GET" -gt "0" ]; then
						strike_diff_turn_count_remain=0; while [[ $strike_diff_turn_count_remain -lt "${STRIKE_DIFF}" ]]; do { eval "iptables -I LDSENTSTRIKE -s $ip"; }; strike_diff_turn_count_remain="$(( strike_diff_turn_count_remain + 1 ))"; done
					fi; wait $!
				elif [ $STRIKE_MARK_COUNT_GET -lt $STRIKECOUNT_GET ]; then
					#If the number of strikes recorded in the log is less than number of strikes recorded in LSSENTSTRIKE
					STRIKE_DIFF="$(( $STRIKECOUNT_GET - $STRIKE_MARK_COUNT_GET ))"
					if [ "$STRIKE_DIFF" -gt "0" ] && [ "$STRIKECOUNT_GET" -gt "0" ]; then
						strike_diff_turn_count_remain=0; while [[ $strike_diff_turn_count_remain -lt "${STRIKE_DIFF}" ]]; do { add_strike_fix; }; strike_diff_turn_count_remain="$(( strike_diff_turn_count_remain + 1 ))"; done
					fi; wait $!
				fi; wait $!
				#Accurate color to counter matching
				case $STRIKE_MARK_COUNT_GET in
					0)
						if [ $STRIKE_MARK_COUNT_GET -lt 1 ]; then
							if { grep -Eoq "(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b" "/tmp/$RANDOMGET"; }; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip}\b)/${ip}/g" "/tmp/$RANDOMGET"
								sed -i -E "s/(^.*${ip}\b.*#)((${STRIKE_MARK_SYMB}{1,})$)/\1/g" "/tmp/$RANDOMGET"
							fi
						fi
					;;
					1)
						if [ $STRIKE_MARK_COUNT_GET = 1 ]; then
							if { grep -Eoq "(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b" "/tmp/$RANDOMGET"; }; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip}\b)/$(echo -e "${BG_CYAN}")\2/g" "/tmp/$RANDOMGET"
							fi
						fi
					;;
					2)
						if [ $STRIKE_MARK_COUNT_GET = 2 ]; then
							if { grep -Eoq "(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b" "/tmp/$RANDOMGET"; }; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip}\b)/$(echo -e "${BG_GREEN}")\2/g" "/tmp/$RANDOMGET"
							fi
						fi
					;;
					3)
						if [ $STRIKE_MARK_COUNT_GET = 3 ]; then
							if { grep -Eoq "(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b" "/tmp/$RANDOMGET"; }; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip}\b)/$(echo -e "${BG_YELLOW}")\2/g" "/tmp/$RANDOMGET"
							fi
						fi
					;;
					*)
						if [ $STRIKE_MARK_COUNT_GET -ge 4 ]; then
							if { grep -Eoq "(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b" "/tmp/$RANDOMGET"; }; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip}\b)/$(echo -en "${BG_BLUE}")\2/g" "/tmp/$RANDOMGET"
							fi
						fi
					;;
				esac
			fi
		}
		strike_correction
	}
	sentinelstrike(){
		ACT_STATE="$(tail +1 "/tmp/${LDTEMPFOLDER}/ld_act_state/${ACTIPFILENAME}#")"
		STAND_COUNT_READ="$(tail +1 "/tmp/${LDTEMPFOLDER}/ld_act_standby_counter/${SENTIPFILENAME}#")"
		STAND_COUNT_LIMIT=2
		SAFE_TO_BAN=0
		if [ $STAND_COUNT_READ -ge $STAND_COUNT_LIMIT ]; then SAFE_TO_BAN=1; fi
		if { [ $STRIKECOUNT_GET -ge $STRIKEMAX ] || [ $STRIKE_MARK_COUNT_GET -ge $STRIKEMAX ]; }; then # Max strikes. You're OUT!
				LINENUMBERSTRIKEOUTBAN=$(iptables --line-number -nL LDSENTSTRIKE|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
				LINENUMBERSTRIKEOUTACCEPT=$(iptables --line-number -nL LDACCEPT|grep -E "\b${CONSOLE}\b"|grep -E "\b${ip}\b"|grep -Eo "^(\s*)?[0-9]{1,}")
				if [ $SAFE_TO_BAN = 1 ]; then
					if { iptables -nL LDACCEPT|grep -Eoq "\b${ip}\b"; }; then
						eval "iptables -D LDACCEPT $LINENUMBERSTRIKEOUTACCEPT"
					fi
					if ! { iptables -nL LDBAN|grep -Eoq "\b${ip}\b"; }; then
						eval "iptables -A LDBAN -s $ip -j REJECT "${WAITLOCK}"";
						sed -i -E "s/#(.\[[0-9]{1}\;[0-9]{2}m){1,}(${ip})(.*$)/#$(echo -e "${BG_RED}")\2%${SENTINEL_BAN_MESSAGE}%@%$(date +"%X")%$(echo -e "${NC}")/g" "/tmp/$RANDOMGET"; sleep 5
					fi
				fi
			# If less than the max number of strikes...
			else
				if [ "$STRIKECOUNT_GET" -lt "$STRIKEMAX" ]; then
					#Counting Strikes, marking in log
					case "$STRIKECOUNT_GET" in
						0)
							# Strike 1
							if { [ "$STRIKECOUNT_GET" -lt 1 ]; }; then
								sed -i -E "s/(${ip})\b/$(echo -e "${BG_CYAN}")\1/g" "/tmp/$RANDOMGET"
								add_strike
							fi
						;;
						1)
							# Strike 2
							if [ "$STRIKECOUNT_GET" = 1 ]; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b/$(echo -e "${BG_GREEN}")\2/g" "/tmp/$RANDOMGET"
								add_strike
							fi
						;;
						2)
							# Strike 3
							if [ "$STRIKECOUNT_GET" = 2 ]; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b/$(echo -e "${BG_YELLOW}")\2/g" "/tmp/$RANDOMGET"
								add_strike
							fi
						;;
						*)
							# Strike 4 and beyond
							if [ "$STRIKECOUNT_GET" -ge 3 ]; then
								sed -i -E "s/(.\[[0-9]{1}\;[0-9]{2}m){0,}(${ip})\b/$(echo -e "${BG_BLUE}")\2/g" "/tmp/$RANDOMGET"
								add_strike
							fi
						;;
					esac
				fi
		fi
	}
	walkback_strike(){
		wait $!
		if [ $STRIKE_MARK_COUNT_GET = $STRIKECOUNT_GET ]; then
			sed -E -i "s/^(.*${ip}.*)(~$)/\1/" "/tmp/$RANDOMGET" &&
			{
				eval "iptables -D LDSENTSTRIKE -s ${ip}"
			}
		fi; wait $!
	}
	sent_action(){
		fix_strikes
		if { iptables -nL LDACCEPT| grep -E "\b${CONSOLE}\b"|grep -Eoq "\b${ip}\b"; }; then
		{
			case $PACKET_OR_BYTE in
				1)
					#Packet
					BYTE_LABEL="PACKETS"
					byte1="$(echo "${GET_LDACCEPT_VALUES1}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $1}')"
					byte2="$(echo "${GET_LDACCEPT_VALUES2}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $1}')"
					byte1_tare="$(echo "${GET_LDACCEPT_VALUES1}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $2}')"
					byte2_tare="$(echo "${GET_LDACCEPT_VALUES2}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $2}')"
				;;
				2)
					#Bytes
					BYTE_LABEL="BYTES"
					byte1="$(echo "${GET_LDACCEPT_VALUES1}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $2}')"
					byte2="$(echo "${GET_LDACCEPT_VALUES2}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $2}')"
				;;
			esac
			#Absolute value adjust
			if [ $ABS_VAL = 1 ]; then
				byte1=$(echo -n "$byte1"|sed -E "s/-//g")
				byte2=$(echo -n "$byte2"|sed -E "s/-//g")
			fi
			#Math
			DELTA_new="$(( $byte2 - $byte1 )) "
			DELTA_new="$(( DELTA_new / $SENTINELDELAYSMALL ))"
			if [ $PACKET_OR_BYTE != 2 ]; then
				DELTA_new_tare="$(( $(( $byte2_tare - $byte1_tare )) / $SENTINELDELAYSMALL ))"
			fi
			if ! [ -f "/tmp/${LDTEMPFOLDER}/oldval/${SENTIPFILENAME}#" ]; then echo $DELTA_new > "/tmp/${LDTEMPFOLDER}/oldval/${SENTIPFILENAME}#"; fi
			continuous_mode
			if [ $ABS_VAL = 1 ]; then
				#Ensures deltas are positive integers
				DELTA_old=$(echo -n "$DELTA_old"|sed -E "s/-//g")
				DELTA_new=$(echo -n "$DELTA_new"|sed -E "s/-//g")
			fi
			#Tare: Set delta values less than TARE to 0. Should prevent reading of spikes during lobbies and pregame, but allow Sentinel to see true zero transfers.
			if [ $PACKET_OR_BYTE = 2 ]; then
				#bytes
				if [ $DELTA_new -le $TARE ] && [ $DELTA_new -gt 1 ]; then DELTA_new=0; fi
			else
				#packets
				if [ $DELTA_new_tare -le $TARE ] || [ $DELTA_new -lt $DELTA_AVGLIMIT ] || { [ $DELTA_new -lt $PACKET_TARE ] && [ $DELTA_new -gt 1 ]; }; then DELTA_new=0; fi
			fi
			if [ $ABS_VAL = 1 ]; then
				DELTA_old=$(echo -n "$DELTA_old"|sed -E "s/-//g")
				DELTA_new=$(echo -n "$DELTA_new"|sed -E "s/-//g")
				DELTA_new_tare=$(echo -n "$DELTA_new_tare"|sed -E "s/-//g")
				DELTA_DIFF="$(( $DELTA_new - $DELTA_old ))"
				DELTA_DIFF=$(echo -n "$DELTA_DIFF"|sed -E "s/-//g")
				if [ $DELTA_new = $DELTA_old ]; then DELTA_DIFF=0; fi #DELTA_DIFF Correction
			else
				DELTA_DIFF="$(( $DELTA_new - $DELTA_old ))"
			fi
			DELTA_SUM="$(( $DELTA_new + $DELTA_old ))"
			DELTA_AVG="$(( $DELTA_SUM / 2 ))"
			if [ $DELTA_AVG = 0 ]; then DELTA_AVG=1; fi
			DELTA_DIFFSQ="$(( $DELTA_DIFF * $DELTA_DIFF ))"
			DELTA_XSQ="$(( $DELTA_DIFFSQ / $DELTA_AVG ))"
			DELTA_STD_DEV="$(( (( 100 * $DELTA_DIFF )) / $DELTA_AVG ))"
			# These values should never be negative. That causes problems. This occurs often when using bytes.
			DELTA_DIFFSQ=$(echo -n "$DELTA_DIFFSQ"|sed -E "s/-//g")
			DELTA_XSQ=$(echo -n "$DELTA_XSQ"|sed -E "s/-//g")
			DELTA_STD_DEV=$(echo -n "$DELTA_STD_DEV"|sed -E "s/-//g")
			if [ ! -d "/tmp/${LDTEMPFOLDER}" ]; then mkdir -p "/tmp/${LDTEMPFOLDER}" ; fi
			echo "$DELTA_new" > "/tmp/${LDTEMPFOLDER}/oldval/${SENTIPFILENAME}#"
			#Verify Values; mirrors how Sentinel will observe values
			if [ $VERIFY_VALUES = 1 ]; then
				#Write values
				VV_WRITE_LIMIT=1
				#if { { [ $DELTA_old = 0 ] && [ $DELTA_new != 0 ]; } || { [ $DELTA_old != 0 ] && [ $DELTA_new = 0 ]; }; }; then
				if { { { [ $DELTA_old = 0 ] && [ $DELTA_new != 0 ]; } && [ $(tail +2 ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|tail -${VV_WRITE_LIMIT}|grep -Eo "0\t0\t0\t0\t1\t0\t0\t0$"|wc -l) = $VV_WRITE_LIMIT ]; } || { { { [ $DELTA_old != 0 ] && [ $DELTA_new = 0 ]; } || { [ $DELTA_old = 0 ] && [ $DELTA_new != 0 ]; };} && [ $(tail +2 ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|tail -$(( ${VV_WRITE_LIMIT} * 5 ))|grep -Eo "[1-9]?[0-9]?[1-9]{1,}\t[1-9]?[0-9]?[1-9]{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}$"|wc -l) != $VV_WRITE_LIMIT ]; }; }; then
					write_DELTA_old=0
					write_DELTA_new=0
					write_DELTA_SUM=0
					write_DELTA_DIFF=0
					write_DELTA_AVG=1
					write_DELTA_DIFFSQ=0
					write_DELTA_XSQ=0
					write_DELTA_STD_DEV=0
				else
					write_DELTA_old=$DELTA_old
					write_DELTA_new=$DELTA_new
					write_DELTA_SUM=$DELTA_SUM
					write_DELTA_DIFF=$DELTA_DIFF
					write_DELTA_AVG=$DELTA_AVG
					write_DELTA_DIFFSQ=$DELTA_DIFFSQ
					write_DELTA_XSQ=$DELTA_XSQ
					write_DELTA_STD_DEV=$DELTA_STD_DEV
				fi
				{
					#Prep for verify file
					GET_LOCATION_VV="$(grep -E "^(${SENTIPFILENAME})#" ""$DIR"/42Kmi/${GEOMEMFILE}"|sed -E "s/^.*#//g")"
					IP_MASK="$(echo ${ip}|sed -E "s/\.[0-9]{1,3}\.[0-9]{1,3}\./.xx.xx./g")"
					#Make verify folder
					if ! [ -d ""${DIR}"/42Kmi/verify/" ]; then mkdir ""${DIR}"/42Kmi/verify/"; fi
					vv_header(){
					#Make header for verifyvalues.txt
					HEADER_VV="Epoch\tTIME\t${BYTE_LABEL}diffA\t${BYTE_LABEL}diffB\t${BYTE_LABEL}SUM\t${BYTE_LABEL}DIFF\t${BYTE_LABEL}AVG\t${BYTE_LABEL}DIFFSQ\t${BYTE_LABEL}XSQ\t${BYTE_LABEL}STD_DEV"
					HEADER_ID="${IP_MASK} [${GET_LOCATION_VV}] $(date)"
					HEADER_HIGHLIGHT="${DELTA_AVGLIMIT}\t${SENTLOSSLIMIT}\t${CHI_LIMIT}\t${DELTA_STD_DEV_LIMIT}"
					if [ -f ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt" ]; then
						if ! { grep -Eq "^(${HEADER_VV})" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"; }; then
							echo -e "${HEADER_VV}\t${HEADER_HIGHLIGHT}\t${HEADER_ID}" >> ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"
						fi
					else
						echo -e "${HEADER_VV}\t${HEADER_HIGHLIGHT}\t${HEADER_ID}" > ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"
					fi
					}
					#Populate verifyvalues.txt
					VV_WRITE_LIMIT=1 #Maximum allowed number of consecutive 0 entries. To save space.
					if [ $write_DELTA_SUM = 0 ] && [ $write_DELTA_DIFF = 0 ] && [ $write_DELTA_STD_DEV = 0 ] && [ $(tail +2 ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|tail -${VV_WRITE_LIMIT}|grep -Eo "0\t0\t0\t0\t1\t0\t0\t0$"|wc -l) = $VV_WRITE_LIMIT ]; then :;
					else
						vv_header
						#GET_DATE=$(date +%s)
						GET_DATE="${GET_DATE_INIT}"
						WRITE_DATE=$(date -d "@$GET_DATE" +%X)
						GET_DATE_MINUS_1=$(( $GET_DATE - 1))
						WRITE_DATE_MINUS_1=$(date -d "@$GET_DATE_MINUS_1" +%X)
						GET_DATE_PLUS_1=$(( $GET_DATE + 1))
						WRITE_DATE_PLUS_1=$(date -d "@$GET_DATE_PLUS_1" +%X)
						WRITE_BLANK="${GET_DATE_MINUS_1}\t${WRITE_DATE_MINUS_1}\t0\t0\t0\t0\t1\t0\t0\t0"
						#Add a blank after consecutive blanks just before adding real value. For graph accuracy.
						if [ $(tail +2 ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|tail -${VV_WRITE_LIMIT}|grep -Eo "0\t0\t0\t0\t1\t0\t0\t0$"|wc -l) = $VV_WRITE_LIMIT ]; then
							if ! { grep -Eq "^${GET_DATE_MINUS_1}" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"; }; then
								echo -e "${WRITE_BLANK}" >> ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"
							fi
						fi
						if { grep -Eq "^${GET_DATE}" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"; }; then
							echo -e "${GET_DATE_PLUS_1}\t${WRITE_DATE_PLUS_1}\t${write_DELTA_old}\t${write_DELTA_new}\t${write_DELTA_SUM}\t${write_DELTA_DIFF}\t${write_DELTA_AVG}\t${write_DELTA_DIFFSQ}\t${write_DELTA_XSQ}\t${write_DELTA_STD_DEV}" >> ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"
						else
							echo -e "${GET_DATE}\t${WRITE_DATE}\t${write_DELTA_old}\t${write_DELTA_new}\t${write_DELTA_SUM}\t${write_DELTA_DIFF}\t${write_DELTA_AVG}\t${write_DELTA_DIFFSQ}\t${write_DELTA_XSQ}\t${write_DELTA_STD_DEV}" >> ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"
						fi
					fi
					#InlineCorrections
					{
						READING_FRAME=3
						if [ -f ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt" ]; then
							#Remove bookend zero to non-zero/non-zero to zero values
							(
								GET_LINE_TO_CORRECT="$(tail -${READING_FRAME} ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|grep -Eo -C 1 -m 1 "^[0-9]{10,}\t(\d{2}:\d{2}:\d{2})\t(([1-9]?[0-9]?[1-9]{1,}0?\t\b0|\b0\t[1-9]?[0-9]?[1-9]{1,}0?).*$)")"
								CHECK_LINE_TO_CORRECT_LC="$(echo "$GET_LINE_TO_CORRECT"|wc -l)"
								if [ -n "$GET_LINE_TO_CORRECT" ] && [ $CHECK_LINE_TO_CORRECT_LC -ge "${READING_FRAME}" ]; then
									CHECK_LINE1="$(echo "$GET_LINE_TO_CORRECT"|sed -n 1p)"
									CHECK_LINE2="$(echo "$GET_LINE_TO_CORRECT"|sed -n 2p)"
									CHECK_LINE2_sub="$(echo "$CHECK_LINE2"|sed -E "s/\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}$/0\t0\t0\t0\t1\t0\t0\t0/g")"
									CHECK_LINE3="$(echo "$GET_LINE_TO_CORRECT"|sed -n 3p)"
									if { { echo "$CHECK_LINE1"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; } || { echo "$CHECK_LINE3"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; }; }; then
										sed -i -E "s/${CHECK_LINE2}/${CHECK_LINE2_sub}/" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt" &&
										walkback_strike #Subtract from Strikes
									fi
								fi
							)
							#Remove bookend zero to non-zero/non-zero to zero values: leading blanks
							(
								GET_LINE_TO_CORRECT="$(tail -${READING_FRAME} ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|grep -Eo -B 2 -m 1 "^[0-9]{10,}\t(\d{2}:\d{2}:\d{2})\t(([1-9]?[0-9]?[1-9]{1,}0?\t\b0|\b0\t[1-9]?[0-9]?[1-9]{1,}0?).*$)")"
								CHECK_LINE_TO_CORRECT_LC="$(echo "$GET_LINE_TO_CORRECT"|wc -l)"
								if [ -n "$GET_LINE_TO_CORRECT" ] && [ $CHECK_LINE_TO_CORRECT_LC -ge "${READING_FRAME}" ]; then
									CHECK_LINE1="$(echo "$GET_LINE_TO_CORRECT"|sed -n 1p)"
									CHECK_LINE2="$(echo "$GET_LINE_TO_CORRECT"|sed -n 2p)"
									CHECK_LINE3="$(echo "$GET_LINE_TO_CORRECT"|sed -n 3p)"
									CHECK_LINE3_sub="$(echo "$CHECK_LINE3"|sed -E "s/\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}$/0\t0\t0\t0\t1\t0\t0\t0/g")"
									if { { echo "$CHECK_LINE1"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; } && { echo "$CHECK_LINE2"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; }; }; then
										sed -i -E "s/${CHECK_LINE3}/${CHECK_LINE3_sub}/" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt" #&&
										#walkback_strike #Subtract from Strikes
									fi
								fi
							)
							#Remove bookend zero to non-zero/non-zero to zero values: trailing blanks
							(
								GET_LINE_TO_CORRECT="$(tail -${READING_FRAME} ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|grep -Eo -A 2 -m 1 "^[0-9]{10,}\t(\d{2}:\d{2}:\d{2})\t(([1-9]?[0-9]?[1-9]{1,}0?\t\b0|\b0\t[1-9]?[0-9]?[1-9]{1,}0?).*$)")"
								CHECK_LINE_TO_CORRECT_LC="$(echo "$GET_LINE_TO_CORRECT"|wc -l)"
								if [ -n "$GET_LINE_TO_CORRECT" ] && [ $CHECK_LINE_TO_CORRECT_LC -ge "${READING_FRAME}" ]; then
									CHECK_LINE1="$(echo "$GET_LINE_TO_CORRECT"|sed -n 1p)"
									CHECK_LINE1_sub="$(echo "$CHECK_LINE1"|sed -E "s/\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}$/0\t0\t0\t0\t1\t0\t0\t0/g")"
									CHECK_LINE2="$(echo "$GET_LINE_TO_CORRECT"|sed -n 2p)"
									CHECK_LINE3="$(echo "$GET_LINE_TO_CORRECT"|sed -n 3p)"
									if { { echo "$CHECK_LINE2"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; } && { echo "$CHECK_LINE3"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; }; }; then
										sed -i -E "s/${CHECK_LINE1}/${CHECK_LINE1_sub}/" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt" #&&
										#walkback_strike #Subtract from Strikes
									fi
								fi
							)
							#Remove blips between all-zero values
							(
								GET_LINE_TO_CORRECT="$(tail -${READING_FRAME} ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|grep -Eo -C 1 "^[0-9]{10,}\t(\d{2}:\d{2}:\d{2})\t(([1-9]?[0-9]?[1-9]{1,}0?\t){2}.*$)"|grep -Eo "^[0-9]{10,}\t(\d{2}:\d{2}:\d{2})\t(([1-9]?[0-9]?[1-9]{1,}0?\t){2}.*$)")"
								for line in "$GET_LINE_TO_CORRECT"; do
									COMB_GET_LINE_TO_CORRECT="$(grep -Eo -C 1 "$line" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt")"
									COMB_CHECK_LINE1="$(echo "$COMB_GET_LINE_TO_CORRECT"|sed -n 1p)"
									COMB_CHECK_LINE2="$(echo "$COMB_GET_LINE_TO_CORRECT"|sed -n 2p)"
									COMB_CHECK_LINE2_sub="$(echo "$COMB_CHECK_LINE2"|sed -E "s/\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}$/0\t0\t0\t0\t1\t0\t0\t0/g")"
									COMB_CHECK_LINE3="$(echo "$COMB_GET_LINE_TO_CORRECT"|sed -n 3p)"
									if { { echo "$COMB_CHECK_LINE1"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; } && { echo "$COMB_CHECK_LINE3"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; }; }; then
										sed -i -E "s/${COMB_CHECK_LINE2}/${COMB_CHECK_LINE2_sub}/" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt" &&
										walkback_strike #Subtract from Strikes
									fi
								done
							)
							#Remove blips between all-zero values: full-comb
							(
								GET_LINE_TO_CORRECT="$(tail + 1 ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt"|grep -Eo -C 1 "^[0-9]{10,}\t(\d{2}:\d{2}:\d{2})\t(([1-9]?[0-9]?[1-9]{1,}0?\t){2}.*$)"|grep -Eo "^[0-9]{10,}\t(\d{2}:\d{2}:\d{2})\t(([1-9]?[0-9]?[1-9]{1,}0?\t){2}.*$)")"
								for line in "$GET_LINE_TO_CORRECT"; do
									COMB_GET_LINE_TO_CORRECT="$(grep -Eo -C 1 "$line" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt")"
									COMB_CHECK_LINE1="$(echo "$COMB_GET_LINE_TO_CORRECT"|sed -n 1p)"
									COMB_CHECK_LINE2="$(echo "$COMB_GET_LINE_TO_CORRECT"|sed -n 2p)"
									COMB_CHECK_LINE2_sub="$(echo "$COMB_CHECK_LINE2"|sed -E "s/\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}\t\d{1,}$/0\t0\t0\t0\t1\t0\t0\t0/g")"
									COMB_CHECK_LINE3="$(echo "$COMB_GET_LINE_TO_CORRECT"|sed -n 3p)"
									if { { echo "$COMB_CHECK_LINE1"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; } && { echo "$COMB_CHECK_LINE3"|grep -Eoq "\t0\t0\t0\t0\t1\t0\t0\t0$"; }; }; then
										sed -i -E "s/${COMB_CHECK_LINE2}/${COMB_CHECK_LINE2_sub}/" ""${DIR}"/42Kmi/verify/verifyvalues#${SENTIPFILENAME}#.txt" #&&
										#walkback_strike #Subtract from Strikes
									fi
								done
							)
						fi
					}
				}
			fi
			##### SENTINELS #####
			{
				errata
				if [ $DELTA_new -gt $DELTA_AVGLIMIT ] || [ $DELTA_old -gt $DELTA_AVGLIMIT ]; then
					##### PACKETBLOCK ##### // 0 or 1=Difference, 2=X^2, 3=Difference or X^2, 4=Difference & X^2, 5=Difference, X^2, & Std Dev
					case "${SENTMODE}" in
						0|1) # Difference only
							DELTA_BLOCK=$({ if { { [ $DELTA_new -gt $DELTA_AVGLIMIT ] || [ $DELTA_old -gt $DELTA_AVGLIMIT ]; } && [ "${DELTA_AVG}" -gt "${DELTA_AVGLIMIT}" ] && [ "${DELTA_DIFF}" -ge "${SENTLOSSLIMIT}" ]; }; then sentinelstrike; fi; } &)
							;;
						2) #X^2 only
							DELTA_BLOCK=$({ if { { [ $DELTA_new -gt $DELTA_AVGLIMIT ] || [ $DELTA_old -gt $DELTA_AVGLIMIT ]; } && [ "${DELTA_AVG}" -gt "${DELTA_AVGLIMIT}" ] && [ "${DELTA_XSQ}" -gt "${CHI_LIMIT}" ]; }; then sentinelstrike; fi; } &)
							;;
						3) #Difference or X^2
							DELTA_BLOCK=$({ if { [ $DELTA_new -gt $DELTA_AVGLIMIT ] || [ $DELTA_old -gt $DELTA_AVGLIMIT ]; } && { [ "${DELTA_AVG}" -gt "${DELTA_AVGLIMIT}" ] && [ "${DELTA_DIFF}" -ge "${SENTLOSSLIMIT}" ]; } || [ "${DELTA_XSQ}" -gt "${CHI_LIMIT}" ]; then sentinelstrike; fi; } &)
							;;
						4) #Difference AND X^2
							DELTA_BLOCK=$({ if { [ $DELTA_new -gt $DELTA_AVGLIMIT ] || [ $DELTA_old -gt $DELTA_AVGLIMIT ]; } && { [ "${DELTA_AVG}" -gt "${DELTA_AVGLIMIT}" ] && [ "${DELTA_DIFF}" -ge "${SENTLOSSLIMIT}" ]; } && [ "${DELTA_XSQ}" -gt "${CHI_LIMIT}" ]; then sentinelstrike; fi; } &)
							;;
						5) #Difference AND X^2 AND STD_DEV
							DELTA_BLOCK=$({ if { [ $DELTA_new -gt $DELTA_AVGLIMIT ] || [ $DELTA_old -gt $DELTA_AVGLIMIT ]; } && { [ "${DELTA_AVG}" -gt "${DELTA_AVGLIMIT}" ] && [ "${DELTA_DIFF}" -ge "${SENTLOSSLIMIT}" ] && [ "${DELTA_XSQ}" -gt "${CHI_LIMIT}" ] && [ "${DELTA_STD_DEV}" -gt "${DELTA_STD_DEV_LIMIT}" ]; }; then sentinelstrike; fi; } &)
					;;
					esac
				fi
			}
		} & #Comment if it causes problems
		fi
			#Sentinel Activity
			{
				if { [ $DELTA_old = 0 ] && [ $DELTA_new = 0 ]; } || { [ $DELTA_SUM = 0 ] || [ $DELTA_DIFF = 0 ]; }; then :; #Don't run Sentinel action for zero values.
				else
					if [ $DELTA_new != $DELTA_old ]; then
						if ! { [ $DELTA_new = $DELTA_old ] && [ $DELTA_DIFF != 0 ]; }; then
							if [ $DELTA_new -gt $DELTA_AVGLIMIT ] && [ $DELTA_old -gt $DELTA_AVGLIMIT ]; then
								if [ $DELTA_SUM != 0 ]; then
									if [ $DELTA_DIFF != 0 ]; then
										if [ $DELTA_new -gt $(( $DIFF_MIN + $DELTA_OFFSET )) ] || [ $DELTA_old -gt $(( $DIFF_MIN + $DELTA_OFFSET )) ]; then
											$DELTA_BLOCK
										fi
									fi
								fi
							fi
						fi
					fi
				fi
			} &
		}
	sentinel_openwrt(){
		while "$@" &> /dev/null; do
		exit_trap
		{
			get_the_values
			SENTINELLIST="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed -E "/\b(${RESPONSE3})\b/d"|sed "/${SENTINEL_BAN_MESSAGE}/d"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
			SENTINELLIST_COUNT="$(echo "$SENTINELLIST"|wc -l)"
		#====================================================
			#Sentinel will act only if DELTA_new and DELTA_old are greater than DIFF_MIN. Varies with game.
			if [ $SENTBAN = 1 ]; then
				STRIKEMAX="$STRIKECOUNT_LIMIT"
			else
				STRIKEMAX=999999999 #Effectively disabled
			fi
			SENTINELLIST="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed -E "/\b(${RESPONSE3})\b/d"|sed "/${SENTINEL_BAN_MESSAGE}/d"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
			if [ -f "$DIR"/42Kmi/tweak.txt ]; then
				PACKET_OR_BYTE=$TWEAK_PACKET_OR_BYTE
				SENTINELDELAYSMALL=$TWEAK_SENTINELDELAYSMALL
				STRIKEMAX=$TWEAK_STRIKEMAX
				ABS_VAL=$TWEAK_ABS_VAL
				SENTMODE=$TWEAK_SENTMODE
				SENTLOSSLIMIT=$TWEAK_SENTLOSSLIMIT
			else
				SENTINELDELAYSMALL=1 #1 #Establishes deltas
				STRIKEMAX="$STRIKECOUNT_LIMIT" #Max number of strikes before banning
				ABS_VAL=1 #Absolute value (e.g.: 3 - 5 = 2). Set to 0 to disable. Don't Change
				SENTMODE=5 #4 #3 #0 or 1=Difference, 2=X^2, 3=Difference or X^2, 4=Difference & X^2
					#If DELTA_DIFF -gt SENTLOSSLIMIT, Sentinel will act. These values are constant regardless of game played.
				if [ $PACKET_OR_BYTE = 2 ]; then
					DELTA_DIV=1
					#Bytes
					DELTA_AVGLIMIT=5000 #6500 #Don't change. Derived from active matches during Super Smash Bros. Ultimate.
					TARE="${DELTA_AVGLIMIT}" #5000
					PACKET_TARE=20
					SENTLOSSLIMIT=600 #Don't change
					#Correction
					DELTA_AVGLIMIT="$(( $DELTA_AVGLIMIT / $DELTA_DIV ))"
					CHI_LIMIT=100
					DELTA_STD_DEV_LIMIT=10 #Don't change
				else
					#Packets
					DELTA_AVGLIMIT=30 #35 #Don't change
					TARE=5000 #6500 #Tare acts based on bytes transferred
					SENTLOSSLIMIT=4 #Don't change
					CHI_LIMIT=0 #Don't change
					DELTA_STD_DEV_LIMIT=14 #Don't change
				fi
			fi
		#====================================================
			#This is where Sentinel Execution happens.
			for ip in $SENTINELLIST; do
				#Strike Counts
				{
					 #Get strike count from log.
					STRIKE_MARK_COUNT_GET="$(grep -E "#(.\[[0-9]{1}\;[0-9]{2}m)(${ip})\b" "/tmp/$RANDOMGET"|sed "/${SENTINEL_BAN_MESSAGE}/d"|grep -Eo "(${STRIKE_MARK_SYMB}{1,}$)"|wc -c)"
					if [ $STRIKE_MARK_COUNT_GET -le 0 ]; then STRIKE_MARK_COUNT_GET=0; else STRIKE_MARK_COUNT_GET=$(( STRIKE_MARK_COUNT_GET - 1 )); fi
					#Get strikes from LDSENTSTRIKE
					if [ "${SHELLIS}" = "ash" ]; then
						STRIKECOUNT_GET="$(iptables -nL LDSENTSTRIKE "$WAITLOCK"|tail +3|grep -E "\b${ip}\b"|wc -l)"
					else
						STRIKECOUNT_GET="$(iptables -nL LDSENTSTRIKE|tail +3|grep -E "\b${ip}\b"|wc -l)"
					fi
			}
			SENTIPFILENAME="$(panama ${ip})"
			(
			if [ $SENTINELLIST_COUNT -gt 1 ]; then
				#sent_action &
				( sent_action ) &
			else
				sent_action
			fi
			) &
		done
		}
			sentinel_bans
			cleansentinel &
		done 2> /dev/null &
	}
	sentinel(){
		while "$@" &> /dev/null; do
			exit_trap
			{
				get_the_values
				SENTINELLIST="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed -E "/\b(${RESPONSE3})\b/d"|sed "/${SENTINEL_BAN_MESSAGE}/d"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
				SENTINELLIST_COUNT="$(echo "$SENTINELLIST"|wc -l)"
			#====================================================
				if [ $SENTBAN = 1 ]; then
					STRIKEMAX="$STRIKECOUNT_LIMIT"
				else
					STRIKEMAX=999999999 #Effectively disabled
				fi
				#This is where Sentinel Execution happens.
				for ip in $SENTINELLIST; do
					#Strike Counts
					{
						 #Get strike count from log.
						STRIKE_MARK_COUNT_GET="$(grep -E "#(.\[[0-9]{1}\;[0-9]{2}m)(${ip})\b" "/tmp/$RANDOMGET"|sed "/${SENTINEL_BAN_MESSAGE}/d"|grep -Eo "(${STRIKE_MARK_SYMB}{1,}$)"|wc -c)"
						if [ $STRIKE_MARK_COUNT_GET -le 0 ]; then STRIKE_MARK_COUNT_GET=0; else STRIKE_MARK_COUNT_GET=$(( STRIKE_MARK_COUNT_GET - 1 )); fi
						#Get strikes from LDSENTSTRIKE
						if [ "${SHELLIS}" = "ash" ]; then
							STRIKECOUNT_GET="$(iptables -nL LDSENTSTRIKE "$WAITLOCK"|tail +3|grep -E "\b${ip}\b"|wc -l)"
						else
							STRIKECOUNT_GET="$(iptables -nL LDSENTSTRIKE|tail +3|grep -E "\b${ip}\b"|wc -l)"
						fi
					}
					SENTIPFILENAME="$(panama ${ip})"
					if [ -f "$DIR"/42Kmi/tweak.txt ]; then
						SENTINELDELAYSMALL=$TWEAK_SENTINELDELAYSMALL;
						ABS_VAL=$TWEAK_ABS_VAL
						SENTMODE=$TWEAK_SENTMODE
						SENTLOSSLIMIT=$TWEAK_SENTLOSSLIMIT
					else
						SENTINELDELAYSMALL=1 #1 #Establishes deltas
						ABS_VAL=1 #Absolute value (e.g.: 3 - 5 = 2). Set to 0 to disable. Don't Change
						SENTMODE=5 #0 or 1=Difference, 2=X^2, 3=Difference or X^2, 4=Difference & X^2, 5=Difference & X^2 & StdDev
						#LOG_PINGTRGET="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -E "\b(${ip})\b"|grep -Eo "\b(#[0-9]{1,}\.[0-9]{3})ms\b"|sed "s/#//g"|sed -E "s/\.[0-9]{3}ms$//g")" #Ignores approximated pings
						LOG_PINGTRGET="$(tail +1 "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -E "\b(${ip})\b"|grep -Eo "\b([0-9]{1,}\.[0-9]{3})ms\b"|sed "s/#//g"|sed -E "s/\.[0-9]{3}ms$//g")" #Includes approximated pings
						LOG_PING="$(echo "$LOG_PINGTRGET"|sed -n 1p)"; if ! { echo "$LOG_PING"|grep -Eoq "[0-9]{1,}"; }; then LOG_PING=0; fi
						LOG_TR="$(echo "$LOG_PINGTRGET"|sed -n 2p)"; if ! { echo "$LOG_TR"|grep -Eoq "[0-9]{1,}"; }; then LOG_TR=0; fi
						if [ $LOG_PING = 0 ]; then LOG_TR=0; fi
						#Math
						LOG_PING_TR_SUM=$(( LOG_PING + LOG_TR ))
						LOG_PING_TR_AVG=$(( LOG_PING_TR_SUM / 2 ))
						if [ $LOG_PING_TR_AVG = 0 ]; then LOG_PING_TR_AVG=1; fi
						LOG_PING_TR_DIFF=$(( LOG_PING - LOG_TR ));LOG_PING_TR_DIFF=$(echo -n "$LOG_PING_TR_DIFF"|sed -E "s/-//g")
						LOG_PING_TR_DIFFSQ=$(( LOG_PING_TR_DIFF * LOG_PING_TR_DIFF ))
						LOG_PING_TR_XSQ=$(( LOG_PING_TR_DIFFSQ / LOG_PING_TR_AVG )); LOG_PING_TR_XSQ=$(echo -n "$LOG_PING_TR_XSQ"|sed -E "s/-//g")
						LOG_PING_TR_MATH="$LOG_PING_TR_XSQ"
						COEFFICIENT=$(( LOG_PING_TR_XSQ ))
						LOG_PING_LIMIT_BOTTOM=100 #150 #100
						LOG_PING_LIMIT_TOP=300
						if [ $PACKET_OR_BYTE = 2 ]; then
							#Bytes
							DELTA_AVGLIMIT=5000 #6500 #Don't change. Derived from active matches during Super Smash Bros. Ultimate.
							TARE="${DELTA_AVGLIMIT}" #5000
							if [ $COEFFICIENT -ge $LOG_PING_LIMIT_BOTTOM ] && [ $COEFFICIENT -le $LOG_PING_LIMIT_TOP ]; then
								SENTLOSSLIMIT_INIT=400 #500 #1100
								SENTLOSSLIMIT=$(( $(( SENTLOSSLIMIT_INIT * COEFFICIENT )) / 100 )) #Scales based on PING time
							else
								SENTLOSSLIMIT=600 #700 #400 #500 #1100 #Don't change
							fi
							#Correction
							CHI_LIMIT=100 #60 #40 #20 #100 #110
							DELTA_STD_DEV_LIMIT=10 #14 #Don't change
						else
							#Packets
							DELTA_AVGLIMIT=30 #35 #Don't change
							TARE=5000 #6500 #Tare acts based on bytes transferred
							if [ $COEFFICIENT -ge $LOG_PING_LIMIT_BOTTOM ] && [ $COEFFICIENT -le $LOG_PING_LIMIT_TOP ]; then
								SENTLOSSLIMIT_INIT=4 #Don't change
								SENTLOSSLIMIT=$(( $(( SENTLOSSLIMIT_INIT * COEFFICIENT )) / 100 )) #Scales based on PING time
							else
								SENTLOSSLIMIT=4 #Don't change
							fi
							CHI_LIMIT=0 #Don't change
							DELTA_STD_DEV_LIMIT=14 #Don't change
						fi
					fi
					#usleep corrections
					USLEEP_DELAY_TIME="$(( $SENTINELDELAYSMALL * $USLEEP_DELAY_MULTIPLIER ))"
					if [ $USLEEP_EXISTS = 1 ]; then
						DELTA_AVGLIMIT=$(( DELTA_AVGLIMIT / 2 ))
						TARE=$(( TARE / 2 ))
					fi
					(
					if [ $SENTINELLIST_COUNT -gt 1 ]; then
						#sent_action &
						( sent_action ) &
					else
						sent_action
					fi
					) &
				done 2> /dev/null
			}
		done 2> /dev/null &
	}
if [ "${SHELLIS}" != "ash" ]; then
	sentinel 2> /dev/null &
else
	sentinel_openwrt 2> /dev/null &
fi
}
fi
###### SENTINELS #####
#==========================================================================================================
##### ACTIVE PEER INDICATOR #####
active_peer_id(){
	while "$@" &> /dev/null; do
	{
		ACTIVE_BYTE_LIMIT=4000 #2000 #1000
		#usleep corrections
		if [ $USLEEP_EXISTS = 1 ]; then
			ACTIVE_BYTE_LIMIT=$(( ACTIVE_BYTE_LIMIT / 2 ))
		fi
		if [ ! -d "/tmp/${LDTEMPFOLDER}/ld_act_state" ]; then mkdir "/tmp/${LDTEMPFOLDER}/ld_act_state"; fi
		#Get Values
		{
			if [ "$SENTINEL" = 1 ]; then
				ACTIVE_PEER_GET1="$(tail +1 "/tmp/${LDTEMPFOLDER}/ldacceptval1")"
				ACTIVE_PEER_GET2="$(tail +1 "/tmp/${LDTEMPFOLDER}/ldacceptval2")"
			else
				#Get iptables LDACCEPT values
				ACTIVE_DELAY=1
				USLEEP_DELAY_TIME="$(( $ACTIVE_DELAY * $USLEEP_DELAY_MULTIPLIER ))"
				ACTIVE_PEER_GET1="$(iptables -xvnL LDACCEPT)"
				if [ $USLEEP_EXISTS = 1 ]; then usleep $USLEEP_DELAY_TIME; else sleep $ACTIVE_DELAY; fi
				ACTIVE_PEER_GET2="$(iptables -xvnL LDACCEPT)"
			fi
		}
			ALLOWED_PEERS_LIST="$(grep -v "${RESPONSE3}" "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
			if [ -z $ALLOWED_PEERS_LIST ]; then write_null_to_log; fi
		act_peer_task(){
			if [ "$(tail +1 "/tmp/${LDTEMPFOLDER}/ld_act_state/${ACTIPFILENAME}#")" != "${ACT_SUB_WRITE}" ]; then
				echo "${ACT_SUB_WRITE}" > "/tmp/${LDTEMPFOLDER}/ld_act_state/${ACTIPFILENAME}#"
				touch -c "/tmp/${LDTEMPFOLDER}/ld_act_state"
				WRITE_NULL=1
			fi
		}
		#Do Math
		{
			for ip in $ALLOWED_PEERS_LIST; do
				ACTIPFILENAME="$(panama ${ip})"
				#Packet
				byte_act1="$(echo "${ACTIVE_PEER_GET1}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $2}')"
				byte_act2="$(echo "${ACTIVE_PEER_GET2}"|tail +3|grep -E "\b${ip}\b"|awk '{printf $2}')"
				#Packet deltas
				byte_act_deltaA="$(( byte_act2 - byte_act1 ))"
				#Abs Values
				byte_act_deltaA="$(echo -n "$byte_act_deltaA"|sed -E "s/-//g")"
				case $byte_act_deltaA in
					0)
						#if a packet delta is zero...
						#... write a red X
						ACT_SUB_WRITE="${NOT_CONNECT_MARK}"
						act_peer_task
					;;
					*)
						if [ $byte_act_deltaA -ge $ACTIVE_BYTE_LIMIT ]; then
							#if a packet delta is greater than 800...
							#... write green dot.
							ACT_SUB_WRITE="${CONNECT_MARK}"
							act_peer_task
						elif [ $byte_act_deltaA -lt $ACTIVE_BYTE_LIMIT ] && [ $byte_act_deltaA -gt 0 ]; then
							#if a packet delta is greater than zero but less than 800...
							#... write magenta square.
							ACT_SUB_WRITE="${STANDBY_SYMB}"
							act_peer_task
						fi
					;;
				esac
				{
				if [ "$SENTINEL" = 1 ]; then
					#Standby counter: increments when status is in standby. Used by Sentinel for safe banning.
					if [ "$SENTBAN" = 1 ]; then
						if [ ! -d "/tmp/${LDTEMPFOLDER}/ld_act_standby_counter" ]; then mkdir "/tmp/${LDTEMPFOLDER}/ld_act_standby_counter"; fi
						GET_STATE="$(tail +1 "/tmp/${LDTEMPFOLDER}/ld_act_state/${ACTIPFILENAME}#")"
						STAND_COUNT_GET="$(tail +1 "/tmp/${LDTEMPFOLDER}/ld_act_standby_counter/${ACTIPFILENAME}#")"
						STAND_COUNT_GET_ADD_1=$(( STAND_COUNT_GET + 1 ))
						STAND_GET_LINE="$(tail +1 "/tmp/$RANDOMGET"|grep -E "(#|m)(${ip})\b")"
						STAND_STRIKE_MARK_COUNT="$(echo "$ASR_GET_LINE"|grep -Eo "(${STRIKE_MARK_SYMB}{1,})$"|wc -c)"
						if [ $STAND_STRIKE_MARK_COUNT -le 0 ]; then STAND_STRIKE_MARK_COUNT=0; else STAND_STRIKE_MARK_COUNT=$(( ASR_STRIKE_MARK_COUNT - 1 )); fi
						if [ $STAND_STRIKE_MARK_COUNT -gt 0 ]; then
						#if [ $STAND_STRIKE_MARK_COUNT -ge $STRIKECOUNT_LIMIT ]; then
							#if [ "$GET_STATE" = "$STANDBY_SYMB" ]; then
							if [ "$GET_STATE" != "$CONNECT_MARK" ]; then
								echo "$STAND_COUNT_GET_ADD_1" > "/tmp/${LDTEMPFOLDER}/ld_act_standby_counter/${ACTIPFILENAME}#"
							else
								if [ $ASR_STRIKE_MARK_COUNT -gt $STRIKECOUNT_LIMIT ]; then :;
								else
									echo "0" > "/tmp/${LDTEMPFOLDER}/ld_act_standby_counter/${ACTIPFILENAME}#"
								fi
							fi
						fi
					fi
					#Auto Strike Reset
					if [ "$STRIKERESET" = 1 ]; then
						#Make counter folder
						if [ ! -d "/tmp/${LDTEMPFOLDER}/ld_state_counter/" ]; then mkdir "/tmp/${LDTEMPFOLDER}/ld_state_counter"; fi
						#Counter Establish
						if ! [ -f "/tmp/${LDTEMPFOLDER}/ld_state_counter/${ACTIPFILENAME}#" ]; then
							STAT_COUNT=0 #When zero,
						else
							STAT_COUNT="$(tail +1 "/tmp/${LDTEMPFOLDER}/ld_state_counter/${ACTIPFILENAME}#")" #Have Sentinel reference this file before banning
						fi
						ASR_COUNTER_INCREMENT_LIMIT=1 #$ACTIVE_BYTE_LIMIT
						#Get Strike count
						ASR_GET_LINE="$(tail +1 "/tmp/$RANDOMGET"|grep -E "(#|m)(${ip})\b")"
						ASR_STRIKE_MARK_COUNT="$(echo "$ASR_GET_LINE"|grep -Eo "(${STRIKE_MARK_SYMB}{1,})$"|wc -c)"
						if [ $ASR_STRIKE_MARK_COUNT -le 0 ]; then ASR_STRIKE_MARK_COUNT=0; else ASR_STRIKE_MARK_COUNT=$(( ASR_STRIKE_MARK_COUNT - 1 )); fi
						#Write increment to counter. Significant data transfer happening. Stall Sentinel banning
						STAT_COUNT_ADD_1=$(( STAT_COUNT + 1 ))
						if [ $ASR_STRIKE_MARK_COUNT -gt 0 ]; then
							echo -n "$STAT_COUNT_ADD_1" > "/tmp/${LDTEMPFOLDER}/ld_state_counter/${ACTIPFILENAME}#"
						fi
						STAT_COUNT_LIMIT=120 #200 #Value when Sentinel will automatically reset strikes against peer.
						#Reset Sentinel Strikes
						if [ $STAT_COUNT -ge $STAT_COUNT_LIMIT ] && ! { [ "$SENTBAN" = 1 ] && [ $ASR_STRIKE_MARK_COUNT -ge $STRIKECOUNT_LIMIT ];}; then
							ASR_GET_LINE_CLEAR_STRIKE="$(echo -n "$ASR_GET_LINE"|grep -Eo "^.*#"|sed -E "s/(.\[[0-9]{1}\;[0-9]{2}m){1,}(${ip}\b)/\2/g")"
							AUTOCLEANDSENTNUMGET="$(iptables --line-number -nL LDSENTSTRIKE|grep -E "\b${ip}\b"|grep -Eo "^(\s?){1,}[0-9]{1,}"|sed -E "s/\s//g"|sort -nr)"
							if { echo "$ASR_GET_LINE"|grep -Eoq "${STRIKE_MARK_SYMB}"; }; then #Only act if strike marks are found
								for line in $AUTOCLEANDSENTNUMGET; do
									iptables -D LDSENTSTRIKE $line
								done
								sed -i -E "s/(^.*(#|m)${ip}\b.*)/${ASR_GET_LINE_CLEAR_STRIKE}/g" "/tmp/$RANDOMGET"
									echo -n "0" > "/tmp/${LDTEMPFOLDER}/ld_state_counter/${ACTIPFILENAME}#" #Reset counter to zero
							else
								echo -n "0" > "/tmp/${LDTEMPFOLDER}/ld_state_counter/${ACTIPFILENAME}#" #Reset counter to zero
							fi
						fi
					fi
				fi
				} &
			done
		} 2> /dev/null
		wait $!
		if [ "$WRITE_NULL" = 1 ]; then
			write_null_to_log
			WRITE_NULL=0
			sleep 1
		fi
	}
	done 2> /dev/null &
}
#( active_peer_id 2> /dev/null )
active_peer_id 2> /dev/null &
##### ACTIVE PEER INDICATOR #####
#==========================================================================================================
#42Kmi LagDrop Monitor
spinnertime=20000
SYMB='\ | / -'
spinner(){
	while "$@" &> /dev/null; do
		for char in $SYMB; do
			echo -e -n "${CLEARLINE}${RED}$char \r${NC}" ;usleep $spinnertime
			echo -e -n "${CLEARLINE}${YELLOW}$char \r${NC}"; usleep $spinnertime
			echo -e -n "${CLEARLINE}${GREEN}$char \r${NC}"; usleep $spinnertime
			echo -e -n "${CLEARLINE}${BLUE}$char \r${NC}"; usleep $spinnertime
		done
		wait $!
	done
}
echo -e "$REFRESH"
{
	##### Log Message #####
	if [ $POPULATE = 1 ]; then
		LOG_MESSAGE="${GREEN}Populating caches until LagDrop is restarted without -p flag.${NC}"
	else
		LOG_MESSAGE="Waiting for peers..."
	fi
	##### Log Message #####
	##### BL/WL/TW? #####
	if [ -f "$DIR"/42Kmi/blacklist.txt ]; then BL="$(echo -e " BL")"; fi
	if [ -f "$DIR"/42Kmi/whitelist.txt ]; then WL="$(echo -e " ${WHITE}WL${NC}")"; fi
	if [ -f "$DIR"/42Kmi/tweak.txt ]; then TW="$(echo -e " ${LIGHTBLUE}TW${NC}")"; fi
	if [ -f "$DIR"/42Kmi/bancountry.txt ]; then BC="$(echo -e " ${LIGHTRED} BC${NC}")"; fi
	if [ $SMARTMODE = 1 ]; then SMARTON="$(echo " | SMART MODE")"; SMARTCOL="$(printf "\t")S. PING$(printf "\t")S. TR"; fi
	if [ $SHOWLOCATION = 1 ]; then LOCATION="$(echo " | LOCATE${BC}")"; LOCATECOL="$(printf "\t")LOCATION"; fi
	display(){
		##### LogCounts #####
		if [ -f "/tmp/$RANDOMGET" ]; then
			TOTALCOUNT=$(grep -Evi "^[a-z]]" "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed -E "/^(\s*)?$/d"|wc -l)
		fi
		if [ ! -f "/tmp/$RANDOMGET" ]; then
			BLOCKCOUNT="0"
			ACCEPTCOUNT="0"
		else
			BLOCKCOUNT=$(grep -Evi "^[a-z]]" "/tmp/$RANDOMGET"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|sed -E "/^(\s*)?$/d"|grep -Foc "${RESPONSE3}")
			ACCEPTCOUNT=$(( TOTALCOUNT - BLOCKCOUNT ))
			if [ $ACCEPTCOUNT -lt 0 ]; then ACCEPTCOUNT="0"; fi #correction
		fi
		##### LogCounts #####
		if [ $SENTON_SIG = 1 ]; then SENTON="$(echo -e " | ${BLUE}[${NC}${MAGENTA}S${SENT_APPEND}${VV_APPEND}${NC}${BLUE}]${NC}")"; fi
		##### BL/WL/TW? #####
		if [ -f "/tmp/$RANDOMGET" ] && grep -Eo "^(\s*)?$" "/tmp/$RANDOMGET"; then sed -i -E "/^(\s*)?$/d" "/tmp/$RANDOMGET"; fi
		echo -en "$REFRESH"
		echo -en "$CLEARSCROLLBACK"
		echo -e " ${CYAN}42Kmi LagDrop${NC} | ${LOADEDFILTER}${BL}${WL}${TW} | Allowed: ${MAGENTA}$ACCEPTCOUNT${NC} Blocked: ${MAGENTA}$BLOCKCOUNT${NC}${SMARTON}${LOCATION}${SENTON}\n"
		printf "%0s\t" "" TIME PEER "" PING TR RESULT"${SMARTCOL}""${LOCATECOL}"; wait $!
		echo -en "\n"
		if [ -f "/tmp/$RANDOMGET" ] && [ -s "/tmp/$RANDOMGET" ]; then
			LOG="$(tail +1 "/tmp/$RANDOMGET"|sed -E "/^(\s*)?$/d"|sed -E "/^(\s*)?[a-zA-Z]$/d")"
			{
				for line in $LOG; do
					(
						#Count strikes as numbers
						if { echo "$line" | grep -Eoq "(${STRIKE_MARK_SYMB}{1,}$)"; }; then
							STRIKE_MARK_COUNT="$(echo -n "$line"|grep -Eo "(${STRIKE_MARK_SYMB}{1,})$"|wc -c)"
							STRIKE_MARK_COUNT=$(( STRIKE_MARK_COUNT - 1 ))
							#corrections
							STRIKE_MARK_COUNT="$(echo -en "${BG_RED}${WHITE}${STRIKE_MARK_COUNT}${NC}")"
							sed -E "s/(${STRIKE_MARK_SYMB}{1,})$/${BG_RED}${STRIKE_MARK_COUNT}${NC}/g"
						fi
						#Active Peer Symbol Substitution
						ACT_PEER="$(echo "$line"|sed -E "s/.\[[0-9]{1}(\;[0-9]{2})?m//g"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
						ACT_FILE_GET="$(panama $ACT_PEER)#"
						if ! { echo $line|grep -q "${RESPONSE3}"; }; then
							#Is not a block
							if [ -f "/tmp/${LDTEMPFOLDER}/ld_act_state/${ACT_FILE_GET}" ]; then
								ACT_SUB="$(tail +1 "/tmp/${LDTEMPFOLDER}/ld_act_state/${ACT_FILE_GET}")"
							else
								ACT_SUB="${PENDING}"
							fi
						else
							#Is a block
							ACT_SUB="${NOT_CONNECT_MARK}"
						fi
						{ echo -en "${line}"|sed "s/^${ACT_PLACEHOLD}/${ACT_SUB}/"|sed "s/%/ /g"|sed -E "s/#(${STRIKE_MARK_SYMB}{1,})$/ ${STRIKE_MARK_COUNT}/g"|sed -E "s/(#){1,}/#/g"|sed "s/#/\t/g"|sed -E "/^\s*$/d"|sed '/txt/d'|sort -n|sed -E "s/\"([0-9]{1,})\"/$(echo -en ${BLUE})/g"|sed -E "s/(([0-9]{4,})(\-([0-9]{1,2})){2}.([0-9]{1,2}\:?){3})/\1$(echo -en ${NC})/g"|sed -E 's/\.[0-9]{1,3}\.[0-9]{1,3}\./.xx.xx./g'|sed -E "s/([0-9])ms/\1/g"|sed -E "s/(\t){1,}/\t/g"; }
					)
				done #&
			}|grep -nE ".*"|sed -E "s/^([0-9]{1,}):/\1.$(echo -en "${HIDE}") $(echo -en "${NC}")/g"|sed -E "s/[0-9]{4,}(-[0-9]{2}){2}\s//g"|sed -E "s/\, \, /, /g"|sed -E "s/\, 0(null)?0\,/,/g"|sed -E "s/^([1-9]\.)/ &/g"|sed -E "s/${STRIKE_MARK_SYMB}//g" &
		else
			if [ ! -f "/tmp/$RANDOMGET" ] || [ ! -s "/tmp/$RANDOMGET" ] || [ $POPULATE = 1 ]; then
				echo -e "$LOG_MESSAGE"
			fi
		fi
		wait $!
	}
	monitor(){
		##### New Monitor Display #####
		display
			wait $!
		( spinner & fg )
		if [ $LOG_LINE_COUNTL -gt 10 ]; then sleep $(( $LOG_LINE_COUNTL / 10 )); fi
		while "$@" &> /dev/null; do
			wait $!
			{
				ALLOWED_PEERS_LIST="$(tail +1 "/tmp/$RANDOMGET"|grep -Eo "\b(([0-9]{1,3}\.){3})([0-9]{1,3})\b")"
				LOG_LINE_COUNTA="$(grep -Evic "^.*$" "/tmp/$RANDOMGET")"
				LOG_LINE_COUNTA="$(( LOG_LINE_COUNTA - 1 ))"
				#sentinel_bans &
				cleansentinel &
			if [ ! -f "/tmp/$RANDOMGET" ]; then :
				else
					ATIME=$(date +%s -r "/tmp/$RANDOMGET")
					ASIZE=$(tail +1 "/tmp/$RANDOMGET"|wc -c)
					if [ "$ATIME" != "$LTIME" ]; then
						if [ "$ASIZE" != "$LSIZE" ]; then
							echo -e "$CLEARSCROLLBACK"|display
							LTIME=$ATIME && LSIZE=$ASIZE
						fi
					else
						if [ -f "/tmp/$RANDOMGET" ] && [ -s "/tmp/$RANDOMGET" ]; then
							if [ "$LOG_LINE_COUNTA" -gt "$LOG_LINE_COUNTL" ]; then
								echo -e "$CLEARSCROLLBACK"|display
								LTIME=$ATIME && LSIZE=$ASIZE
							fi
						fi
					fi
				fi
				LOG_LINE_COUNTL=$LOG_LINE_COUNTA
				#wait $!
			}
		done
		##### New Monitor Display #####
	}
	( monitor 2> /dev/null )
}
fi 2> /dev/null
##### Ban SLOW Peers #####
##### 42Kmi International Competitive Gaming #####
##### 42Kmi.com #####
##### LagDrop.com #####
} 2> /dev/null
xngjQX43AFTPUjROJ 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 +dkTHy0pSMcbocbcYYaaxqKyg7hq0F
