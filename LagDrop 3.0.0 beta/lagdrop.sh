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
