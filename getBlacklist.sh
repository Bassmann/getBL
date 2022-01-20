#!/bin/bash
# ########################################################
#  Name:        getBlacklist.sh
#  Version:     1.2
#  Author:      Mad | Pavol Kluka - 2017/09/09
#  Date:        2020/12/10
#  Platforms:   Linux
# ########################################################

# SCRIPT VARIABLES
DIR_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# PATH VARIABLES
PATH_LIST="$DIR_SCRIPT/lists"
PATH_ARCHIVE="$DIR_SCRIPT/archive"
PATH_DATE="$PATH_ARCHIVE/$( date +"%Y%m%d" )"
PATH_BLACKLISTS="$DIR_SCRIPT/blacklists"

# BIN VARIABLES
BIN_AWK="$( which awk )"
BIN_WGET="$( which wget )"
BIN_MKDIR="$( which mkdir )"
BIN_GZIP="$( which gzip )"

# FILE VARIABLES
FILE_IP_BLACKLIST="ip_blacklist.txt"

# FUNCTIONS
# CHECK IF EXIST WORK FOLDER | 1st PARAMETER = FOLDER FOR CHECK
function funCheckFolder() {
    ARG1="$1"
    if [ -d "$ARG1" ]
    then
            echo "Folder $ARG1 exist."
    else
            echo "Folder $ARG1 doesn't exist. Folder was created."
            $BIN_MKDIR -p $ARG1 > /dev/null
    fi
}

# CURRENT TIMESTAMP
function timestamp() {
    date +"%Y-%m-%d %T"
}

echo "$(timestamp) Start."

funCheckFolder $PATH_LIST
funCheckFolder $PATH_ARCHIVE
funCheckFolder $PATH_DATE
funCheckFolder $PATH_BLACKLISTS

# Reach all free Feeds
echo "$(timestamp) Get Feodo IP Blacklist."
$BIN_WGET -q https://feodotracker.abuse.ch/downloads/ipblocklist.txt -O $PATH_DATE/ip_feodo_blocklist.txt --no-check-certificate
echo "$(timestamp) Processing Feodo IP Blacklist."
$BIN_AWK '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 }' $PATH_DATE/ip_feodo_blocklist.txt >> $PATH_LIST/ip_feodo_blacklist.txt

echo "$(timestamp) Get Emerging Threats - Spamhaus DROP Nets."
$BIN_WGET -q http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -O $PATH_DATE/ip_spamhaus_blocklist.txt --no-check-certificate
echo "$(timestamp) Processing Emerging Threats - Spamhaus DROP Nets."
$BIN_AWK '/#.*?Spamhaus DROP Nets/ { show=1; next } /#.*?/ { show=0 } show' $PATH_DATE/ip_spamhaus_blocklist.txt | \
$BIN_AWK 'NF > 0' | \
while read IP_ADDRESS
do
  echo "$IP_ADDRESS" >> $PATH_LIST/ip_spamhaus_blacklist.txt
done

echo "$(timestamp) Get Emerging Threats - Known hostile or compromised hosts."
$BIN_WGET -q http://rules.emergingthreats.net/blockrules/compromised-ips.txt -O $PATH_DATE/ip_compromised_blocklist.txt --no-check-certificate
echo "$(timestamp) Processing Emerging Threats - Known hostile or compromised hosts."
$BIN_AWK '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 }' $PATH_DATE/ip_compromised_blocklist.txt >> $PATH_LIST/ip_compromised_blacklist.txt

echo "$(timestamp) Get AlienVault - IP Reputation Database."
$BIN_WGET -q https://reputation.alienvault.com/reputation.snort.gz -P $PATH_DATE --no-check-certificate
$BIN_GZIP -f -d $PATH_DATE/reputation.snort.gz
echo "$(timestamp) Processing AlienVault - IP Reputation Databases."
$BIN_AWK -F '#' '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { gsub(" ","",$1); gsub(" ","",$2); print $1 }' $PATH_DATE/reputation.snort >> $PATH_LIST/ip_snort_rep_list.txt

echo "$(timestamp) Get SSLBL - SSL Blacklist."
$BIN_WGET -q https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O $PATH_DATE/ip_ssl_blacklist.csv --no-check-certificate
echo "$(timestamp) Processing SSL Blacklist."
$BIN_AWK -F ',' '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 }' $PATH_DATE/ip_ssl_blacklist.csv >> $PATH_LIST/ip_ssl_blacklist.txt

echo "$(timestamp) Get IP Blacklist from Talos Reputation Center."
$BIN_WGET -q https://www.talosintelligence.com/documents/ip-blacklist -O $PATH_DATE/ip_talos_blacklist.txt --no-check-certificate
echo "$(timestamp) Processing Talos Feeds - IP Blacklist."
$BIN_AWK '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 }' $PATH_DATE/ip_talos_blacklist.txt >> $PATH_LIST/ip_talos_blacklist.txt

echo "$(timestamp) Get IP Blacklist from Blocklist.de - All attacked IP addresses (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/all.txt -O $PATH_DATE/ip_blocklist_all.txt --no-check-certificate
echo "$(timestamp) Processing Blocklist.de (All) - IP Blacklist"
$BIN_AWK '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 }' $PATH_DATE/ip_blocklist_all.txt >> $PATH_LIST/ip_blocklist_all.txt

echo "$(timestamp) Get BotScout FireHOL IP List."
$BIN_WGET -q http://botscout.com/last_caught_cache.txt -O $PATH_DATE/ip_botscout_blacklist.txt --no-check-certificate
echo "$(timestamp) Processing BotScout FireHOL IP List with email addresses of Bots."
$BIN_AWK -F ',' '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $3 }' $PATH_DATE/ip_botscout_blacklist.txt >> $PATH_LIST/ip_botscout_blacklist.txt

echo "$(timestamp) Get Brute Force Blocker IP List."
$BIN_WGET -q http://danger.rulez.sk/projects/bruteforceblocker/blist.php -O $PATH_DATE/ip_bruteforce_blacklist.txt --no-check-certificate
echo "$(timestamp) Processing Brute Force Blocker IP List."
$BIN_AWK '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 }' $PATH_DATE/ip_bruteforce_blacklist.txt >> $PATH_LIST/ip_bruteforce_blacklist.txt

echo "$(timestamp) Get CI Army Bad IPs."
$BIN_WGET -q http://www.ciarmy.com/list/ci-badguys.txt -O $PATH_DATE/ip_badguys_blacklist.txt --no-check-certificate
echo "$(timestamp) Processing CI Army Bad IPs."
$BIN_AWK '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 }' $PATH_DATE/ip_badguys_blacklist.txt >> $PATH_LIST/ip_badguys_blacklist.txt

# Collect all feeds to one csv per type of feeds
echo "$(timestamp) Collecting tables to blacklist folder."
cat $PATH_LIST/*.txt > $PATH_BLACKLISTS/$FILE_IP_BLACKLIST

echo "$(timestamp) End."
