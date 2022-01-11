# This is a fork of https://github.com/npocmak/getBL

I removed URLs which are no longer updated.

## getBlacklist.sh

This script download list of IP addresses, URL and domains, which are suspicious or maicious.
List of sources:

1. **Feodo IP Blacklist**
* https://feodotracker.abuse.ch/blocklist/?download=ipblocklist
2. **Emerging Threats - Spamhaus DROP Nets**
* http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
3. **Emerging Threats - Known hostile or compromised hosts**
* http://rules.emergingthreats.net/blockrules/compromised-ips.txt
4. **Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed**
* http://www.binarydefense.com/banlist.txt
5. **AlienVault - IP Reputation Database**
* https://reputation.alienvault.com/reputation.snort.gz
6. **SSLBL - SSL Blacklist**
* https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
7. **BotScout FireHOL IP List**
* http://botscout.com/last_caught_cache.txt
8. **Brute Force Blocker IP List**
* http://danger.rulez.sk/projects/bruteforceblocker/blist.php
9. **CI Army Bad IPs**
* http://www.ciarmy.com/list/ci-badguys.txt
10. **Talos Reputation Center**
* https://www.talosintelligence.com/documents/ip-blacklist
11. **Talos Reputation Center**
* https://www.talosintelligence.com/documents/ip-blacklist
12. **Blocklist.de - All attacked IP addresses**
* https://lists.blocklist.de/lists/all.txt
13. **Blocklist.de - Attacks on the service SSH**
* https://lists.blocklist.de/lists/ssh.txt
14. **Blocklist.de - Attacks on the service Mail, Postfix**
* https://lists.blocklist.de/lists/mail.txt
15. **Blocklist.de - Attacks on the service Apache, Apache-DDOS, RFI-Attacks**
* https://lists.blocklist.de/lists/apache.txt
16. **Blocklist.de - Attacks on the Service imap, sasl, pop3**
* https://lists.blocklist.de/lists/imap.txt
17. **Blocklist.de - Attacks on the Service FTP**
* https://lists.blocklist.de/lists/ftp.txt
18. **Blocklist.de - All IP addresses that tried to login in a SIP-, VOIP- or Asterisk-Server**
* https://lists.blocklist.de/lists/sip.txt
19. **Blocklist.de - Attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots**
https://lists.blocklist.de/lists/bots.txt
20. **Blocklist.de - All IPs which are older then 2 month and have more then 5.000 attacks**
* https://lists.blocklist.de/lists/strongips.txt
21. **All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Loginss**
* https://lists.blocklist.de/lists/bruteforcelogin.txt
