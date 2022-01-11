# This is a fork of https://github.com/npocmak/getBL

I removed URLs which are no longer updated and correctd some outdated URLs.

## getBlacklist.sh

This script download list of IP addresses, URL and domains, which are suspicious or maicious.
List of sources:

1. **Feodo IP Blacklist**
* https://feodotracker.abuse.ch/downloads/ipblocklist.txt
2. **Emerging Threats - Spamhaus DROP Nets**
* http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
3. **Emerging Threats - Known hostile or compromised hosts**
* http://rules.emergingthreats.net/blockrules/compromised-ips.txt
4. **AlienVault - IP Reputation Database**
* https://reputation.alienvault.com/reputation.snort.gz
5. **SSLBL - SSL Blacklist**
* https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
6. **Talos Reputation Center**
* https://www.talosintelligence.com/documents/ip-blacklist
7. **Talos Reputation Center**
* https://www.talosintelligence.com/documents/ip-blacklist
8. **Blocklist.de - All attacked IP addresses**
* https://lists.blocklist.de/lists/all.txt
9. **Blocklist.de - Attacks on the service SSH**
* https://lists.blocklist.de/lists/ssh.txt
10. **Blocklist.de - Attacks on the service Mail, Postfix**
* https://lists.blocklist.de/lists/mail.txt
11. **Blocklist.de - Attacks on the service Apache, Apache-DDOS, RFI-Attacks**
* https://lists.blocklist.de/lists/apache.txt
12. **Blocklist.de - Attacks on the Service imap, sasl, pop3**
* https://lists.blocklist.de/lists/imap.txt
13. **Blocklist.de - Attacks on the Service FTP**
* https://lists.blocklist.de/lists/ftp.txt
14. **Blocklist.de - All IP addresses that tried to login in a SIP-, VOIP- or Asterisk-Server**
* https://lists.blocklist.de/lists/sip.txt
15. **Blocklist.de - Attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots**
https://lists.blocklist.de/lists/bots.txt
16. **Blocklist.de - All IPs which are older then 2 month and have more then 5.000 attacks**
* https://lists.blocklist.de/lists/strongips.txt
17. **All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Loginss**
* https://lists.blocklist.de/lists/bruteforcelogin.txt
18. **BotScout FireHOL IP List**
* http://botscout.com/last_caught_cache.txt
19. **Brute Force Blocker IP List**
* http://danger.rulez.sk/projects/bruteforceblocker/blist.php
20. **CI Army Bad IPs**
* http://www.ciarmy.com/list/ci-badguys.txt
