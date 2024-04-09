TI AD :

 - set ip & dns
 - dump fqdn de l'ad
 - sous domaine enum (ex gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt)
 - dump les spn et les parser pour extraire les dn
 	ldapsearch -x -H ldap://x.net:389 -b "DC=x,DC=net" "(ServicePrincipalName=*)" "sAMAccountName" "ServicePrincipalName" -E pr=1000/noprompt > x_SPN
 	cat x_SPN | grep "servicePrincipalName:" | cut -d "/" -f 2 | sort | uniq | grep "\." > x_spn_fqdn
 - scan nmap services admin
 - scan nmap plus de services
 - scan hosts interfaces pour trouver d'autres sous réseaux (module cme smb IOXIDResolver)
 - aquatone (voir si y a une option connectée avec kerberos)
 	 - à test pour découverte  ? echo hackerone.com | naabu -silent | httpx -silent
 - nuclei sur les http/https
 - share acessibles anonymement + enumeration
 	- si accès drop des .url / .lnk pour coerce (https://github.com/mdsecactivebreach/Farmer, )
 		- module cme slinky
 		- https://github.com/Greenwolf/ntlm_theft
 	- CVE-2020-0729
 - ldap :
 	- accès anonyme ? sinon faire le reste une fois un compte compromis :
	 	- nom description
	 	- password not req => mdp possiblement vide
	 	- dump users (tester ldeep) => spray cme / kerbrute
	 	- asreproast => crack
	 		CVE-2022-33679 => on peut utiliser la réponse comme TGT et donc impersonate le user (nécessite RC4 support par le kdc)
	 		- creuser https://googleprojectzero.blogspot.com/2022/10/rc4-is-still-considered-harmful.html
	 	- timeroast (https://github.com/SecuraBV/Timeroast) : à faire que si on peut pas kerberoast les comptes machines et qu'on souhaite trouver des vieux mdp pour des comptes machines pas mis à jour auto. Le type de hash reçu est cassable uniquemnet par hashcat beta (mode 31300)
	 	- gpp passwords (ms14-025) (gpp_autologin et gpp_password)
	 	- get laps passwords (module cme) (ms-Mcs-AdmPwd (le principal), ms-LAPS-Password, msLAPS-EncryptedPassword, msLAPS-EncryptedDSRMPassword) 
	 	- get unix passwords : chercher si UserPassword, UnixUserPassword, unicodePwd and msSFU30Password peuplés
	 	- get gmsa passwords : msds-ManagedPassword
	 - si pas d'accès anonyme tenter de trouver des users valides avec kerbrute et différents models de samaccountname (ex: jdoe, john.doe, johndoe) et des noms / prénoms communs en rapport avec la langue utilisée puis faire du spray / asrep / pwd not req
 - poisonning / coerce & relay
 	- responder => crack / relay
 	- mitm6 => crack / relay
 	- coerce 
 		- petitpotam / coercer (https://github.com/p0dalirius/Coercer) / printerbug => relay
 		- webdav (https://github.com/med0x2e/NTLMRelay2Self) => rce
 		- https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/living-off-the-land
 		- https://github.com/p0dalirius/windows-coerced-authentication-methods
 	- relay ntlm & kerberos
 		- smb signature non requise
 		- ldap signing not req + ldaps non requis => coerce into --add-computer avec ntlmrelayx pour obtenir un compte. Need une coerce http / ldap depuis un accès non auth
 		- https://en.hackndo.com/assets/uploads/2020/03/ntlm_resume.png
 		- relai smb vers ldap si dropthemic CVE-2019-1040
 		- krbrelayx (depuis mitm6)



 - vuln connues pas auth
 	- vulns sans poc : CVE-2022-37958 (rce) & ms rpc CVE-2022-26809 (rce sur machine vuln)
 	- Windows LSA Spoofing CVE-2022-26925 (pas de PoC ? Privesc non auth vers dc)	
 	- Credentials Roaming, RCE(CVE-2022-30170) (à creuser)
 	- petitpotam CVE-2021-36942 (need adcs, non auth vers dcsync, peut marcher avec un compte => esc1)
 	- printnightmare CVE-2021-1675, CVE-2021-34527  (compromission du dc/workstation/server si print spooler exposé et pas patch, rce into dcsync)
 	- zerologon CVE 2020 1472 (non auth into dcsync)
 	- smbghot (rce) CVE-2020-0796
 	- bluekeep CVE-2019-0708 (pas exploitable stablement à ce jour)
 	- eternal blue CVE-2017-0143 (ms 17 010, need (?) smb v1)
 	- NTLM reflection CVE-2008-4037 (MS08-068 ntlm relai vers la machine coercée) peu de chance que ça arrive mais peut permettre de pown des vieilles machines à distance



 - à chaque fois après compromission d'un compte : 
 	- voir catégorie LDAP si pas d'accès anonyme (une fois)
 	- get laps passwords (module cme) (ms-Mcs-AdmPwd (le principal), ms-LAPS-Password, msLAPS-EncryptedPassword, msLAPS-EncryptedDSRMPassword) 
 	- kerberoast (une fois)
 	- bloodhound (extract une fois, analyse à chaque fois)
 	- pingcastle (une fois)
 	- adpeas (une fois)
 	- tester le comptes sur ports d'admin (share smb/vnc/rdp/ssh/mssql/...)
 		- si accès smb voir partie "share acessibles anonymement"
 		- si accès smb en admin (write sur admin$ ou c$) => rce
 		- si accès mssql voir la partie "post exploit (autre)"
 		- rdp : rdp socket / connection direct / modif dll pour multi co / ...
 		- vnc :
 			- test guest access (auxiliary/scanner/vnc/vnc_none_auth)
 			- test password = "password" (auxiliary/scanner/vnc/vnc_login)
 		- winrm / wmi / ssh : command exec donc essayer de privesc etc
 	- (à tester, peut être faisable sans auth) : enum dns depuis l'ad (une fois), tester les deux tools :
 		- dnstool.py -u 'DOMAINE/user' -p 'pass' record '*' --action query <ip_dc>
 		- adidnsdump -u DOMAIN\\user --print-zones dc.domain.corp (--dns-tcp)
 		à voir : 
 			StandIn.exe --dns --limit 20
			StandIn.exe --dns --filter SQL --limit 10
			StandIn.exe --dns --forest --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
			StandIn.exe --dns --legacy --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
 	- certipy find / adcs exploit (esc1 à 11)
 		certipy find -u x@y.local -p pass -dc-ip xx.xx.xx.xx
 	- exploit acl https://www.thehacker.recipes/ad/movement/dacl
 	- si présent dans managedBy d'un rodc = y a des trucs à faire (à creuser)



 - privesc ad (nécessite un compte) : 
 	- certifried CVE-2022-26923 (permet de s'auth en tant que dc et donc dcsync, need ADCS, need machine quota)
 	- nopac, CVE-2021-42287, cve 2021 42278 (privesc vers DA, requier la création / maitrise d'un compte machine)
 	- Kerberos Bronze Bit Attack CVE-2020-17049 (privesc rbcd / constrained delegation vers da, à creuser / confirmer)
 	- Microsoft Exchange :
 		- Privilege Escalation CVE-2019-0724, CVE-2019-0686 (2019 exchange server, permet de coherce un co du serv exchange vers une machine puis relai ntlm vers le dc (ldap) et donc avoir les droits du serv, souvant admin) module msf exchange_web_server_pushsubscription / https://github.com/dirkjanm/PrivExchange
 		- RCE CVE-2020-0688 (todo trouver un bon repo)
 		- ProxyNotShell / ProxyShell / ProxyLogon (CVE-2022-41040 & CVE-2022-41082 / CVE-2021-34473 & CVE-2021-34523 & CVE-2021-31207 / CVE-2021-26855 & CVE-2021-27065)
 	- Kerberos Checksum Vulnerability CVE-2014-6324 ms14-068 (pour domaine pas patch 2014 => faible taux de réussite), goldenPac
 	- si DES activé (à creuser) https://exploit.ph/des-is-useful.html
 		- CVE-2022-37967 même trucs ? https://github.com/bmcmcm/Get-msDSSupportedEncryptionTypes
 	- si sharepoint local utilisé et pas à jour CVE-2020-0932 ou CVE-2019–0604 (y a aussi CVE-2019-1257 mais demande plus de prérequis) = RCE sur le serv sharepooint depuis un accès authentifié


 - privesc locale :
	- dll highjacking
	- localpotatoe CVE-2023-21746
	- hivenightmare / serioussam CVE-2021-36934
	- printnightmare peut aussi être utilisé pour privesc
	- webdav https://github.com/med0x2e/NTLMRelay2Self
	- sharpwsus
	- KrbRelayUp https://github.com/ShorSec/KrbRelayUp
	- trucs habituels privesckcheck.ps1 / winpease / beRoot / seatbelt / Invoke-Privesc / powerup . . .
	- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md



 - post exploit (ordinateur / serveur) : 
	- dump lsass => creds / hash / ticket kerberos domaine / runasppl bypass (pplkiller/pplmedic)
	- dump lsa => creds / hash domaine 
	- dump sam => hash compte locaux
	- dump dpapi (donpapi / secretsdump )
	- pass the hash si pas de laps
	- chercher creds dans fichier
	- lazagne 
	- sharpcromium
	- extraction de token pour impersonate autres users co (module cme / https://github.com/zblurx/impersonate-rs) / si y a adcs https://github.com/Z4kSec/Masky
	- impersonate rdp session (à creuser)
	- vérifier si un service tourne avec des délégations kerberos
	- lister interface réseaux pour plus d'accès réseau puis ligolo/chisel/reverse port fw avec putty
	- lister les co actives pour voir si il y a certains services contactés (genre bdd) auxquels on n'a pas accès depuis notre réseau



 - post exploit (ad pown)
 	- dcsync
 	- secret dump
 	- donpapi
 	- trust enumeration / exploit



 - post exploit (autre)
 	- mssql : xp_cmdshell
 	- mssql : trust
 	- mssql : relay ntlm vers autre mssql / service
 	- ?



 - à creuser
 	- wsus
 	- sccm
 	- adfs
 	- ad connect (MSOL)
 	- trust / trustroast
 	- ADIDNS et Inveigh https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/
 	- https://statics.teams.cdn.office.net/evergreen-assets/safelinks/1/atp-safelinks.html
 	- Ghost Potato - CVE-2019-1384
 	- https://github.com/cfalta/MicrosoftWontFixList : 
 		- RemotePotato0 https://github.com/antonioCoco/RemotePotato0
 		- SpoolSample https://github.com/leechristensen/SpoolSample   &   https://twitter.com/tifkin_/status/1420076325151272960
 	- https://github.com/GoSecure/pyrdp
 	- Child Domain to Forest Compromise - SID Hijacking
 	- https://github.com/Wack0/CVE-2022-35841
 	- https://github.com/ycdxsb/WindowsPrivilegeEscalation




 - tools à tester / creuser
	- https://github.com/hausec/ADAPE-Script
	- https://github.com/sense-of-security/ADRecon
	- https://github.com/CravateRouge/bloodyAD
	- https://github.com/the-useless-one/pywerview
	- https://github.com/RedTeamPentesting/pretender
	- https://github.com/lkarlslund/Adalanche
	- https://github.com/synacktiv/GPOddity & https://github.com/Hackndo/pyGPOAbuse
	- https://github.com/Hackndo/conpass
	- https://github.com/Hackndo/sprayhound 	
	- https://github.com/Hackndo/Snaffler
	- https://github.com/Hackndo/WebclientServiceScanner
	- https://github.com/Flangvik/SharpCollection
	- https://github.com/Mazars-Tech/AD_Miner
	- https://github.com/synacktiv/ntdissector/
	- https://github.com/qtc-de/rpv-web
	- https://github.com/tastypepperoni/PPLBlade
	- https://github.com/franc-pentest/ldeep
	- https://github.com/p0dalirius/LDAPmonitor
	- https://github.com/foxlox/GIUDA
	- https://github.com/Kevin-Robertson/Inveigh
	- https://github.com/Trackflaw/CVE-2023-23397
	- https://github.com/ly4k/SpoolFool
	- https://github.com/zblurx/certsync
	- https://github.com/garrettfoster13/sccmhunter
	

top 3 des trucs que j'aimerai mieux comprendre dans Windows : DCE/RPC, COM/DCOM, WMI

sources : 
mes observéations / expériences et mon savoir passé 
https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg
https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
