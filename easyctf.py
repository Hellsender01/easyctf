#!/usr/bin/env python3

import webbrowser
import sys
import os

def logo():
    os.system("clear")
    print("""

U _____ u    _      ____      __   __       ____   _____    _____  
\| ___"|/U  /"\  u / __"| u   \ \ / /    U /"___| |_ " _|  |" ___| 
 |  _|"   \/ _ \/ <\___ \/     \ V /     \| | u     | |   U| |_  u 
 | |___   / ___ \  u___) |    U_|"|_u     | |/__   /| |\  \|  _|/  
 |_____| /_/   \_\ |____/>>     |_|        \____| u |_|U   |_|     
 <<   >>  \\    >>  )(  (__).-,//|(_      _// \\  _// \\_  )(\\,-  
(__) (__)(__)  (__)(__)      \_) (__)    (__)(__)(__) (__)(__)(_/  

                                            BY - HARSHIT JOSHI       
        """)

def user_input():
    challenges = ["Exit","Cryptography","Steganography","Forensics(Also Traffic Analysis)","OSINT","Reverse Engineering","SQL","Programming","Pwn","Web"]

    print("\n\n")
    for chall in range (len(challenges)):
        print(str(chall)+".",challenges[chall])

    challenge_type = int(input("\nEnter Challenge Type (Num 0 - "+str(len(challenges)-1)+"): "))

    if challenge_type > len(challenges)-1:
        sys.exit("\nSorry You Choose Invalid Option.\n")
    
    return challenge_type  

class EasyCTF:
    
    def __init__(self):
        self.encryption = {"CyberChef[RECOM]":"https://gchq.github.io/CyberChef/","Decode.fr":"https://www.dcode.fr/en","Cryptii":"https://cryptii.com/","Encode-Decode":["https://encode-decode.com/encryption-functions/","https://encode-decode.com/encoding-functions/"],"CryptiiV2":"https://v2.cryptii.com/text/select","Online Domain Tools":["http://aes.online-domain-tools.com/","http://encoders-decoders.online-domain-tools.com/"],"MD5Decrypt":"https://md5decrypt.net/en","Cryptool":"https://www.cryptool.org/en/cto-ciphers/","Kifanga":"https://kifanga.com/pages/details/list-of-ciphers-and-codes","8gwifi":"https://8gwifi.org/","Google Translate":"https://translate.google.co.in/"}
        self.hashing = {"MD5Hashing[RECOM]":"https://md5hashing.net/","CrackStation":"https://crackstation.net/","Decode.fr":"https://www.dcode.fr/en","Tunnelsup":"https://www.tunnelsup.com/hash-analyzer/","HashToolkit":"https://hashtoolkit.com/","my-addr":"http://md5.my-addr.com/","CMD5":"https://www.cmd5.org/","password-decrypt":"http://password-decrypt.com/","MD5Decrypt":"https://md5decrypt.net/en","Kifanga":"https://kifanga.com/pages/details/list-of-ciphers-and-codes","Main Menu":"Back To Main Menu"}
        self.general_steganography = {"StegOnline[RECOM]":"https://stegonline.georgeom.net/upload","CyberChef":"https://gchq.github.io/CyberChef/","aperisolve":"https://aperisolve.fr/","StyleSuxx":"http://stylesuxx.github.io/steganography/","Regex":"http://exif.regex.info/exif.cgi","Stegano":"https://futureboy.us/stegano/decinput.html","Stego Toolkit":"https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md#tools","Compress Or Die":"https://compress-or-die.com/analyze","Extract text":"https://brandfolder.com/workbench/extract-text-from-image","BarQR Code Reader":"https://online-barcode-reader.inliteresearch.com/"}
        self.multimedia_steganography = {"Regex":"http://exif.regex.info/exif.cgi","Stego Toolkit":"https://github.com/DominicBreuker/stego-toolkit/blob/master/README.md#tools","Compress Or Die":"https://compress-or-die.com/analyze","Decode.fr":"https://www.dcode.fr/spectral-analysis","Academo":"https://academo.org/demos/spectrum-analyzer/","Main Menu":"Back To Main Menu"}
        self.forensics = {"CyberChef":"https://gchq.github.io/CyberChef/","Iris":"https://iris-h.services/pages/submit","Joesandbox":"https://www.joesandbox.com/","Opswat":"https://metadefender.opswat.com/?lang=en","FotoForensics":"http://fotoforensics.com/","HexEdit":"https://hexed.it/","Image Forensics":"http://www.imageforensic.org/","Photo-Forensics":"https://29a.ch/photo-forensics/","File Magic Numbers":"https://en.wikipedia.org/wiki/List_of_file_signatures"}
        self.traffic_analysis = {"Apackets":"https://apackets.com/[RECOM]","PacketTotal":"https://packettotal.com/","Honeynet pcap":"https://pcap.honeynet.org.my/v1/","Packet HEX Decoder":"http://packetor.com/","Main Menu":"Back To Main Menu"}
        self.general_osint = {"osint.link[REC]":"https://osint.link/","Google":"https://google.co.in","Bing":"https://bing.com","WayBack Machine":"https://archive.org/web/","Shodan":"https://www.shodan.io/","Spyse":"https://spyse.com/","Mamont FTP search":"https://www.mmnt.ru/int/","Search FTPs":"https://www.searchftps.net/","Fagan File Finder":"https://www.faganfinder.com/filetype/","Greyhat File Search":"https://buckets.grayhatwarfare.com/","Google Image Search":"https://images.google.com/","Picture Search":"https://pictures.reuters.com/C.aspx?VP3=CMS3&VF=RTRRTT_1_VForm","Stock Image Finder":"https://imagefinder.co/","IStock Photos":"https://www.istockphoto.com/","YouTube":"https://www.youtube.com/","Google Video Search":"https://www.google.com/videohp","BlogSpot Search":"https://www.searchblogspot.com/","Blog SearchEngine": "http://www.blogsearchengine.org/","IOT Search":"https://www.thingful.net/","Censys":"https://censys.io/","Exploit DB":"https://www.exploit-db.com/","Sploitus exploit search":"https://sploitus.com/","CVE Search":"https://www.cvedetails.com/","Google News Search":"https://news.google.com/","World News Search":"https://www.allyoucanread.com/","Wifi Lookup":"https://wigle.net/"}
        self.reverse_image_lookup = {"Google Image Lookup[RECOM]":"https://www.google.com/imghp","Karmadecay":"http://karmadecay.com/","Tinyeye":"https://tineye.com/","Image Search":"https://www.reverse-image-search.com/","Image Identify":"https://www.imageidentify.com/","Yandex Image":"https://yandex.com/images/","Flickr Image Search":"https://www.flickr.com/photos/tags/images/","Main Menu":"Back To Main Menu"}
        self.reverse_enginnering = {"Oline Disassembler":"https://onlinedisassembler.com/odaweb/","APK Decompiler":"https://www.apkdecompilers.com/","Java Decompiler":"http://www.javadecompilers.com/","Multi Lang Decompiler":"http://www.decompiler.com/","Hex Editor":"https://hexed.it/","Assembler Disassembler":"https://defuse.ca/online-x86-assembler.htm","Binary Analysis":"https://www.boxentriq.com/code-breaking/binary-analysis","Visual binary-analysis":"https://binvis.io/","Main Menu":"Back To Main Menu"}
        self.linux = {"Payload All Things[RECO]":"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Linux - Privilege Escalation.md","TTY Shell":"https://netsec.ws/?p=337","Gtofobins":"https://gtfobins.github.io/","Exploit DB":"https://www.exploit-db.com/","Pentester Monkey":"https://jaytaylor.com/notes/node/1520886669000.html","Kernel Exploits":"https://github.com/SecWiki/linux-kernel-exploits","Reverse Shell":"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell Cheatsheet.md","PrivEsc Cheet Sheet":"https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/","Linux Cheatsheet":"https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Cheat sheets reference%20pages%20Checklists%20-/Linux/cheat sheet%20Basic Linux%20Privilege Escalation.txt","LinPeas":"https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS","LinEnum":"https://github.com/rebootuser/LinEnum","Linux Exploit Suggestor":"https://github.com/mzet-/linux-exploit-suggester"}
        self.windows = {"Payload All Things[RECO]":"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and%20Resources/Windows%20-%20Privilege Escalation.md","OSCP windows privesc":"https://www.hackingdream.net/2020/03/windows-privilege-escalation-cheatsheet-for-oscp.html","Windows Privesc":"https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html","Kernel Exploits":"https://github.com/SecWiki/windows-kernel-exploits","Exploit DB":"https://www.exploit-db.com/","Windows Privesc Guide":"https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/","WinPeas":"https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS","Win Exploit Suggestor":"https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git","WindowsEnum":"https://github.com/absolomb/WindowsEnum","Mimikatz":"https://github.com/gentilkiwi/mimikatz","Main Menu":"Back To Main Menu"}
        self.web = {"Security Headers":"https://securityheaders.com/","Web Vuln Scanner":"https://pentest-tools.com/website-vulnerability-scanning/website-scanner#","DNS Dumbster":"https://dnsdumpster.com/","Built With":"https://builtwith.com/","Wappalyzer Lookup":"https://www.wappalyzer.com/lookup/","Cookie Editor":"https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/","HackBar":"https://addons.mozilla.org/en-US/firefox/addon/hackbartool/","Website Scanner":"https://webhint.io/scanner/","Directory Buster":"https://addons.mozilla.org/en-US/firefox/addon/foxdirb/","Json Tokens Decoder":"https://jwt.io/","JS-Fuck Decoder":"https://enkhee-osiris.github.io/Decoder-JSFuck/","Foxy Proxy":"https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/","Live HTTP Headers":"https://addons.mozilla.org/en-US/firefox/addon/http-header-live/","Tamper Request Response":"https://addons.mozilla.org/en-US/firefox/addon/tamper-data-for-ff-quantum/","Web-Scraper":"https://addons.mozilla.org/en-US/firefox/addon/web-scraper/","Main Menu":"Back To Main Menu"}
        self.programming = {"All Lang IDE":"https://tio.run/#[RECOM]","Online IDE":"https://www.codechef.com/ide","Online C Compiler":"https://www.programiz.com/c-programming/online-compiler/","Beautify Converter":"https://www.beautifyconverter.com/","Bash Online":"https://www.tutorialspoint.com/execute_bash_online.php","Web Devlopment IDE":"https://codesandbox.io/s/","JSON Viewer":"https://codebeautify.org/jsonviewer","Online GDB Debugger":"https://www.onlinegdb.com/","Online Text Editor":"https://www.prepostseo.com/tool/online-text-editor","Main Menu":"Back To Main Menu"}
        self.sql = {"Sql All Work[RECOM]":"https://sqliteonline.com/","Online SQL IDE":"https://www.tutorialspoint.com/execute_sql_online.php","MySql Online":"https://paiza.io/en/projects/new?language=mysql","MongoDB":"https://www.mplay.run/mongodb-online-terminal","DB File Opener":"https://extendsclass.com/sqlite-browser.html#","SQL Script Opener":"https://sqliteonline.com/","MySql Compiler":"https://rextester.com/l/mysql_online_compiler","Main Menu":"Back To Main Menu"}
        self.count = 1

    def browser(self,openit):
        webbrowser.open(openit)

    def valid_option(self):
        website = int(input("\n\nEnter Website To Open(Number) : "))
        while website < 1 or website > (self.count-1):
            print("\nOption Not In Menu\n\nType {} For Main Menu".format((self.count-1)))
            website = int(input("\n\nEnter Website To Open(Number) : "))
        return website

    def exit(self):
        sys.exit("\nExiting As Per Your Orders.\n")

    def crypto(self):
        print("\n[Encoding And Encryption]\n")
        print("SNO.\r\tName\r\t\t\t\tURL")
        for key in self.encryption:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.encryption[key]))
            self.count += 1
        print("\n\n[Hashing]\n")
        print("SNO.\r\tName\r\t\t\t\tURL")
        for key in self.hashing:
            print(str(self.count)+".      \r\t"+str(key)+"      \r\t\t\t\t"+str(self.hashing[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            value1 = list((self.encryption).values())
            value2 = list((self.hashing).values())
            values=list(value1+value2)
            webpage = (values[website-1])
            webbrowser.open(webpage)
    
    def stego(self):
        print("\n[General Steganography(For All Types Of Files)]\n")
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.general_steganography:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.general_steganography[key]))
            self.count += 1
        print("\n\n[MultiMedia Steganography(Mainly For Audio And Video Files)]\n")
        print("SNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.multimedia_steganography:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.multimedia_steganography[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            value1 = list((self.general_steganography).values())
            value2 = list((self.multimedia_steganography).values())
            values=list(value1+value2)
            webpage = (values[website-1])
            webbrowser.open(webpage)
    

    def foren(self):
        print("\n[Digital Forensics]\n")
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.forensics:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.forensics[key]))
            self.count += 1
        print("\n\n[Network Traffic Analysis]\n")
        print("SNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.traffic_analysis:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.traffic_analysis[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            value1 = list((self.forensics).values())
            value2 = list((self.traffic_analysis).values())
            values=list(value1+value2)
            webpage = (values[website-1])
            webbrowser.open(webpage)

    def osin(self):
        print("\n[Genral OSINT]\n")
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.general_osint:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.general_osint[key]))
            self.count += 1
        print("\n\n[Reverse Image Lookup]\n")
        print("SNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.reverse_image_lookup:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.reverse_image_lookup[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            value1 = list((self.general_osint).values())
            value2 = list((self.reverse_image_lookup).values())
            values=list(value1+value2)
            webpage = (values[website-1])
            webbrowser.open(webpage)
    
    def reverse(self):
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.reverse_enginnering:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.reverse_enginnering[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            values=list((self.reverse_enginnering).values())
            webpage = (values[website-1])
            webbrowser.open(webpage)

    def prog(self):
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.programming:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.programming[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            values=list((self.programming).values())
            webpage = (values[website-1])
            webbrowser.open(webpage)

    def pwn(self):
        print("\n[Linux Pwning]\n")
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.linux:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.linux[key]))
            self.count += 1
        print("\n\n[Windows Pwning]\n")
        print("SNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.windows:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.windows[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            value1 = list((self.linux).values())
            value2 = list((self.windows).values())
            values=list(value1+value2)
            webpage = (values[website-1])
            webbrowser.open(webpage)

    def web_scan(self):
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.web:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.web[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            values=list((self.web).values())
            webpage = (values[website-1])
            webbrowser.open(webpage)

    def sqli(self):
        print("\nSNO.\r\tName\r\t\t\t\tURL\n")
        for key in self.sql:
            print(str(self.count)+".      \r\t"+str(key)+"       \r\t\t\t\t"+str(self.sql[key]))
            self.count += 1
        website = self.valid_option()
        if website == (self.count-1):
            pass
        else:
            values=list((self.sql).values())
            webpage = (values[website-1])
            webbrowser.open(webpage)

if len(sys.argv) == 2:
    if sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("""Easy CTF Is A Interactive Python Tool To Help CTF Players
To Sovle Thier Challenges Online With All Websites In one Tool
Organised According To Thier Types.            
\nTo Use Easy CTF Type In Terminal - easyctf """)
        sys.exit()
    else:
        sys.exit("\nNo Arguments Are Required")

while True:
    if __name__ == "__main__":

        logo()
        
        challenge = user_input()

        easy_ctf = EasyCTF()
            
        if challenge == 0:
            easy_ctf.exit()

        elif challenge == 1:
            easy_ctf.crypto()

        elif challenge == 2:
            easy_ctf.stego()

        elif challenge == 3:
            easy_ctf.foren()

        elif challenge == 4:
            easy_ctf.osin()

        elif challenge == 5:
            easy_ctf.reverse()

        elif challenge == 6:
            easy_ctf.sqli()

        elif challenge == 7:
            easy_ctf.prog()
        
        elif challenge == 8:
            easy_ctf.pwn()

        elif challenge == 9:
            easy_ctf.web_scan()
