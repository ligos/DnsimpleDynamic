del /q DnsimpleDynamic.zip
zip.exe -9j DnsimpleDynamic.zip bin\Release\*.* 
zip.exe -u DnsimpleDynamic.zip LICENSE.txt 
zip.exe DnsimpleDynamic.zip -d DnsimpleDynamic.vshost.exe* 
zip.exe DnsimpleDynamic.zip -d *.xml
pause