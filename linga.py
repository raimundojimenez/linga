#!/usr/bin/env python2
# coding: utf-8

###############################################################################################################
## [Titulo]: Linga - Linux INformation GAthering
## 			 PFM_6.1. Herramienta para el escaneo de información de la arquitectura en máquinas Linux
## [Autor] : Raimundo Jiménez
##-------------------------------------------------------------------------------------------------------------
## [Detalles]: 
## Este script está pensado para ser ejecutado en un equipo Linux con la idea de enumerar las configuraciones
## básicas del sistema y descubrir el resto de la infraestructura
## Proporciona vectores comunes de escalado de privilegios tales como:
## Ficheros editables universalmente, configuraciones erróneas, contraseñas en texto claro...
##-------------------------------------------------------------------------------------------------------------
## [Modificación, Distribución, y Atribución]:
## Basado inicialmente en parte del código de linuxprivchecker.py de Mike Czumak (T_v3rn1x) -- @SecuritySift
###############################################################################################################

# Debug
def pause():
    programPause = raw_input("Pulsa <ENTER> para continuar...")


# Comprobamos si podemos importar subprocess
try:
    import subprocess as sub
    compatmode = 0 	# Versiones nuevas de Python
except ImportError:
    import os 		# Versiones antiguas de Python necesitan utilizar 'os'
    compatmode = 1

# Comprobamo si tenemos acceso a argparse
try:
	import argparse
	# argmode = 0
except ImportError:
	print('ERROR al tratar de importar argparse')
	# argmode = 1
	

try:
	parser = argparse.ArgumentParser(description='''Linga - Linux INformation GAthering
	PFM_6.1. Herramienta para el escaneo de información de la arquitectura en máquinas Linux''',
		epilog='(c) 2019 Raimundo Jiménez', 
		formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("-b", action='store_true', help='Activa las búsquedas (consume mucho tiempo)',
		default=False, dest='buscar')
	parser.add_argument("-c", action='store_true', help='Imprime el contenido de ficheros extensos (consume mucho espacio)',
		default=False, dest='contenido')
	parser.add_argument("-e", action='store_true', help='Imprime el contenido de resultados extensos (consume mucho espacio)',
		default=False, dest='extenso')
	parser.add_argument("-l", action='store_true', help='Imprime el contenido de directorios (consume mucho espacio)',
		default=False, dest='directorios')
	parser.add_argument("-p", action='store_true', help='Añade pausas en la visualización (interactivo)',
		default=False, dest='pausas')
	parser.add_argument("-d", action='store_true', help='Imprime información de depuración (debug)',
		default=False, dest='debug')
	args = parser.parse_args()
except Exception as e:
	print('ERROR: No se pudieron analizar los argumentos de entrada')

if args.debug:
	print(args)
	pause()

# Formato auxiliar
bigline = "================================================================================================="
smlline = "-------------------------------------------------------------------------------------------------"

print(bigline)
print('Linga - Linux INformation GAthering')
print('')
print('PFM_6.1 - Herramienta para el escaneo de información de la arquitectura de máquinas Linux')
print(bigline)
print('')

# Recorre el diccionario pasado como argumento ejecutando los comandos incluidos en el mismo y almacenando los resultados, devolviendo finalmente el diccionario actualizado
def execCmd(cmdDict):
	for item in cmdDict:
		cmd = cmdDict[item]["cmd"]
		if compatmode == 0: 	# Nuevo python, soporta subprocess
			out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
			results = out.split('\n')
		else: 					# Versión antigua de python, utilizamos os.popen
			echo_stdout = os.popen(cmd, 'r')  
			results = echo_stdout.read().split('\n')
		cmdDict[item]["results"]=results
	return cmdDict

# Imprime los resultados de cada comando ejecutado
def printResults(cmdDict, pausa=False):
	for item in cmdDict:
		msg = cmdDict[item]["msg"]
		results = cmdDict[item]["results"]
		#if len(results)>0:
		if results != ['']:
			print("[+] " + msg)
			for result in results:
			    if result.strip() != "":
					print ("    " + result.strip())
			print('')
			if pausa:
				pause()
	return

# Escribe los resultados a disco en un fichero de log (log_pfm.txt)
# def writeResults(msg, results):
#     f = open("log_pfm.txt", "a")
#     f.write("[+] " + str(len(results)-1) + " " + msg)
#     for result in results:
#         if result.strip() != "":
#             f.write("    " + result.strip())
#     f.close()
#     return


print ("[*] INFORMACIÓN BÁSICA DEL EQUIPO...\n")
print ("")
print ("[*] CPU y Capacidad de Proceso...\n")

cpuInfo = {
	"CPUINFO":{"cmd":"cat /proc/cpuinfo","msg":"Información del Procesador (/proc/cpuinfo)","results":[]}, 
	"CPUCOUNT":{"cmd":"cat /proc/cpuinfo | grep processor | wc -l","msg":"Número de hilos (/proc/cpuinfo)","results":[]}, 
	"CPUCORES":{"cmd":"cat /proc/cpuinfo | grep 'core id' | sort -u","msg":"Número de cores (CPU)","results":[]}, 
	"CPUVENDOR":{"cmd":"cat /proc/cpuinfo | grep 'vendor' | sort -u","msg":"Fabricante (CPU)","results":[]}, 
	"CPUMODEL":{"cmd":"cat /proc/cpuinfo | grep 'model name' | sort -u","msg":"Modelo (CPU)","results":[]}, 
	"CPUINFO_ls":{"cmd":"lscpu 2>/dev/null","msg":"Información del Procesador (lscpu)","results":[]}, 
	"HWINFO":{"cmd":"lshw -C CPU 2>/dev/null","msg":"Información del Procesador (lshw -C CPU)","results":[]}, 
	"PROCINFO":{"cmd":"nproc 2>/dev/null","msg":"Número de hilos (nproc)","results":[]}, 
	"DMIINFO":{"cmd":"dmidecode -q 2>/dev/null","msg":"Información DMI (dmidecode)","results":[]}, 
	"BIOSINFO":{"cmd":"dmidecode -qt bios 2>/dev/null","msg":"Información BIOS (dmidecode)","results":[]}, 
	"CPUID":{"cmd":"cpuid 2>/dev/null","msg":"Información DMI (dmidecode)","results":[]}
	}

cpuInfo = execCmd(cpuInfo)
printResults(cpuInfo, args.pausas)

print ("[*] Hardware...\n")

computerInfo = {
	"HWINFOls":{"cmd":"lshw 2>/dev/null","msg":"Información del Equipo (lshw)","results":[]}, 
	"HWINFOlss":{"cmd":"lshw -short 2>/dev/null","msg":"Información abreviada del Equipo (lshw)","results":[]}, 
	"HWINFO":{"cmd":"hwinfo --short 2>/dev/null","msg":"Información abreviada del Equipo (hwinfo)","results":[]}, 
	"PCIINFO":{"cmd":"lspci 2>/dev/null","msg":"Información del Bus PCI (lspci)","results":[]}, 
	"PCIINFOt":{"cmd":"lspci -tv 2>/dev/null","msg":"Información del Bus PCI (lspci) - Tree","results":[]}, 
	"VGAINFO":{"cmd":"lspci | grep 'VGA' 2>/dev/null","msg":"Información de la Tarjeta Gráfica (lspci)","results":[]}, 
	"SCSIINFO":{"cmd":"lsscsi 2>/dev/null","msg":"Información de la Tarjeta Gráfica (lspci)","results":[]}, 
	"USBINFO":{"cmd":"lsusb 2>/dev/null","msg":"Información del Bus USB (lsusb)","results":[]},
	"MEMINFO":{"cmd":"free 2>/dev/null","msg":"Información de la Memoria (free)","results":[]},
	"MEMINFO2":{"cmd":"cat /proc/meminfo 2>/dev/null","msg":"Información de la Memoria (cat /proc/meminfo)","results":[]}
	}

computerInfo = execCmd(computerInfo)
printResults(computerInfo, args.pausas)


print ("[*] Almacenamiento...\n")

storageInfo = {
	"BLKINFO":{"cmd":"lsblk 2>/dev/null","msg":"Dispositivos de Bloque (lsblk)","results":[]}, 
	"BLKINFO2":{"cmd":"lsblk | grep -v 'loop' 2>/dev/null","msg":"Dispositivos de Bloque (lsblk)","results":[]}, 
	"DFINFO":{"cmd":"df -h 2>/dev/null","msg":"Utilización Dispositivos de Bloque (lsblk)","results":[]}, 
	"DFINFO2":{"cmd":"df -h | grep -v 'loop' 2>/dev/null","msg":"Utilización Dispositivos de Bloque (lsblk)","results":[]}, 
	"FDISKINFO":{"cmd":"fdisk -l 2>/dev/null","msg":"Utilización Dispositivos de Bloque (lsblk)","results":[]}, 
	"MOUNTINFO":{"cmd":"mount | column -t 2>/dev/null","msg":"Utilización Dispositivos de Bloque (lsblk)","results":[]}, 
	"MOUNTINFO2":{"cmd":"mount | grep -Ev 'squashfs|cgroup|tmpfs' | column -t 2>/dev/null","msg":"Utilización Dispositivos de Bloque (lsblk)","results":[]}, 
	"PARTITIONINFO":{"cmd":"cat /proc/partitions 2>/dev/null","msg":"Particiones (/proc/partitions)","results":[]}, 
	"HDPARMINFO":{"cmd":"hdparm /dev/sd? 2>/dev/null","msg":"Particiones (/proc/partitions)","results":[]}
	}

storageInfo = execCmd(storageInfo)
printResults(storageInfo, args.pausas)



print ("[*] INFORMACIÓN BÁSICA DEL SISTEMA...\n")

sysInfo = {"OS":{"cmd":"cat /etc/issue","msg":"Sistema Operativo (Distribución)","results":[]}, 
	   "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":[]}, 
	   "HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":[]}, 
	   "DOMAIN":{"cmd":"hostname -d", "msg":"Domain", "results":[]},
	   "BOOTCMD":{"cmd":"cat /proc/cmdline 2>/dev/null", "msg":"Boot Command Line (/proc/cmdline)", "results":[]}, 
	   "UPTIME":{"cmd":"uptime 2>/dev/null", "msg":"Usuarios conectados y tiempo encendido (uptime)", "results":[]}, 
	   "UNAME":{"cmd":"uname -a 2>/dev/null", "msg":"Información del sistema (uname -a)", "results":[]}
	  }

sysInfo = execCmd(sysInfo)
printResults(sysInfo, args.pausas)


print ("[*] CONFIGURACIÓN DE RED...\n")

netConfig = {
		"IPs":{"cmd":"ip address show", "msg":"IPs configuradas (ip address show)", "results":[]},
		"IPsv4":{"cmd":"ip address show | grep 'inet ' | cut -d ' ' -f 6", "msg":"IPs v4 configuradas (ip address show)", "results":[]},
		"IPsv6":{"cmd":"ip address show | grep 'inet6' | cut -d ' ' -f 6", "msg":"IPs v6 configuradas (ip address show)", "results":[]},
		"INTERFACES_ifconfig":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces (ifconfig)", "results":[]},
		"INTERFACES_ip":{"cmd":"ip l", "msg":"Interfaces (ip link)", "results":[]},
		"INTERFACES_ip_clean":{"cmd":"ip link | grep '<' | cut -d':' -f2 | tr -d ' '", "msg":"Interfaces (ip link)", "results":[]},
		"INTERFACES_ip_status":{"cmd":"ip link show up | grep '<' | cut -d' ' -f2,9", "msg":"Interfaces Status (ip link)", "results":[]},
		"INTERFACES_ip_MACs":{"cmd":"ip link show up | grep 'link' | grep -v 'loopback' | sed -n 's/ \+/ /gp' | cut -d' ' -f 3", "msg":"Interfaces MACs (ip link)", "results":[]},
		"ROUTE":{"cmd":"route", "msg":"Rutas (route)", "results":[]},
		"ROUTE_ip":{"cmd":"ip r", "msg":"Rutas (ip route)", "results":[]}, 
		"GATEWAYS":{"cmd":"ip route | grep src | cut -d' ' -f 9", "msg":"Gateways (ip route)", "results":[]}, 
		"DNS":{"cmd":"cat /etc/resolv.conf", "msg":"DNS Servers (cat /etc/resolv.conf)", "results":[]}	
	  }

netConfig = execCmd(netConfig)
printResults(netConfig, args.pausas)


netInfo = {
		"NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":[]},
#		"SS":{"cmd":"ss -antup | grep -v 'TIME_WAIT'", "msg":"Conexiones establecidas (ss -antup)", "results":[]},
		"PORTS_TCP":{"cmd":"ss -lntp | grep -v 'TIME_WAIT'", "msg":"Puertos TCP en escucha (ss -lntp)", "results":[]},
		"PORTS_TCPv4":{"cmd":"ss -lntp4 | sed -n 's/ \+/ /gp' | cut -d' ' -f 4 | cut -d':' -f 2 | sort -n | grep -v 'Local'", "msg":"Puertos TCPv4 en escucha (ss -lntp4)", "results":[]},
		"PORTS_TCPv6":{"cmd":"ss -lntp6 | sed -n 's/ \+/ /gp' | cut -d' ' -f 4 | sort -n | grep -v 'Local'", "msg":"Puertos TCPv6 en escucha (ss -lntp6)", "results":[]},
		"PORTS_UDP":{"cmd":"ss -lnup | grep -v 'TIME_WAIT'", "msg":"Puertos UDP en escucha (ss -lnup)", "results":[]},
		"CONN_TCP":{"cmd":"ss -ntp | grep -v 'TIME_WAIT'", "msg":"Conexiones TCP (ss -ntp)", "results":[]}, 
		"CONN_TCP":{"cmd":"ss -nup | grep -v 'TIME_WAIT'", "msg":"Conexiones UDP (ss -nup)", "results":[]}
	  }

netInfo = execCmd(netInfo)
printResults(netInfo, args.pausas)


# raise SystemExit(0)

print ("[*] INFORMACIÓN DEL SISTEMA DE FICHEROS...\n")

driveInfo = {"MOUNT":{"cmd":"mount","msg":"Sistemas de ficheros montados", "results":[]},
	    "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"Contenido del fichero /etc/fstab", "results":[]},
	    "FSTABt":{"cmd":"cat /etc/fstab | grep -v '#' | column -t 2>/dev/null", "msg":"Contenido del fichero /etc/fstab", "results":[]}
	    }

driveInfo = execCmd(driveInfo)
printResults(driveInfo, args.pausas)


cronInfo = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Cron jobs programados", "results":[]},
	    "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Directorios de trabajos cron con permisos de escritura", "results":[]}
	   }

cronInfo = execCmd(cronInfo)
printResults(cronInfo, args.pausas)



print ("\n[*] INFORMACIÓN DEL USUARIO Y DEL ENTORNO...\n")

userInfo = {"WHOAMI":{"cmd":"whoami", "msg":"Usuario actual", "results":[]},
	    "ID":{"cmd":"id","msg":"ID del usuario actual", "results":[]},
	    "ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"Todos los usuarios (/etc/passwd)", "results":[]},
	    "ALLUSERS2":{"cmd":"cat /etc/passwd | cut -d':' -f 1 2>/dev/null", "msg":"Nombres de usuario (/etc/passwd)", "results":[]},
	    "ALLUSERS3":{"cmd":"cat /etc/passwd | grep -Ev 'nologin|false' | cut -d':' -f1,3,7", "msg":"Usuarios con shell (/etc/passwd)", "results":[]},
	    "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Superusuarios encontrados:", "results":[]},
	    "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Ficheros 'history' con el registro de comandos del usuario actual y de root (depende de los privilegios)", "results":[]},
	    "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Variables de entorno (env)", "results":[]},
	    "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (usuarios con privilegios)", "results":[]},
	    "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Usuarios conectados en este momento", "results":[]},
	    "LAST":{"cmd":"last 2>/dev/null", "msg":"Últimos usuarios conectados al sistema", "results":[]}
	   }

if args.contenido:
	userInfo.update({
		"HISTORYCU":{"cmd":"cat ~/.*_history 2>/dev/null", "msg":"Contenido de los ficheros 'history' con el registro de comandos del usuario actual", "results":[]},
		"HISTORYCR":{"cmd":"cat /root/.*_history 2>/dev/null", "msg":"Contenido de los ficheros 'history' con el registro de comandos de root (depende de los privilegios)", "results":[]},
	})

userInfo = execCmd(userInfo)
printResults(userInfo, args.pausas)

if "root" in userInfo["ID"]["results"][0]:
    print ("[!] ¿HAS COMPROBADO QUE NO SEAS root?\n")



print ("[*] PROCESOS Y APLICACIONES...\n")

if "debian" in sysInfo["KERNEL"]["results"][0] or "ubuntu" in sysInfo["KERNEL"]["results"][0]:
    getPkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" # Debian/Ubuntu
else:
    getPkgs = "rpm -qa | sort -u" 	# RH/Fedora/CentOS/otros

getAppProc = {
				"PROCS":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"Procesos actuales", "results":[]},
            	"PKGS":{"cmd":getPkgs, "msg":"Paquetes instalados", "results":[]}
			  }

if args.extenso:
	getAppProc = execCmd(getAppProc)
	printResults(getAppProc, args.pausas)	# Comentar para evitar una salida excesiva durante las pruebas


otherApps = { "SUDO":{"cmd":"sudo -V | grep version 2>/dev/null", "msg":"Versión de SUDO", "results":[]},
	      "APACHE":{"cmd":"apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null", "msg":"Versión de Apache y sus módulos", "results":[]},
	      "APACHECONF":{"cmd":"cat /etc/apache2/apache2.conf 2>/dev/null", "msg":"Fichero de Configuración de Apache", "results":[]}
	    }

otherApps = execCmd(otherApps)
printResults(otherApps, args.pausas)



print ("[*] PROCESOS Y PAQUETES EJECUTÁNDOSE COMO ROOT O ALGÚN OTRO SUPERUSUARIO...\n")

# Buscamos la información de los paquetes correspondientes a los procesos
# que se están ejecutando como root o como algún otro superusuario

procs = getAppProc["PROCS"]["results"]
pkgs = getAppProc["PKGS"]["results"]
supusers = userInfo["SUPUSERS"]["results"]
procdict = {} # dictionary to hold the processes running as super users
  
for proc in procs: # loop through each process
	relatedpkgs = [] # list to hold the packages related to a process    
	try:
		for user in supusers: # loop through the known super users
			if (user != "") and (user in proc): # if the process is being run by a super user
				procname = proc.split(" ")[4] # grab the process name
				if "/" in procname:
					splitname = procname.split("/")
					procname = splitname[len(splitname)-1]
				for pkg in pkgs: # loop through the packages
					if not len(procname) < 3: # name too short to get reliable package results
						if procname in pkg: 
							if procname in procdict: 
								relatedpkgs = procdict[proc] # if already in the dict, grab its pkg list
							if pkg not in relatedpkgs:
								relatedpkgs.append(pkg) # add pkg to the list
				procdict[proc]=relatedpkgs # add any found related packages to the process dictionary entry
	except:
		pass

for key in procdict:
	print ("    " + key) # print the process name
	try:
		if not procdict[key][0] == "": # only print the rest if related packages were found
			print ("        Possible Related Packages: " )
			for entry in procdict[key]: 
				print ("            " + entry) # print each related package
	except:
		pass

if args.pausas:
	pause()

print ('')
print ("[*] LENGUAJES DE PROGRAMACIÓN Y HERRAMIENTAS INSTALADAS PARA LA CONSTRUCCIÓN DE EXPLOITS...\n")

devTools = {
	"TOOLS":{"cmd":"which awk perl python python2 python3 ruby gcc cc vi vim nmap find netcat ss nc wget tftp ftp 2>/dev/null", "msg":"Herramientas instaladas", "results":[]}
	}

devTools = execCmd(devTools)
printResults(devTools, args.pausas)



print ("[*] CONTENIDO Y PERMISOS DE FICHEROS Y DIRECTORIOS...\n")

fdPerms={}

fdPerms.update({
	"ROOTHOME":{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Comprobación de acceso al directorio de 'root'", "results":[]}
	})

if args.buscar:
	print('Se va a realizar una búsqueda que puede llevar un tiempo... Espere por favor...')
	fdPerms.update({
	"SUID":{"cmd":"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"Ficheros y directorios con SUID/SGID", "results":[]}
	})

# if args.buscar:
# 	fdPerms.update({
# 		"WWDIRSROOT":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"Directorios del usuario/grupo 'root' con permiso de escritura universal", "results":[]},
# 		"WWDIRS":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"Directorios con permiso de escritura universal", "results":[]},
# 		"WWFILES":{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"Ficheros con permiso de escritura universal", "results":[]},
# 	  })

if args.directorios:
	fdPerms.update({
		"MYHOME":{"cmd":"ls -ahlR ~ 2>/dev/null", "msg":"Listado completo de mi directorio", "results":[]}
	})

fdPerms = execCmd(fdPerms) 
printResults(fdPerms, args.pausas)

pwdFiles = {}

if args.buscar:
	print('Se va a realizar una búsqueda que puede llevar un tiempo... Espere por favor...')
	pwdFiles.update({
		"LOGPWDS":{"cmd":"find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Logs que contienen la palabra 'password'", "results":[]},
	    "CONFPWDS":{"cmd":"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Ficheros de configuración que contienen la palabra 'password'", "results":[]}
	})

if args.contenido:
	pwdFiles.update({
		"SHADOW":{"cmd":"cat /etc/shadow 2>/dev/null", "msg":"Shadow File (se requieren privilegios)", "results":[]},
		"PASSWORD":{"cmd":"cat /etc/passwd 2>/dev/null", "msg":"Passwd File", "results":[]}
	})

pwdFiles = execCmd(pwdFiles)
printResults(pwdFiles, args.pausas)


print ('')	
print ("Ejecución finalizada")
print (bigline)

#sys.exit(0)
raise SystemExit(0)

