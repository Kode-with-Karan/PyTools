from scapy.all import ARP, Ether, srp
import platform
import requests
import telebot
import socket
import re

bot_token = "6341384178:AAHKKeUwJ9D3iVc3ihgBzIAm_Gx1cHYOV7o"
chat_id = "5594268442"
bot = telebot.TeleBot(bot_token)

def get_mac_details(mac_address):
	
	# We will use an API to get the vendor details
	url = "https://api.macvendors.com/"
	
	# Use get method to fetch details
	response = requests.get(url+mac_address)
	if response.status_code != 200:
		raise Exception("[!] Invalid MAC Address!")
	return response.content.decode()

def scan_net(target_ip):
	arp = ARP(pdst=target_ip+"/24")
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether/arp
	result = srp(packet, timeout=3, verbose=0)[0]
	clients = []
	
	for sent, received in result:
		clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'Vender Name': get_mac_details(received.hwsrc)})
	
	return clients

def get_my_ip():
	host_name = socket.gethostname()
	ipv4_address = socket.gethostbyname(host_name)
	try:
		ipv6_address = socket.getaddrinfo(host_name, None, socket.AF_INET6)[0][4][0]
	except (socket.gaierror, IndexError):
		ipv6_address = None

	url = "https://httpbin.org/ip"
	public_ip = None
	try:
		# Send an HTTP GET request to the service
		response = requests.get(url)

		# Parse the JSON response to extract the IP address
		data = response.json()
		public_ip = data.get("origin")

	except requests.RequestException as e:
		pass
	return [host_name,ipv4_address,ipv6_address,public_ip]

def get_my_info():
	sysinfo = f""" <b>System Platform: </b> {platform.system()}\n\n<b>System Info: </b> {platform.uname()}\n\n<b>Processor Architecture: </b> {platform.architecture()}\n\n<b>Python Version: </b> {platform.python_version()}\n\n<b>Network Name: </b> {platform.node()}\n\n<b>System Release: </b> {platform.release()}\n\n<b>Machine: </b> {platform.machine()}\n\n<b>Platform Architecture: </b> {platform.platform()}\n\n<b>Platform Version: </b> {platform.version()}\n\n<b>Host IP Info:- </b>\n\n<b>Host Name: </b> {get_my_ip()[0]}\n\n<b>IPv4 Address: </b> {get_my_ip()[1]}\n\n<b>IPv6 Address: </b> {get_my_ip()[2]}\n\n<b>Public IP Address: </b> {get_my_ip()[3]}\n\n"""
	return sysinfo

@bot.message_handler(commands=['start'])
def start(message):
	print(message)
	bot.reply_to(message,get_my_info(), parse_mode='HTML')
	

@bot.message_handler(func=lambda message: message.text.startswith('/scan'))
def handle_command_with_message(message):
    ip = (message.text[len('/scan '):])

    for index, client  in enumerate(scan_net(ip)):
        bot.reply_to(message, f'<b>Client</b> {index}', parse_mode='HTML')
        bot.reply_to(message, f"<b>IP: </b>{str(client['ip'])}\n<b>MAC: </b>{str(client['mac'])}\n<b>Vender Name: </b>{str(client['Vender Name'])}\n\n", parse_mode='HTML')

@bot.message_handler(func=lambda message: True)
def echo_all(message):
	print(message)
	bot.reply_to(message, message.text)

if __name__ == '__main__':
	# bot.send_message("5594268442","Hello, Hnn bhai me hi hu")

	bot.polling()







