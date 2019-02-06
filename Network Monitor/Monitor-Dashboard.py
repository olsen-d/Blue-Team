from tkinter import * 
from tkinter import ttk
import sqlite3 as sq 
import datetime
import subprocess
import time
import matplotlib.pyplot as plt



window = Tk()
window.title("Network Monitor") 
window.geometry('1200x700')

#Date Params
x = datetime.datetime.now()
today = x.strftime("%x")

#SQL Connection & Queries
con = sq.connect('network.db') 
c = con.cursor() 
sql_select_tests = 'SELECT * FROM tests WHERE date="'+today+'"'
sql_select_devices = 'SELECT DISTINCT mac_addr,ip_addr FROM devices WHERE date="'+today+'"'
sql_device_packet_count_bydate = 'SELECT count(*) FROM devices GROUP BY date'
sql_device_scan_dates = 'SELECT DISTINCT date FROM devices' 
sql_device_data = 'SELECT * FROM devices'
sql_arp_packet_count = 'SELECT COUNT(*) FROM arp_traffic WHERE date = "'+today+'"' 
sql_icmp_packet_count = 'SELECT COUNT(*) FROM icmp_traffic WHERE date = "'+today+'"'
sql_tcp_packet_count = 'SELECT COUNT(*) FROM tcp_traffic WHERE date = "'+today+'"'
sql_udp_packet_count = 'SELECT COUNT(*) FROM udp_traffic WHERE date = "'+today+'"'
sql_other_packet_count = 'SELECT COUNT(*) FROM other_traffic WHERE date = "'+today+'"'    
sql_tcp_convos = 'SELECT DISTINCT source_ip,dest_ip,src_port,dest_port,COUNT(source_ip) FROM tcp_traffic WHERE date = "'+today+'" GROUP BY source_ip,dest_ip'     
#sql_device_scan_count_bydate = 'SELECT date, COUNT( distinct (time)) FROM devices WHERE date="'+date+'"'

# PULL SQL DATA
def get_data(c,sql):
	c.execute(sql) 
	data = c.fetchall()
	return data
# GATHER DEVICE DATA:	
device_data = get_data(c,sql_select_devices)
n_devices = len(device_data)

# GATHER TRAFFIC DATA:
arp_packet_count = get_data(c,sql_arp_packet_count)
icmp_packet_count = get_data(c,sql_icmp_packet_count)
tcp_packet_count = get_data(c,sql_tcp_packet_count)
udp_packet_count = get_data(c,sql_udp_packet_count)
other_packet_count = get_data(c,sql_other_packet_count)
tcp_convos = get_data(c,sql_tcp_convos)

def calc_device_history():
	scan_dates = get_data(c, sql_device_scan_dates)
	device_history = []
	for date in scan_dates:
		date = date[0]
		sql_device_packets_bydate = 'SELECT date,COUNT(time) FROM devices WHERE date="'+date+'"'
		sql_device_scan_count_bydate = 'SELECT date, COUNT( distinct (time)) FROM devices WHERE date="'+date+'"'
		packet_count_bydate = get_data(c, sql_device_packets_bydate)
		scan_count_bydate = get_data(c, sql_device_scan_count_bydate)
		device_count_bydate = [date,(packet_count_bydate[0][1])/(scan_count_bydate[0][1])]
		device_history.append(device_count_bydate)
	return device_history
	
def graph_device_history():
	t = []
	s = []
	device_history = calc_device_history()
	for element in device_history:
		t.append(element[0])
		s.append(element[1])
	plt.plot(t, s)

	#Formatting
	plt.xlabel('date (s)')
	plt.ylabel('device count')
	plt.title('Device Count by Date')
	plt.grid(True)
	plt.savefig("test.png")
	plt.show()
		


def device_ips(device_data):
	device_ips = []
	for device in device_data:
		device_ips.append(device[1])
	return device_ips
	
def speed_record():
	c.execute('SELECT * FROM tests') #Select from which ever compound lift is selected
	data = c.fetchall() # Gets the data from the table
	detail = 1
	frame = Frame(speed_frame)
	frame.place(x= 5, y = 520)
    # --> create a Hide Function
	button_3A = Button(speed_frame,text="Hide",command=donothing)
	button_3A.place(x=10,y=660)

    #Create Table in Listbox
	Lb = Listbox(frame, height = 8, width = 50,font=("arial", 10)) 
	Lb.pack(side = LEFT, fill = Y)
	scroll = Scrollbar(frame, orient = VERTICAL) # set scrollbar to list box for when entries exceed size of list box
	scroll.config(command = Lb.yview)
	scroll.pack(side = RIGHT, fill = Y)
	Lb.config(yscrollcommand = scroll.set) 
	for row in data:
		Lb.insert(1,row) # Inserts record row by row in list box

	L7 = Label(speed_frame, text = 'Date	Time	Source	Destination', font=("arial", 10), bg='white')
	L7.place(x=10,y=500)
	con.commit()
	return detail
	

	
def devices_record():
	header = 'Date	Time	Source	Destination'
	data = get_data(c,sql_device_data)
	frame = Frame(devices_frame, height = 20, width = 80)
	frame.place(x= 5, y = 330)
    #Create Table in Listbox
	Lb = Listbox(frame, height = 18, width = 60, font=("arial", 10)) 
	Lb.pack(side = LEFT, fill = Y)
	scroll = Scrollbar(frame, orient = VERTICAL) # set scrollbar to list box for when entries exceed size of list box
	scroll.config(command = Lb.yview)
	scroll.pack(side = RIGHT, fill = Y)
	Lb.config(yscrollcommand = scroll.set)
	Lb.insert(1,header)
	for row in data:
		Lb.insert(2,row) # Inserts record row by row in list box
	con.commit()

	


def ping():
	host = ipField.get('1.0',END)
	p1 = subprocess.Popen(['ping', '-c 2', host], stdout=subprocess.PIPE)
	output = p1.communicate()[0]
	output = output.decode('utf8')
	return output

def ping_window():
	output = ping()
	filewin1 = Toplevel(window)
	filewin1.title('Ping Results')
	filewin1.geometry('500x300')
	ping_outputLabel = Label(filewin1,text="Output")
	ping_outputLabel.pack(side=TOP)
	ping_outputWindow = Text(filewin1)
	ping_outputWindow.config(relief=SUNKEN, bg='white',width=100,height=20)
	ping_outputWindow.pack(side=BOTTOM)
	ping_outputWindow.delete('1.0',END)
	ping_outputWindow.insert('1.0',output)

def nmap():
	p1 = subprocess.Popen(['nmap', '192.168.208.1'], stdout=subprocess.PIPE)
	output = p1.communicate()[0]
	output = output.decode('utf8')
	#time.sleep(30)
	return output

def nmap_scan():
	nmap_outputLabel = Label(devices_frame,text="Output", bg='white', font=("arial",10, 'bold'))
	nmap_outputLabel.place(x=5,y=310)
	nmap_outputWindow = Text(devices_frame)
	nmap_outputWindow.config(relief=SUNKEN, bg='white',width=60,height=20)
	nmap_outputWindow.place(x=5,y=330)
	nmap_outputWindow.delete('1.0',END)
	rc = nmap()
	#time.sleep(30)
	nmap_outputWindow.insert('1.0',rc)


# Menu Bar - Currently Does Nothing
def donothing():
   filewin = Toplevel(window)
   button = Button(filewin, text="Do nothing button")
   button.pack()

menubar = Menu(window,bg='grey')
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="Refresh", command=donothing)
filemenu.add_command(label="Disconnect", command=donothing)
filemenu.add_command(label="Exit", command=window.quit)
menubar.add_cascade(label="File", menu=filemenu)

datamenu = Menu(menubar, tearoff=0)
datamenu.add_command(label="Export", command=donothing)
datamenu.add_command(label="Import", command=donothing)
datamenu.add_separator()
datamenu.add_command(label="Reports", command=donothing)
datamenu.add_command(label="Reports", command=donothing)
menubar.add_cascade(label="Data", menu=datamenu)



#Frames & Labels Data
#if speed_data != 0:
speed_data = get_data(c,sql_select_tests)
last_download = str(speed_data[0][2]) + " Mbits/sec"
last_upload = str(speed_data[0][3]) + " Mbits/sec"
last_ping = str(speed_data[0][4]) + " ms"

today_downloads = []
today_uploads = []
today_pings = []
for test in speed_data:
	today_downloads.append(test[2])
	today_uploads.append(test[3])
	today_pings.append(test[4])

avg_download = sum(today_downloads) / len(today_downloads)
avg_download = ("%.2f Mbits/sec" % avg_download)
avg_upload = sum(today_uploads) / len(today_uploads)
avg_upload = ("%.2f Mbits/sec" % avg_upload)
avg_ping = sum(today_pings) / len(today_pings)
avg_ping = ("%.2f ms" % avg_ping)

min_download = min(today_downloads)
min_download = ("%.2f Mbits/sec" % min_download)
min_upload = min(today_uploads)
min_upload = ("%.2f Mbits/sec" % min_upload)
min_ping = min(today_pings)
min_ping = ("%.2f ms" % min_ping)
max_download = max(today_downloads)
max_download = ("%.2f Mbits/sec" % max_download)
max_upload = max(today_uploads)
max_upload = ("%.2f Mbits/sec" % max_upload)
max_ping = max(today_pings)
max_ping = ("%.2f ms" % max_ping)

	

	
#PanedWindows
panewindow_1 = ttk.PanedWindow(window, orient = HORIZONTAL)
panewindow_1.pack(fill = BOTH, expand = True, side = LEFT)



#Frames & Labels Format
speed_frame = Frame(panewindow_1, width = 50, height = 600, relief = FLAT, bg='black', bd=1)
speed_frame.grid(row=1, column=0)
speed_label1 = Label(speed_frame, text="Bandwidth Statistics",justify=LEFT, fg='white', bg='black', font=("arial",14,"bold"))
speed_label1.place(x= 5, y = 10)
speed_label2 = Label(speed_frame, text="Most Recent Test", justify = LEFT, fg='white', bg='black', font=("arial",12,'bold'))
speed_label2.place(x= 10, y = 50)
speed_label3 = Label(speed_frame, text="Download", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label3.place(x= 10, y = 70)
speed_label4 = Label(speed_frame, text=last_download, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label4.place(x= 100, y = 70)
speed_label5 = Label(speed_frame, text="Upload", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label5.place(x= 10, y = 90)
speed_label6 = Label(speed_frame, text=last_upload, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label6.place(x= 100, y = 90)
speed_label7 = Label(speed_frame, text="Ping", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label7.place(x= 10, y = 110)
speed_label8 = Label(speed_frame, text=last_ping, justify = RIGHT, fg='white', bg='black', font=("arial",10))
speed_label8.place(x= 100, y = 110)

speed_label9 = Label(speed_frame, text="Today's Results", justify = LEFT, fg='white', bg='black', font=("arial",12,'bold'))
speed_label9.place(x= 10, y = 150)
speed_label10 = Label(speed_frame, text="Downloads", justify = LEFT, fg='white', bg='black', font=("arial",12))
speed_label10.place(x= 10, y = 170)
speed_label11 = Label(speed_frame, text="Average", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label11.place(x= 10, y = 190)
speed_label12 = Label(speed_frame, text=avg_download, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label12.place(x= 100, y = 190)
speed_label13 = Label(speed_frame, text="Minimum", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label13.place(x= 10, y = 210)
speed_label14 = Label(speed_frame, text=min_download, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label14.place(x= 100, y = 210)
speed_label15 = Label(speed_frame, text="Maximum", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label15.place(x= 10, y = 230)
speed_label16 = Label(speed_frame, text=max_download, justify = RIGHT, fg='white', bg='black', font=("arial",10))
speed_label16.place(x= 100, y = 230)

speed_label17 = Label(speed_frame, text="Uploads", justify = LEFT, fg='white', bg='black', font=("arial",12))
speed_label17.place(x= 10, y = 260)
speed_label18 = Label(speed_frame, text="Average", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label18.place(x= 10, y = 280)
speed_label19 = Label(speed_frame, text=avg_upload, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label19.place(x= 100, y = 280)
speed_label20 = Label(speed_frame, text="Minimum", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label20.place(x= 10, y = 300)
speed_label21 = Label(speed_frame, text=min_upload, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label21.place(x= 100, y = 300)
speed_label22 = Label(speed_frame, text="Maximum", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label22.place(x= 10, y = 320)
speed_label23 = Label(speed_frame, text=max_upload, justify = RIGHT, fg='white', bg='black', font=("arial",10))
speed_label23.place(x= 100, y = 320)

speed_label24 = Label(speed_frame, text="Pings", justify = LEFT, fg='white', bg='black', font=("arial",12))
speed_label24.place(x= 10, y = 350)
speed_label25 = Label(speed_frame, text="Average", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label25.place(x= 10, y = 370)
speed_label26 = Label(speed_frame, text=avg_ping, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label26.place(x= 100, y = 370)
speed_label27 = Label(speed_frame, text="Minimum", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label27.place(x= 10, y = 390)
speed_label28 = Label(speed_frame, text=min_ping, justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label28.place(x= 100, y = 390)
speed_label29 = Label(speed_frame, text="Maximum", justify = LEFT, fg='white', bg='black', font=("arial",10))
speed_label29.place(x= 10, y = 410)
speed_label30 = Label(speed_frame, text=max_ping, justify = RIGHT, fg='white', bg='black', font=("arial",10))
speed_label30.place(x= 100, y = 410)

button_3 = Button(speed_frame,text="Bandwidth",command=speed_record)
button_3.place(x=10,y=520)

#device_data = get_data(c,sql_select_devices)
#n_devices = len(device_data)
#device_ips = []
#for device in device_data:
#	device_ips.append(device[1])
#print(device_ips)
devices_frame = Frame(panewindow_1, bg='white', bd=1)
devices_label1 = Label(devices_frame, text="Connected Devices",justify=CENTER ,bg='white', font=("arial",14,"bold"))
devices_label1.place(x= 5, y = 10)
devices_label4 = Label(devices_frame, text="Devices Today:", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
devices_label4.place(x= 10, y = 50)
button_device_graph = Button(devices_frame, text='Graph History',height=1, width=8,font=("arial",8),command=graph_device_history)
button_device_graph.place(x=335,y=50)
devices_label5 = Label(devices_frame, text=n_devices, justify = LEFT, fg='black', bg='white', font=("arial",10))
devices_label5.place(x= 200, y = 50)
devices_label4 = Label(devices_frame, text="Typical Number of Devices:", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
devices_label4.place(x= 10, y = 70)
devices_label5 = Label(devices_frame, text=n_devices, justify = LEFT, fg='black', bg='white', font=("arial",10))
devices_label5.place(x= 200, y = 70)

devices_label2 = Label(devices_frame, text="MAC Address", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
devices_label2.place(x= 10, y = 110)
devices_label3 = Label(devices_frame, text="IP Address", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
devices_label3.place(x= 140, y = 110)
devices_label3 = Label(devices_frame, text="Name", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
devices_label3.place(x= 275, y = 110)
devices_Lb1 = Listbox(devices_frame, height = 8, width = 60,font=("arial", 10)) 
devices_Lb1.place(x= 5, y = 130)

for device in device_data:
	row = device[0].ljust(30) + device[1].rjust(10)
	devices_Lb1.insert(1,row) # Inserts record row by row in list box

button_1 = Button(devices_frame, text="Device Data",height=1, width=8,font=("arial",8),bg='grey',command=devices_record)
button_1.place(x=20,y=270)

button_2 = Button(devices_frame, text="NMAP Scan",height=1, width=8,font=("arial",8),bg='grey',command=nmap_scan)
button_2.place(x=125,y=270)

button_6 = Button(devices_frame, text="Refresh",height=1, width=8,font=("arial",8),bg='grey',command=donothing)
button_6.place(x=230,y=270)






def main_output_device():
	main_outputLabel = Label(devices_frame,text="Output", bg='white', font=("arial",10, 'bold'))
	main_outputLabel.place(x=5,y=310)
	main_outputWindow = Text(devices_frame)
	main_outputWindow.config(relief=SUNKEN, bg='grey',width=60,height=20)
	main_outputWindow.place(x=5,y=330)
	main_outputWindow.delete('1.0',END)
	main_outputWindow.insert('1.0',"No function selected")
	
main_output_device()

button_device_clear = Button(devices_frame, text="Clear",height=1, width=8,font=("arial",8),bg='grey', command=main_output_device)
button_device_clear.place(x=20,y=640)


connections_frame = Frame(panewindow_1, bg='white', bd=1)
connect_label1 = Label(connections_frame, text="Traffic:", justify=CENTER ,bg='white', font=("arial",14,"bold"))
connect_label1.place(x= 5, y = 10)
connect_label4 = Label(connections_frame, text="Packets Captured (by type):", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
connect_label4.place(x= 10, y = 50)
connect_label6 = Label(connections_frame, text="ARP", justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label6.place(x= 10, y = 70)
connect_label5 = Label(connections_frame, text=arp_packet_count, justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label5.place(x= 200, y = 70)
connect_label6 = Label(connections_frame, text="ICMP", justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label6.place(x= 10, y = 90)
connect_label5 = Label(connections_frame, text=icmp_packet_count, justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label5.place(x= 200, y = 90)
connect_label6 = Label(connections_frame, text="TCP", justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label6.place(x= 10, y = 110)
connect_label5 = Label(connections_frame, text=tcp_packet_count, justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label5.place(x= 200, y = 110)
connect_label6 = Label(connections_frame, text="UDP", justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label6.place(x= 10, y = 130)
connect_label5 = Label(connections_frame, text=udp_packet_count, justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label5.place(x= 200, y = 130)
connect_label6 = Label(connections_frame, text="Other", justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label6.place(x= 10, y = 150)
connect_label5 = Label(connections_frame, text=other_packet_count, justify = LEFT, fg='black', bg='white', font=("arial",10,))
connect_label5.place(x= 200, y = 150)
connect_label4 = Label(connections_frame, text="TCP Conversations:", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
connect_label4.place(x= 10, y = 180)
connect_label4 = Label(connections_frame, text="Source Host", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
connect_label4.place(x= 10, y = 200)
connect_label4 = Label(connections_frame, text="Destination Host", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
connect_label4.place(x= 170, y = 200)
connect_label4 = Label(connections_frame, text="Count", justify = LEFT, fg='black', bg='white', font=("arial",10,'bold'))
connect_label4.place(x= 350, y = 200)

connect_Lb1 = Listbox(connections_frame, height = 8, width = 60,font=("arial", 10)) 
connect_Lb1.place(x= 5, y = 220)
for convo in tcp_convos:
	row = convo[0].ljust(30) + convo[1].center(30) +str(convo[4]).rjust(15)
	connect_Lb1.insert(1,row) 


t_period = StringVar(connections_frame)
t_period.set('Today')

day = StringVar(connections_frame)
month = StringVar(connections_frame)
days_30 = StringVar(connections_frame)
year = StringVar(connections_frame)


#Dictionary for drop down list
t_options = {'Today','Week', 'Month', '30-Days','Year'}


period = OptionMenu(connect_label14, compdb, *t_options)#For 2nd drop down list
period.pack(side = RIGHT)
period.config(bg='grey', font=("arial",8))

ipField = Text(speed_frame)
ipField.place(x=10,y=480)
ipField.config(relief=SUNKEN, bg='white',width=15,height=1.25)

button_8 = Button(speed_frame,text="Ping Host",height=1,command=ping_window)
button_8.place(x=150,y=480)


panewindow_1.add(speed_frame, weight = 1)
panewindow_1.add(devices_frame, weight = 2)
panewindow_1.add(connections_frame, weight = 2)

window.config(menu=menubar)
window.mainloop() 
