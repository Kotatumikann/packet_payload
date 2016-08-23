#_*_coding: utf-8 -*-
import sqlite3
import random
from datetime import datetime
from netfilterqueue import NetfilterQueue
#フラグを２進数にする関数
def flag_change(flag):
	uaprsf_10=int(flag,16)
	uaprsf_2=str(format(uaprsf_10,'012b'))
	uaprsf_6=uaprsf_2[-6:]
	return uaprsf_6
#flag
def flag_view(view):
	jude=[]
	bate=[]	
	flag_6=['URG','ACK','PSH','RST','SYN','FIN']
	for x in range(6):
		jude.append(view[x])

	for y in range(6):
		if jude[y]=='1':
			bate.append(flag_6[y])

	return bate
		
#ICMPのタイプを判断する
def icmp_type(type_icmp):
	if(type_icmp=='0'):
		type_i='エコー応答'	
	elif(type_icmp=='3'):
		type_i='宛先不達'
	elif(type_icmp=='4'):
		tyoe_i='ソースクエンチ'
	elif(type_icmp=='5'):
		type_i='リダイレクト要求'
	elif(type_icmp=='8'):
		type_i='エコー要求'
	elif(type_icmp=='11'):
		type_i='時間経過'
	elif(type_icmp=='12'):
		type_i='パラメータ異常'
	elif(type_icmp=='13'):
		type_i='タイムスタンプ要求'
	elif(type_icmp=='14'):
		type_i='タイムスタンプ応答'
	elif(type_icmp=='15'):
		type_i='情報要求'
	elif(type_icmp==16):
		type_i='情報応答'
	elif(type_icmp==17):
		type_i='アドレスマスク要求'
	else:
		type_i='アドレスマスク応答'
	
	return type_i

#データ部を2つずつにリストに格納する関数
def sprie(a):
	#長さをとる
	length=len(a)
	#2個ずつ格納するので長さは、2分の1でいい
	counter=length/2
	spire=0
	list_ago=[]
	#2つずつにわけて、16進数であることを示すために0xをつけてリストに格納する
	for x in range(counter):
		list_ago.append('0x'+a[spire:spire+2])
		spire=spire+2
	#ASCIIコードに変換する関数に上で作成したリストに渡す
	list_w=changer(list_ago)
	return list_w

#Aciiコードに変換する関数
def changer(list_s):
	list_acii=[]
	for y in list_s:
		#intで16進数を10進数に変換してchrで文字列になおしている(ACSII)
		sect=chr(int(y,16))
		list_acii.append(sect)
	return list_acii

def sql_data(numbers,times,datas):
	con=sqlite3.connect('./pay.db')
	con.text_factory = str
	cur=con.cursor()
	hensu=''
	for u in datas:
		hensu+=u
	sql="INSERT INTO pay(ID,TIME,DATA) VALUES(?,?,?)"
	cur.execute(sql,[numbers,times,hensu,])
	con.commit()
	cur.close()

#データ部別ファイルに書き込む
def data_write(list_bcii,times,datab,numbers_random):
	
	datafct=open('datafuct.txt','a')
	datafct.write('['+numbers_random+']'+'\n')
	datafct.write(times+'\n')
	datafct.write('[DATA_BEFORE]\n')
	datafct.write(datab+'\n')
	datafct.write('\n')
	datafct.write('[DATA_AFFTER]\n')
	for z in list_bcii:
		datafct.write(z)
	datafct.write('\n')
	datafct.write('\n')
	datafct.close()

def fileout(pkt):
	a=pkt.encode('hex')
	moji=str(a)
	time=datetime.now().strftime('%Y/%m/%d %H:%M:%S')
	#IPバージョン
	ip_version=moji[0:1]
	#IPヘッダの長さ
	ip_length=moji[1:2]
	ip_length_byte=str(int(ip_length)*4)
	#優先順位
	yusen=moji[2:4]
	yusen_10=str(int(yusen,16))
	#パケット長
	paketsu=moji[4:8]
	paketsu_10=str(int(paketsu,16))
	#ID
	ip_id=moji[8:12]
	ip_id_10=str(int(ip_id,16))
	#フラグ
	frag=moji[12:16]
	#TTL
	ttl=moji[16:18]
	ttl_10=str(int(ttl,16))
	#プロトコル
	prot=moji[18:20]
	prot_10=str(int(prot,16))
	#チェックサム
	ip_checksam=moji[20:24]
	#送信元IPアドレス
	ip_source=moji[24:32]
	ips_10_1=str(int(ip_source[0:2],16))
	ips_10_2=str(int(ip_source[2:4],16))
	ips_10_3=str(int(ip_source[4:6],16))
	ips_10_4=str(int(ip_source[6:8],16))
	#送信先IPアドレス
	ip_dis=moji[32:40]	
	ipd_10_1=str(int(ip_dis[0:2],16))
	ipd_10_2=str(int(ip_dis[2:4],16))
	ipd_10_3=str(int(ip_dis[4:6],16))
	ipd_10_4=str(int(ip_dis[6:8],16))

	if prot_10 == '6':
		#TCP
		#送信元ポート
		source_port=moji[40:44]
		source_port_10=str(int(source_port,16))
		#送信先ポート
		dis_port=moji[44:48]
		dis_port_10=str(int(dis_port,16))
		#シーケンス番号	
		skensu_16=moji[48:56]
		skensu=str(int(skensu_16,16))
		#ACK番号
		ack_16=moji[56:64]
		ack=str(int(ack_16,16))
		#データセット
		dataset=moji[64:65]
		dataset_byte=str(int(dataset)*4)
		#URG,ACK,PSH,RST,SYN,FIN
		uaprsf=moji[65:68]
		uaprsf_2_6=flag_change(uaprsf)
		#ウィンドウサイズ
		wsize=moji[68:72]
		wsize_10=str(int(wsize,16))
		#チェックサム
		cheksam=moji[72:76]
		#緊急ポインタ
		escap_pointer=moji[76:80]
		escap_pointer_10=str(int(escap_pointer,16))
		#データ部の確認用
		databu=moji[80:]

	elif prot_10 == '17':
		#UDP	
		#送信元ポート
		source_port=moji[40:44]
		source_port_10=str(int(source_port,16))
		#送信先ポート
		dis_port=moji[44:48]
		dis_port_10=str(int(dis_port,16))
		#UDPのパケット長
		paket_length=moji[48:52]
		paket_length_10=str(int(paket_length,16))
		#ヘッダのチェックサム
		udp_checksam=moji[52:56]	
		#データ部の確認用（空白ならば、データ部はない）
		databu=moji[56:]
	else:
		#ICMP	
		#タイプ
		type_16=moji[40:42]
		type_10=str(int(type_16,16))
		#タイプ表示
		icmp_1=icmp_type(type_10)
		#コード
		code=moji[42:44]
		code_10=str(int(code,16))
		#チェックサム
		icmp_checksam=moji[44:48]
		#タイプが0または8ならば
		if type_10 == '0' or type_10 == '8':
			#ID
			icmp_id=moji[48:52]
			icmp_id_10=str(int(icmp_id,16))
			#シーケンス番号
			skensu=moji[52:56]
			skensu_10=str(int(skensu,16))
			#データ部
			databu=moji[56:]
		else:
		#タイプが0,8以外ならば
			databu=moji[48:]

	#ファイルに保存
	fp=open('test.txt','a')
	#時刻の表示
	fp.write(time+'\n')
	#元の16進数
	fp.write('元の16進数:'+moji+'\n')
	fp.write('\n')
	#IPヘッダの表示
	fp.write('[IPヘッダ]\n')
	fp.write('IPバージョン:'+ip_version+'\n')
	fp.write('IPヘッダの長さ:'+ip_length_byte+'\n')
	fp.write('サービスタイプ:'+yusen_10+'\n')	
	fp.write('パケット長:'+paketsu_10+'\n')	
	fp.write('ID:'+ip_id_10+'\n')
	fp.write('フラグ:'+frag+'\n')
	fp.write('TTL:'+ttl_10+'\n')
	#プロトコルの判断
	if prot_10 == '6':
		#TCP
		fp.write('プロトコル番号:'+prot+'→ '+'TCP'+'\n')

	elif prot_10 == '17':
		#UDP
		fp.write('プロトコル番号:'+prot+'→ '+'UDP'+'\n')
	else:
		#ICMP
		fp.write('プロトコル番号:'+prot+'→ '+'ICMP'+'\n')
	fp.write('チェックサム:'+ip_checksam+'\n')
	fp.write('送信元IPアドレス:'+ips_10_1+'.'+ips_10_2+'.'+ips_10_3+'.'+ips_10_4+'\n')
	fp.write('送信先IPアドレス:'+ipd_10_1+'.'+ipd_10_2+'.'+ipd_10_3+'.'+ipd_10_4+'\n')
	fp.write('\n')

	#TCPの表示
	if prot_10 == '6':
		fp.write('[TCPヘッダ]\n')
		fp.write('送信元ポート番号:'+source_port_10+'\n')
		fp.write('送信先ポート番号:'+dis_port_10+'\n')
		fp.write('シーケンス番号:'+skensu+'\n')
		fp.write('ACK番号:'+ack+'\n')
		fp.write('データオフセット:'+dataset_byte+'\n')
		fp.write('URG,ACK,PSH,RST,SYN,FIN:'+uaprsf_2_6)
		flag_jude=flag_view(uaprsf_2_6)
		len_s=(len(flag_jude))
		len_str=str(len_s)
		if len_str != '0':
			fp.write('-->')
			for zz in range(len_s):
				ww=flag_jude[zz]
				fp.write(ww+',')
			fp.write('\n')
		else:
			fp.write('\n')
		fp.write('ウィンドウサイズ:'+wsize_10+'\n')
		fp.write('チェックサム:'+cheksam+'\n')
		fp.write('緊急ポインタ:'+escap_pointer_10+'\n')
		#データ部があるかの確認
		if databu == '':
			fp.write('データ部はありません\n')
		else:	
			number_random=str(random.randint(1,5000))
			list_affter=sprie(databu)
			fp.write('データ部はあります'+'->'+'['+number_random+']'+'\n')
			data_write(list_affter,time,databu,number_random)
			sql_data(number_random,time,list_affter)	

	elif prot_10 == '17':
		#UDPの表示
		fp.write('[UDPヘッダ]\n')
		fp.write('送信元ポート番号:'+source_port_10+'\n')
		fp.write('送信先ポート番号:'+dis_port_10+'\n')
		fp.write('UDPのパケット長:'+paket_length_10+'\n')
		fp.write('ヘッダのチェックサム:'+udp_checksam+'\n')
		#データ部があるかの確認（長さが8のときはデータ部がない）
		if paket_length_10 == '8':
			fp.write('データ部はありません\n')
		else:	
			number_random=str(random.randint(1,5000))
			list_affter=sprie(databu)
			fp.write('データ部はあります'+'->'+'['+number_random+']'+'\n')	
			data_write(list_affter,time,databu,number_random)	
			sql_data(number_random,time,list_affter)	
	else:
		#ICMPの表示		
		fp.write('[ICMPヘッダ]\n')
		fp.write('タイプ:'+type_10+'→ '+icmp_1+'\n')
		fp.write('コード:'+code_10+'\n')
		fp.write('チェックサム:'+icmp_checksam+'\n')
		#タイプが8または0ならば
		if type_10 == '0' or type_10 == '8':
			fp.write('ID:'+icmp_id_10+'\n')
			fp.write('シーケンス番号:'+skensu_10+'\n')
			#データ部確認用
			if databu == '':
				fp.write('データ部がありません\n')
			else:
				number_random=str(random.randint(1,5000))
				list_affter=sprie(databu)
				fp.write('データ部はあります'+'->'+'['+number_random+']'+'\n')
				data_write(list_affter,time,databu,number_random)
				sql_data(number_random,time,list_affter)

		#タイプがそれ以外ならば
		else:
			
			if icmp_data == '':
				fp.write('データ部がありません\n')
			else:	
				number_random=str(random.randint(1,5000))
				list_affter=sprie(databu)
				fp.write('データ部はあります'+'->'+'['+number_random+']'+'\n')
				data_write(list_affter,time,databu,number_random)
				sql_data(number_random,time,list_affter)
	fp.write('\n')
	fp.close()

def print_and_accept(pkt):
	
	c=pkt.get_payload()
	print c
	pkt.accept()
	fileout(c)

def main():	
	nfqueue = NetfilterQueue()
	nfqueue.bind(2,print_and_accept)

	try:
		nfqueue.run()

	except KeyboardInterrupt:
		print

main()
