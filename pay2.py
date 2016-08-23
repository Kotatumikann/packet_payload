#_*_coding: utf-8 -*-
from datetime import datetime
from netfilterqueue import NetfilterQueue
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
		#ウィンドウサイズ
		wsize=moji[68:72]
		wsize_10=str(int(wsize,16))
		#チェックサム
		cheksam=moji[72:76]
		#緊急ポインタ
		escap_pointer=moji[76:80]
		escap_pointer_10=str(int(escap_pointer,16))
		#データ部の確認用
		tcp_databu=moji[80:]

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
		udp_databu=moji[56:]
	else:
		#ICMP	
		#タイプ
		type_16=moji[40:42]
		type_10=str(int(type_16,16))
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
			icmp_data=moji[56:]
		else:
		#タイプが0,8以外ならば
			icmp_data=moji[48:]

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
		fp.write('URG,ACK,PSH,RST,SYN,FIN:'+uaprsf+'\n')
		fp.write('ウィンドウサイズ:'+wsize_10+'\n')
		fp.write('チェックサム:'+cheksam+'\n')
		fp.write('緊急ポインタ:'+escap_pointer_10+'\n')
		#データ部があるかの確認
		if tcp_databu == '':
			fp.write('データ部はありません\n')
		else:
			fp.write('データ部:'+tcp_databu+'\n')
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
			fp.write('データ部:'+udp_databu+'\n')
	else:
		#ICMPの表示		
		fp.write('[ICMPヘッダ]\n')
		fp.write('タイプ:'+type_10+'\n')
		fp.write('コード:'+code_10+'\n')
		fp.write('チェックサム:'+icmp_checksam+'\n')
		#タイプが8または0ならば
		if type_10 == '0' or type_10 == '8':
			fp.write('ID:'+icmp_id_10+'\n')
			fp.write('シーケンス番号:'+skensu_10+'\n')
			#データ部確認用
			if icmp_data == '':
				fp.write('データ部がありません\n')
			else:
				fp.write('データ部:'+icmp_data+'\n')
		#タイプがそれ以外ならば
		else:
			
			if icmp_data == '':
				fp.write('データ部がありません\n')
			else:
				fp.write('データ部:'+icmp_data+'\n')

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
