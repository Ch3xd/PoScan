# -*- coding: utf-8 -*-
import nmap
import argparse
from tqdm import tqdm
from queue import Queue
from socket import socket
from socket import AF_INET
from socket import SOCK_STREAM
from banner import banner
from prettytable import PrettyTable
from concurrent.futures import ThreadPoolExecutor, as_completed


# socket连接判断ip端口号是否存在
def connect_port(host_port):
    try:
        s = socket(AF_INET, SOCK_STREAM)  # 定义socket类型，网络通信，TCP
        s.connect(host_port)
        peername = s.getpeername()
        s.close()
        return peername
    except Exception as e:
        return False


# 扫描TCP端口的信息
def scanTcp_port_info(ip, port_list):
    ports = ','.join(port_list)
    nm = nmap.PortScanner()
    nm.scan(ip, ports, '-sV')
    port_dict = {}
    if nm.all_hosts():
        for port in port_list:
            port_dict[port] = nm[ip].tcp(int(port))
        return port_dict
    return {}


# 多线程扫描端口函数
def scan_port_main(arg):
    host = args.target
    q = Queue()
    # 全端口扫描
    total_len = 0
    if args.scanType == 'all':
        for port in range(0,65536):
            q.put((host, port))
        total_len = 65536
    elif args.scanType == 'common':
    # 常用端口扫描
        commonly_ports = [21,22,23,25,53,69,80,81,88,110,111,123,135,137,139,161,177,389,427,443,445,465,500,515,520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375,2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848,37777,50000,50070,61616]
        for port in commonly_ports:
            q.put((host, port))
        total_len = len(commonly_ports)
    # 数据库端口
    elif args.scanType == 'database':
        databases_ports = [523,1433,1434,1521,1583,2100,2049,2638,3050,3306,3351,5000,5432,5433,5601,5984,6082,6379,7474,8080,8088,8089,8098,8471,9000,9160,9200,9300,9471,11211,15672,19888,27017,27019,27080,28017,50000,50070,50090]
        for port in databases_ports:
            q.put((host, port))
        total_len = len(databases_ports)
    else:
        print('[\033[1;31mERROR\033[0m] Parameter Value Error.')
        exit()
    print(banner)
    print(f'[\033[1;35mINFO\033[0m] Port Scan report for {host}')
    print(f'[\033[1;35mINFO\033[0m] Scanning Select \033[1;31m{args.scanType}\033[0m type and \033[1;31m{args.threads}\033[0m threads.')
    open_port = []
    if args.info:
        total_len = total_len + 1
    pbar = tqdm(total=total_len,ascii=False,desc='PortScan',ncols=70)    #设置进度条总长度
    with ThreadPoolExecutor(max_workers=args.threads) as executor:  # 默认设置370个线程
        future_list = []
        while not q.empty():
            reslts = executor.submit(connect_port, q.get())
            future_list.append(reslts)
        #
        for future in as_completed(future_list):
            result = future.result()
            if result != False:
                pbar.write('[\033[1;32mScan\033[0m] {} {}'.format(result[0],result[1]))   #解决tqdm与print的冲突问题,使用tqdm自带的write方法
                open_port.append(result)
            pbar.update()   #更新进度条

    pbar.write('[\033[1;35mINFO\033[0m] Port Scan complete.')
    pbar.write('[\033[1;35mINFO\033[0m] Nmap Scan Port Info....')
    # 扫描对应端口的信息
    ip = ''
    port_list = []
    for peername in open_port:
        ip = peername[0]
        port_list.append(str(peername[1]))
    # 使用nmap扫描端口信息
    if args.info:
        port_info_dict = scanTcp_port_info(ip, port_list)
        if port_info_dict:
            pt = PrettyTable()
            pt.border = 0   #去掉边框
            pt.field_names = ['PORT', 'STATE', 'SERVICE', 'VERSION']
            for port, port_info in port_info_dict.items():
                pt.add_row([f'{port}/tcp', port_info['state'], port_info['name'], port_info['version']])
            pt.align = 'l'  # l=left,r=rigt,设置对齐方式
            pbar.update()   #更新进度条
            pbar.write('[\033[1;35mINFO\033[0m] Nmap Scan Port Info End.')
            pbar.write(str(pt))
        else:
            pbar.write('[\033[1;33mINFO\033[0m] Nmap No information scanned?')



# 测试函数
if __name__ == "__main__":
    usage = "python3 PoScan.py [options]"
    parser = argparse.ArgumentParser(prog='Pocsuite3', usage=usage)
    parser.add_argument("-tg", dest="target", type=str, default='',
                              help="Scan target address (default null)")
    parser.add_argument("-thread", dest="threads", type=int, default=370,
                              help="Max number of threads (default 370)")
    parser.add_argument("-type", dest="scanType", type=str, default='common',
                              help="Scan port type,(common, database, all) (default common)")
    parser.add_argument("-info", dest="info", type=int, default=1,
                              help="Port information (default 1)")
    args = parser.parse_args()
    if args.target:
        scan_port_main(args)
    else:
        print('usage: python3 PoScan.py -h[--help]')
