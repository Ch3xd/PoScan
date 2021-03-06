# PoScan

## Project introduction

使用socket和nmap相结合，并使用多线程的方式实现的端口扫描器。

一个有三种扫描模式：常用端口（默认）、数据库端口、全部端口65535

- common
- database
- all

```shell
$ python3 PoScan.py -tg 192.168.1.1 -type common
$ python3 PoScan.py -tg 192.168.1.1 -type database
$ python3 PoScan.py -tg 192.168.1.1 -type all
```
缺点: 目标有防火墙的情况下可能无法探测到信息


## Installation

Liunx/window

```shell
$ git clone https://github.com/Ch3xd/PoScan.git
$ cd PoScan
$ pip3 install -r requirements.txt
```

## Usage

```shell
python3 PoScan.py -h
usage: python3 PoScan.py [options]

optional arguments:
  -h, --help       show this help message and exit
  -tg TARGET       Scan target address (default null)
  -thread THREADS  Max number of threads (default 370)
  -type SCANTYPE   Scan port type,(common, database, all) (default all)
  -info INFO       Port information (default 1)
  
##################
# Usage Examples #
##################
$ python3 PoScan.py -tg 192.168.1.1 -type all
```

## Demo
![image](https://user-images.githubusercontent.com/82303088/154834709-7a166f26-d03d-428f-b4b2-077e6f7b4ecc.png)

## 法律免责声明

未经事先双方同意，使用 PoScan 攻击目标是非法的。 PoScan 仅用于安全测试目的
