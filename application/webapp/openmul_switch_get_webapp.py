#!/usr/bin/python

#
# A simple application which utilizes OpenMUL RESTful APIs
# 

import requests, json, sys

http = 'http'
v=True
ip = 'localhost'
port = '8181'
for arg in sys.argv:
    if 'https' in arg:
        http = "https"
        v=False
    elif arg.startswith('port='):
        port = arg.replace('port=','')
    elif arg.startswith('ip='):
        ip = arg.replace('ip=','')
base = http+"://"+ip+":"+port+"/1.0/"

r=requests.get(base+'topology',verify=v)
print r.text
r=requests.get(base+'topology/switch',verify=v)
print r.text
dpid = json.loads(r.text)['switches'][0]['dpid']
print "============dpid : "+dpid+"==============="
r=requests.get(base+'topology/switch/'+dpid,verify=v)
print r.text
r=requests.get(base+'topology/switch/'+dpid+'/port',verify=v)
portno=json.loads(r.text)['ports'][0]['port_no']
print "=============portno : "+str(portno)+"=============="
print r.text
r=requests.get(base+'topology/switch/'+dpid+'/port/'+str(portno),verify=v)
print r.text
r=requests.get(base+'topology/switch/'+dpid+'/meter',verify=v)
print r.text
r=requests.get(base+'topology/switch/'+dpid+'/group',verify=v)
print r.text
r=requests.get(base+'topology/switch/'+dpid+'/table/0',verify=v)
print r.text
r=requests.get(base+'topology/switch/'+dpid+'/limit',verify=v)
print r.text
r=requests.get(base+'flowtable/'+dpid+'/flow',verify=v)
print r.text
flowid=json.loads(r.text)['flows'][0]['flow_id']
print "======================================="
print "flowid : "+flowid
print "======================================="
print flowid
r=requests.get(base+'flowtable/'+dpid+'/flow/'+flowid,verify=v)
print r.text
r=requests.get(base+'stats/switch/'+dpid+'/flow/'+flowid,verify=v)
print r.text
r=requests.get(base+'stats/switch/'+dpid+'/port/'+str(portno),verify=v)
print r.text
r=requests.get(base+'topology/switch/'+dpid+'/neighbor',verify=v)
print r.text
r=requests.get(base+'stats/switch/'+dpid+'/flow/'+flowid,verify=v)
print r.text
r=requests.get(base+'stats/switch/'+dpid+'/port/'+str(portno),verify=v)
print r.text
