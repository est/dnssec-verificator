#! /usr/bin/env python
import ldns
import sys
from subprocess import Popen, PIPE

fp = open(sys.argv[1], "r")

proc = Popen("free -t | grep Total", stdout=PIPE, shell=True)
mem = proc.communicate()[0]
mem1 = int(mem.split(" ")[-1])

while True:
  ret = ldns.ldns_rr_new_frm_fp_l_(fp, 0, None, None, False)
    
  if not ret:
    break
  
  status = ret[0]
  rr = ret[1]
  
  ##### tested part START
  rrl = ldns.ldns_rr_list() #prepare RR for verification function
  rrl.push_rr(rr)
  ##### tested part END

  if status == ldns.LDNS_STATUS_SYNTAX_EMPTY: #reading finished
    break          
  elif status != ldns.LDNS_STATUS_OK:
    raise Exception("Error while reading from zone master file (errno = " + str(status) + ").")

proc = Popen("free -t | grep Total", stdout=PIPE, shell=True)
mem = proc.communicate()[0]
mem2 = int(mem.split(" ")[-1])
print str((mem1 - mem2) / 1024) + "M of memory consumed"
