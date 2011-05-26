#! /usr/bin/env python
import ldns
import sys
from subprocess import Popen, PIPE

def dummy(p1):
  p1.values()

fp = open(sys.argv[1], "r")
lastowner = "."

proc = Popen("free -t | grep Total", stdout=PIPE, shell=True)
mem = proc.communicate()[0]
mem1 = int(mem.split(" ")[-1])

while True:
  tmp_dict= {}
  newowner = ldns.ldns_rdf.new_frm_str(lastowner, ldns.LDNS_RDF_TYPE_DNAME)
  ret = ldns.ldns_rr_new_frm_fp_l_(fp, 0, newowner, newowner, False)
    
  if not ret:
    break
  
  status = ret[0]
  rr = ret[1]
  
  if status == ldns.LDNS_STATUS_SYNTAX_EMPTY: #reading finished
    break          
  elif status != ldns.LDNS_STATUS_OK:
    raise Exception("Error while reading from zone master file (errno = " + str(status) + ").")

  tmp_dict[rr.get_type()] = rr
  dummy(tmp_dict)
    
  lastowner = str(rr.owner())

proc = Popen("free -t | grep Total", stdout=PIPE, shell=True)
mem = proc.communicate()[0]
mem2 = int(mem.split(" ")[-1])
print str((mem1 - mem2) / 1024) + "M of memory consumed"
