#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
File:        test-all.py
Date:        9.4.2011
Author:      Radek Lát, xlatra00@stud.fit.vutbr.cz
Project:     Bachelor thesis:
             Automatic tracking of DNSSEC configuration on DNS servers
Description: Contains load tests for testing program memory allocation and run
             length.
'''

import sys
from subprocess import Popen, PIPE
from time import sleep, time
from multiprocessing import Process, Value

def runCmd(memory_peak, test_title, **options):
  '''
  Runs program with given command line options and waits for it to end. Logs
  how long program runs and how many memory consumes.
  
  If parameter starts with single "_", it is assumed that there should be "_"
  changed to "-" (otherwise "--" prepended). If value is None, the result will
  be option without "=".
  
  Special parameter repeat will be used to repeat run N times. Default is 3.
  
  If specified parameter "add_after", its content will be added after command
  line options as is.
  '''
  param_list = ""
  main_programm = "python Main.py"
  mem_append = " | tail -n 1"
  
  #make a list of parameters
  for key in options.keys():
    if key == "repeat":
      continue
    
    if len(key) >= 2 and key[0] == '_' and key[1] != '_':
      param_list += ' -' + key[1:]
    else:
      param_list += ' --' + key
      
    if options[key] is not None:
      param_list += '=' + str(options[key])
  
  total_time = 0
  total_memory = 0
  repeat_cnt = int(options.get("repeat", 3))
  
  print '{: <20}\t'.format(test_title),
  sys.stdout.flush()

  devnull = open("/dev/null", "w")
  
  #repeat run N times
  for i in range(1, repeat_cnt + 1):
    #print start info
    #if i == 1:
      #print main_programm + param_list
  
    #get before values
    before_memory = getMemoryLoad()
    before_time = time()
    memory_peak.value = 0 #reset
        
    #open program and get its result
    proc = Popen(main_programm + param_list + mem_append, shell=True, stdout=PIPE, stderr=devnull)
    ret = proc.communicate()[0]
    
    after_time = time()
    after_memory = memory_peak.value
    
    overall_time = after_time - before_time
    overall_memory = (after_memory - before_memory) / 1024.0
    
    total_time += overall_time
    total_memory += overall_memory
    
    print '{:.2f}\t{:.2f}\t'.format(overall_time, overall_memory),
    sys.stdout.flush()
    
  print '{:.2f}\t{:.2f}\n'.format(total_time/float(repeat_cnt),
                                  total_memory/float(repeat_cnt)),
  sys.stdout.flush()                                
          
def getMemoryLoad():
  '''
  Gets current memory load.
  '''
  proc = Popen("free -t | grep Total | sed 's/Total: *[0-9]* *\\([0-9]*\).*/\\1/'", stdout=PIPE, shell=True)
  mem = proc.communicate()[0]
  return int(mem[:-1])

def logMemoryLoad(peak_memory):
  '''
  Periodically checks memory allocation and logs peak values. If memory
  allocation gets 10MB below last value, it gets recorded as peak value.
  '''
  last_val = 0
  last_max = 0
  #run forever
  while True:
    mem = getMemoryLoad()
    
    if mem > peak_memory.value:
      peak_memory.value = mem

    sleep(0.25)

def runTests(peak_memory, test_zone, anchors, repeat_cnt = 3):
  '''
  Runs series of tests on program using given test zone master file. Option
  repeat_cnt determines how many time should be each test repeated. On the
  output are written memory allocation and run length for each repetition and
  average for all of them.
  '''
  print '{: <20}\t'.format("Test name"),
  
  for i in range(1, int(repeat_cnt) + 1):
    print "Time" + str(i) + "\tMem" + str(i) + "\t",
    
  print "TimeAvg\tMemAvg\n",
  
  runCmd(peak_memory, 'Empty check',input='"' + test_zone + '"', type="file",
         anchor=anchors, repeat=repeat_cnt, check='" "',
	 time='"2011-02-28 12:00:00"', bw="0")

  runCmd(peak_memory, 'Full check', input='"' + test_zone + '"', type="file",
         anchor=anchors, repeat=repeat_cnt, time='"2011-02-28 12:00:00"',
         bs="1000")
  
  runCmd(peak_memory, 'Common check',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check='"RRSIG;RRSIG_T;DS"',
         time='"2011-02-28 12:00:00"', bw="0", bs="10")
  
  runCmd(peak_memory, 'DS', input='"' + test_zone + '"', type="file",
         anchor=anchors, repeat=repeat_cnt, check="DS",
         time='"2011-02-28 12:00:00"', bw="0")
  
  runCmd(peak_memory, 'Buffer warning', input='"' + test_zone + '"',
         type="file", anchor=anchors, repeat=repeat_cnt, check='" "',
         time='"2011-02-28 12:00:00"', bw="1")
  
  runCmd(peak_memory, 'Buffer size 10',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check='" "', time='"2011-02-28 12:00:00"', bw="0", bs="10")

  runCmd(peak_memory, 'Buffer size 100',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check='" "', time='"2011-02-28 12:00:00"', bw="0", bs="100")
  
  runCmd(peak_memory, 'Buffer size 1 000',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check='" "', time='"2011-02-28 12:00:00"', bw="0", bs="1000")
  
  runCmd(peak_memory, 'Buffer size 10 000',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check='" "', time='"2011-02-28 12:00:00"', bw="0", bs="10000")
  
  runCmd(peak_memory, 'Buffer size 100 000',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check='" "', time='"2011-02-28 12:00:00"', bw="0", bs="100000")
  
  runCmd(peak_memory, 'RRSIG',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check="RRSIG", time='"2011-02-28 12:00:00"', bw="0")
  
  runCmd(peak_memory, 'RRSIG_T',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check="RRSIG_T", time='"2011-02-28 12:00:00"', bw="0")

  runCmd(peak_memory, 'RRSIG_A',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check="RRSIG_A", time='"2011-02-28 12:00:00"', bw="0")
  
  runCmd(peak_memory, 'RRSIG_S',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check="RRSIG_S", time='"2011-02-28 12:00:00"', bw="0")
  
  runCmd(peak_memory, 'NSEC',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check="NSEC", time='"2011-02-28 12:00:00"', bw="0")
  
  runCmd(peak_memory, 'NSEC_S',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check="NSEC_S", time='"2011-02-28 12:00:00"', bw="0")
  
  runCmd(peak_memory, 'TTL',
         input='"' + test_zone + '"', type="file", anchor=anchors,
         repeat=repeat_cnt, check="TTL", time='"2011-02-28 12:00:00"', bw="0")
  
  
if __name__ == '__main__':
    if len(sys.argv) < 4:
      print >>sys.stderr, "Script requires test zone name, trust anchor file and test repetition count as parameters."
    else:
      memory_peak = Value('d', 0.0)
      mem_log_proc = Process(target=logMemoryLoad, args=(memory_peak,))
      mem_log_proc.start()
      
      runTests(memory_peak, sys.argv[1], sys.argv[2], sys.argv[3])
      
      mem_log_proc.terminate()
