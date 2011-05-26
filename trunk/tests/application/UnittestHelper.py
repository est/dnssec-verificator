#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
File:        Unittest helper.py
Date:        15.4.2011
Author:      Radek Lát, xlatra00@stud.fit.vutbr.cz
Project:     Bachelor thesis:
             Automatic tracking of DNSSEC configuration on DNS servers
Description: Contains helper classes for executing automated tests.  
'''
import unittest
from subprocess import Popen, PIPE
import os

class BasicDNSSECTest(unittest.TestCase):
  '''
  Basic class of unittest TestCase that provides high level functions and is
  intended to be inherited by new classes, that will contain actual test cases.
  '''
  
  main_programm = "python Main.py"
  file_ok = "a.example.com.db.signed"
  file_bad = "a.example.com.db.signed.broken"
  file_anchors = "anch1;anch2;anch3"
  axfr_resolver = '192.168.1.222;192.168.1.199'
  axfr_domain = "a.example.com"
  axfr_anchor = "anch1"
  axfr_sec_resolver = '192.168.1.199'
  axfr_sec_domain = "example.com"
  axfr_sec_anchor = "Kexample.com.+005+37447.key"
  axfr_sec_key='example.com HMAC-SHA1 21pffl6ZCb34t6qKr4mP2A=='
  def_time = "2011-04-10 12:00:00"
  
  SECTION_GENERAL = "general"
  SECTION_ZONE = "Zone0"
  TMP_CONF = "/tmp/temporary_configuration_file"
  
  cmd_map = { "--level": ("outputLevel", SECTION_GENERAL), "--time": ("time", SECTION_GENERAL),
             "--sformat": ("outputFormat", SECTION_GENERAL), "--dformat": ("outputFormatDate", SECTION_GENERAL),
             "--type": ("type", SECTION_ZONE), "--input": ("zone", SECTION_ZONE),
             "--anchor": ("trust", SECTION_ZONE), "--resolver": ("resolver", SECTION_ZONE),
             "--key": ("key", SECTION_ZONE), "--bs": ("buffersize", SECTION_ZONE),
             "--bw": ("bufferwarn", SECTION_ZONE), "--sn": ("sncheck", SECTION_ZONE),
             "--check": ("check", SECTION_ZONE), "--nocheck": ("nocheck", SECTION_ZONE) }
  
  def runCmd(self, **options):
    '''
    Runs program with given command line options and waits for it to end.
    
    If parameter starts with single "_", it is assumed that there should be "_"
    changed to "-" (otherwise "--" prepended). If value is None, the result will
    be option without "=".
    
    If specified parameter "add_after", its content will be added after command
    line options as is.
    
    If parameter "time" not specified, there will be used custom static date.
    
    Returns an object with attributes return_code, stdout and stderr.
    '''
    param_list = ""
    
    if "time" not in options.keys(): #if no custom time specified, use fixed
      options["time"] = '"' + self.def_time + '"'
    
    #make a list of parameters
    for key in options.keys():
      if key == "add_after":
        continue
      
      if len(key) >= 2 and key[0] == '_' and key[1] != '_':
        param_list += ' -' + key[1:]
      else:
        param_list += ' --' + key
        
      if options[key] is not None:
        param_list += '=' + str(options[key])
        
    param_list += options.get("add_after", "")
        
    #open program and get its result
    print self.main_programm + param_list
    proc = Popen(self.main_programm + param_list, shell=True, stdout=PIPE, stderr=PIPE)
    output = proc.communicate()
    
    #create return class
    class Proc:
      pass
    
    ret = Proc()
    ret.return_code = proc.returncode
    
    if output is not None:
      ret.stdout = output[0]
      ret.stderr = output[1]
    else:
      ret.stdout = None
      ret.stderr = None
      
    return ret
  
  def runConf(self, **options):
    '''
    Creates file with given options, then runs program with this file as option
    --config and waits for it to end. The configuration file is created and
    deleted in every run.
    
    If parameter starts with "g_", it is assumed that these are parameters
    from [general] section of configuration file. If parameter starts with "z_",
    it is assumed that these are parameters from [zone] section. Otherwise
    parameters are assumed to have the same names as when using runCmd()
    function. They are mapped automatically to appropriate keys and a
    KeyError exception is raised, when a parameter can't be mapped.
    
    Value None is not allowed here as all options in configuration file have to
    have some value. ValueError exception will be raised if None used.
    
    If specified parameter "add_after", its content will be added after command
    line options as is. If parameter "direct_conf" specified, all other
    parameters will be unused (except "add_after") and content of this one will
    be used as configuration file content.
    
    If parameter "time" not specified, there will be used custom static date.
    
    Returns an object with attributes return_code, stdout, stderr and
    configuration.
    
    WARNING: There is not check on duplicate parameters. If specified "time" and
    "g_time", they will both be translated to "time" and both used.
    '''
    param_list_general = "[" + self.SECTION_GENERAL + "]\n"
    param_list_zone = "[" + self.SECTION_ZONE + "]\n"
    
    if "time" not in options.keys(): #if no custom time specified, use fixed
      options["time"] = '2011-04-10 12:00:00'
    
    if options.has_key("direct_conf"):
      conf_file = options["direct_conf"]
    else:
      #make a list of parameters if needed
      for key in options.keys():
        if options[key] is None:
          raise ValueError("Value None is not allowed for configuration file option.")
            
        if key == "add_after":
          continue
        
        if key.upper().startswith("G_"): #general section
          conf_key = key[2:] #strip g
          conf_section = self.SECTION_GENERAL
        elif key.upper().startswith("Z_"): #zone section
          conf_key = key[2:] #strip z_
          conf_section = self.SECTION_ZONE
        else: #mapped key, section not known yet
          #this will raise KeyError when not known
          if len(key) >= 2 and key[0] == '_' and key[1] != '_':
            conf_key, conf_section = self.cmd_map["-" + key[1:]] #strip underscore
          else:
            conf_key, conf_section = self.cmd_map["--" + key]
            
        if conf_section == self.SECTION_GENERAL:
          param_list_general += conf_key + "=" + options[key] + "\n"
        else:
          param_list_zone += conf_key + "=" + options[key] + "\n"
  
      conf_file = param_list_general + "\n" + param_list_zone
    
    #create temporary configuration file
    tmp_file = open(self.TMP_CONF, "w")
    tmp_file.write(conf_file)
    tmp_file.close()
        
    #open program and get its result
    print self.main_programm + " --config=" + self.TMP_CONF + options.get("add_after", "")
    #print conf_file.replace("\n", ", ") #printing what is in configuration file
    proc = Popen(self.main_programm + " --config=" + self.TMP_CONF +
                 options.get("add_after", ""), shell=True, stdout=PIPE,
                 stderr=PIPE)
    output = proc.communicate()
    
    os.remove(self.TMP_CONF) #remove temporary configuration file
    
    #create return class
    class Proc:
      def __eq__(self, other):
        return self.return_code == other.return_code and self.stderr == other.stderr and\
          self.stdout == other.stdout      
    
    ret = Proc()
    ret.return_code = proc.returncode
    ret.configuration = conf_file
    
    if output is not None:
      ret.stdout = output[0]
      ret.stderr = output[1]
    else:
      ret.stdout = None
      ret.stderr = None
      
    return ret
  
  def assertNoException(self, check_str):
    '''
    Verifies that in given string is no exception present.
    '''
    self.assertTrue(check_str.find("Traceback (most recent call last):") == -1,
                    "Unexpected exception found:\n" + check_str)
  
  def assertHasStdout(self, procObject):
    '''
    Verifies that object of Proc class with attribute stdout has that attribute
    not None and not empty. Also verifies, that there is no exception raised.
    '''
    self.assertTrue(procObject.stdout is not None and len(procObject.stdout) > 0, 
                    "There is nothing on stdout.")
    self.assertNoException(procObject.stdout)
                    
  def assertHasStderr(self, procObject):
    '''
    Verifies that object of Proc class with attribute stderr has that attribute
    not None and not empty. Also verifies, that there is no exception raised.
    '''
    self.assertTrue(procObject.stderr is not None and len(procObject.stderr) > 0,
                    "There is nothing on stderr.")
    self.assertNoException(procObject.stderr)
    
  def assertHasNoStdout(self, procObject):
    '''
    Verifies that object of Proc class with attribute stdout has that attribute
    None or empty.
    '''
    self.assertTrue(procObject.stdout is None or len(procObject.stdout) == 0,
                    "There is something on stdout:\n" + str(procObject.stdout))
    
  def assertHasNoStderr(self, procObject):
    '''
    Verifies that object of Proc class with attribute stderr has that attribute
    None or empty.
    '''
    self.assertTrue(procObject.stderr is None or len(procObject.stderr) == 0,
                    "There is something on stderr:\n" + str(procObject.stderr))
    
  def assertRunOK(self, procObject):
    '''
    Verifies that object of Proc class with attribute return_code has that
    attribute equal to 0.
    '''
    self.assertTrue(procObject.return_code == 0, "Program execution failed. Returns code " + 
                    str(procObject.return_code) + ".\n" + str(procObject.stderr))
    
  def assertRunFailed(self, procObject, code=None):
    '''
    Verifies that object of Proc class with attribute return_code has that
    attribute not equal to 0. Optionally can be specified specific return code
    that is expected.
    '''    
    if code is None:
      self.assertTrue(procObject.return_code != 0, "Program execution should failed. " + 
                      str(procObject.stdout))
    else:
      self.assertTrue(procObject.return_code == code, "Program execution should failed with code " + 
                      str(code) + ", not " + str(procObject.return_code) + ".\n" +
                      str(procObject.stdout))
    
class OutputDNSSECTest(BasicDNSSECTest):
  '''
  Adds high level function for testing correctness of output values.
  '''
  list_RRSIG = ["ERROR: Signatures check - test12.a.example.com. A",
               "ERROR: Signatures check - a.example.com. SOA",
               "INFO: Signatures check - test3.a.example.com. NSEC - 1 RRs, 2 RRSIGs, 1 valid",
               "INFO: Signatures check - test2.a.example.com. A - 1 RRs, 2 RRSIGs, all valid",
               "INFO: Signatures check - test4.a.example.com. NSEC - 1 RRs not secured",
               "ERROR: Signatures check - test3.a.example.com. A - RRSIGs Signers Name does not match domain (example.com. != a.example.com.)"]
  
  list_RRSIG_T = ["ERROR: Signatures time check - test1.a.example.com.",
                  "test1.a.example.com. 4 total, 1 valid, 2 old, 1 future",
                  "INFO: Signatures time check - a.example.com. SOA - 2 total, 2 valid, 0 old, 0 future"]
  
  list_RRSIG_A = ["WARNING: test4.a.example.com. - RSASHA512 algorithm not used for creating RRSIG"]
  
  list_RRSIG_S = ["Statistics - RRSIG signing algorithm usage",
                  "Algorithm RSAMD5 is deprecated"]
  
  list_NSEC = ["ERROR: test11.a.example.com. MX type present in NSEC but does not exist",
               "ERROR: test6.a.example.com. A type not present in NSEC",
               "ERROR: test5.a.example.com. NSEC type record not present",
               "INFO: a.example.com. NSEC record type coverage OK (NS SOA MX RRSIG NSEC DNSKEY)"]
  
  list_NSEC_S = ["Statistics - NSEC usage"]
  
  list_TTL = ["WARNING: test1.a.example.com. RRSIG Remaining validity time of RRSIG is too low (0 <",
              "WARNING: test9.a.example.com. RRSIG Remaining validity time of RRSIG is too low",
              "WARNING: test2.a.example.com. NSEC - TTL of RRSIG does not match TTL of RR it covers",
              "WARNING: test14.a.example.com. A - TTL of RRSIG does not match TTL of RR it covers",
              "WARNING: test13.a.example.com. A - Original TTL of RRSIG does not match TTL of RR it covers",
              "WARNING: test14.a.example.com. A - TTL of RRSIG does not match TTL of RR it covers",
              "WARNING: Minimum TTL from SOA should not be lower than 5-10 minutes(600 s), to ensure successful verification of signatures. Current value is 500",
              "WARNING: test10.a.example.com. A - TTL of the RRSIG record should be lower, than the total validity time"]
  
  def generalChecklist(self, runFunction, listType, listOptions, expectToSee = None, expectNotToSee = None,
                       expectInverse = False):
    '''
    Tests reading zone from file with --check or --nocheck option (use check or
    nocheck as listType), and its value in listOptions.
    
    Checks if all values from expectToSee list are present in output on stderr
    and all values from expectNotToSee are not. If expectInverse is set to True,
    meaning of expectToSee and expectNotToSee will be swapped.
    
    runFunction parametr should contain one of these: self.runCmd, self.runConf.
    
    Uses debug severity to get all output possible.
    '''
    delim = ''
    if runFunction == self.runCmd:
      delim = '"'
    
    if listType == "check":
      ret = runFunction(type="file", input=self.file_bad, anchor=delim + self.file_anchors + delim,
                        level="debug", check=delim + listOptions + delim)
    elif listType == "nocheck":
      ret = runFunction(type="file", input=self.file_bad, anchor=delim + self.file_anchors + delim,
                        level="debug", nocheck=delim + listOptions + delim)
    else:
      raise ValueError("Unknown check type: " + str(listType))
      
    self.assertRunOK(ret)
    
    output = ret.stdout+ret.stderr
    str_not = " not"
    str_yes = ""
    
    #swap meaning
    if expectInverse:
      tmp = expectToSee
      expectToSee = expectNotToSee
      expectNotToSee = tmp
      str_not = ""
      str_yes = " not"
    
    if expectToSee is not None:
      for val in expectToSee:
        self.assertTrue(output.find(val) != -1, "String \"" + val +
                        '"' + str_not + " found in output:\n" + output)
        
    if expectNotToSee is not None:
      for val in expectNotToSee:
        self.assertTrue(output.find(val) == -1, "String \"" + val +
                        '"' + str_yes + " found in output:\n" + output)