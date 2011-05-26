# -*- coding: utf-8 -*-
'''
File:        test-all.py
Date:        9.4.2011
Author:      Radek Lát, xlatra00@stud.fit.vutbr.cz
Project:     Bachelor thesis:
             Automatic tracking of DNSSEC configuration on DNS servers
Description: Contains negative automated tests for testing command line options.  
'''
import unittest
from subprocess import Popen, PIPE
import subprocess

from UnittestHelper import *
  
class CmdWrongParametersTests(BasicDNSSECTest):
  def testNoParameter(self):
    '''
    Tests running with no parameter.
    '''
    proc = Popen(self.main_programm, shell=True, stdout=PIPE, stderr=PIPE)
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
      
    self.assertRunFailed(ret, 1)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Not enough parameters. Try using -h or --help for list of available parameters.") != -1, 
                    "Error caused by not giving any parameters expected:\n" + ret.stderr)

  def testWrongCaseParameter(self):
    '''
    Tests parameters that are known but in wrong case. They should not pass.
    '''
    ret = self.runCmd(_H=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
    ret = self.runCmd(Help=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
  def testWrongCaseParameterCombination(self):
    '''
    Tests combination of good parameters with a wrong one. They should not pass.
    '''
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"', Help=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"', _H=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"', Level="warning")
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
  def testUnknownParameter(self):
    '''
    Tests parameters that are unknown. They should not pass.
    '''
    ret = self.runCmd(_RandomParameter=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
    ret = self.runCmd(RandomParameter=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
    ret = self.runCmd(RandomParameter="random_value")
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
  def testUnknownParameterCombination(self):
    '''
    Tests parameters that are unknown and in combination with valid ones. They
    should not pass.
    '''
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"', _RandomParameter=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"', RandomParameter=None)
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"', RandomParameter="random_value")
    self.assertRunFailed(ret, 4)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter ") != -1, 
                    "Error caused giving wrong parameters expected:\n" + ret.stderr)
    
class CmdWrongValuesTests(BasicDNSSECTest):
  def no_value_test(self, ret):
    '''
    Makes testNoValue() shorter.
    '''
    self.assertRunFailed(ret, 3)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter") != -1, 
                    "Error caused by not giving any value expected:\n" + ret.stderr)
  
  def testNoValue(self):
    '''
    Tests running various parameters with no value.
    '''
    self.no_value_test(self.runCmd(type="", input=self.file_ok))
    self.no_value_test(self.runCmd(type="file", input=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, config=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, level=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, time=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, sformat=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, dformat=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, anchor=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, resolver=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, key=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, bs=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, bw=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, check=""))
    self.no_value_test(self.runCmd(type="file", input=self.file_ok, nocheck=""))
    
  def wrong_value_test(self, ret, expect):
    '''
    Makes testWrongValue() shorter.
    '''
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find(expect) != -1, 
                    "Error caused by giving wrong value expected:\n" + ret.stderr)
    self.assertTrue(ret.stderr.find("Traceback (most recent call last)") == -1, 
                    "Found some exception:\n" + ret.stderr)
  
  def testWrongValue(self):
    '''
    Tests running various parameters with wrong values.
    '''
    self.wrong_value_test(self.runCmd(type="nonsense", input=self.file_ok),
                          "CRITICAL: Source Zone0: Invalid type")
    self.wrong_value_test(self.runCmd(type="file", input="ToTaLyR4nD0mNaM3"),
                          "CRITICAL: Source Zone0: Zone master file can't be read. Disabling.")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, config="ToTaLyR4nD0mNaM3"),
                          "CRITICAL: File")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, level="what"),
                          "CRITICAL: Parameter --level has invalid value")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, time="notadate"),
                          "CRITICAL: Parameter --time has invalid value")
    #message format can be broken and cause a lot of exceptions, but there is
    #no way to catch it
    #date format is always valid
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, anchor="ToTaLyR4nD0mNaM3"),
                          'ERROR: No trust anchor was read from file "ToTaLyR4nD0mNaM3".')
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, resolver="abcd"),
                          "CRITICAL: No valid IP address for resolver available.")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, resolver='"192.168.1.1;abcd"'),
                          "CRITICAL: IP address abcd can't be resolved.")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, resolver='"abcd;192.168.1.1"'),
                          "CRITICAL: IP address abcd can't be resolved.")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, key='"one two"'),
                          "CRITICAL: For using TSIG there has to be specified its name, data and algorithm. Disabling TSIG authentication.")
    self.wrong_value_test(self.runCmd(type="axfr", input=self.axfr_sec_domain,
                      anchor=self.axfr_sec_anchor, resolver='"' + self.axfr_sec_resolver + '"',
                      key='"abc def ghi"'), "CRITICAL: Can't start AXFR. Error: Could not create TSIG signature")
    self.wrong_value_test(self.runCmd(type="axfr", input=self.axfr_sec_domain,
                      anchor=self.axfr_sec_anchor, resolver='"' + self.axfr_sec_resolver + '"',
                      key='"examples.com HMAC-SHA1 21pffl6ZCb34t6qKr4mP2A=="'), "Error in AXFR: NOTAUTH")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, bs="nan"),
                          "CRITICAL: Parameter --bs has invalid value")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, bs="-3"),
                          "CRITICAL: Parameter --bs has invalid value")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, bs="0"),
                          "CRITICAL: Parameter --bs has invalid value")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, bs='"2.3"'),
                          "CRITICAL: Parameter --bs has invalid value")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, bw="nab"),
                          "CRITICAL: Parameter --bs has invalid value")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, check="not_a_option"),
                          "CRITICAL: Check option not_a_option is unknown.")
    self.wrong_value_test(self.runCmd(type="file", input=self.file_ok, nocheck="not_a_option"),
                          "CRITICAL: Check option not_a_option is unknown.")

if __name__ == "__main__":
    unittest.main()