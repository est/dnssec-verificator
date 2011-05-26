#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
File:        test-all.py
Date:        9.4.2011
Author:      Radek Lát, xlatra00@stud.fit.vutbr.cz
Project:     Bachelor thesis:
             Automatic tracking of DNSSEC configuration on DNS servers
Description: Contains negative automated tests for testing options given to
             program over configuration file and --config command line option.  
'''
import unittest
from subprocess import Popen, PIPE
import subprocess

from UnittestHelper import *

class ConfWrongParametersTests(BasicDNSSECTest):
  def testEmptyConfigurationFile(self):
    '''
    Tests running with no parameter.
    '''
    ret = self.runConf(direct_conf="")      
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasNoStderr(ret)
    
class ConfBrokenConfigurationFileTests(BasicDNSSECTest):
  def invalid_format(self, ret):
    '''
    Makes tests from this class shorter.
    '''
    self.assertRunFailed(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: File ") != -1 and 
                    ret.stderr.find("could not be parsed.") != -1, 
                    "Error caused by invalid configuration file format expected:\n" +
                    ret.stderr + "Configuration file:\n" + ret.configuration)
  
  def testMissingParenthesis(self):
    '''
    Tests running with broken configuration file - missing section parenthesis
    '''
    tmp_zone_str = "\ntype=file\nzone=" + self.file_ok + "\ntrust=" + self.file_anchors
    
    self.invalid_format(self.runConf(direct_conf="[general\n[zone]" + tmp_zone_str))
    self.invalid_format(self.runConf(direct_conf="general]\n[zone]" + tmp_zone_str))
    self.invalid_format(self.runConf(direct_conf="[general]\nzone]" + tmp_zone_str))
    self.invalid_format(self.runConf(direct_conf="[general]\n[zone" + tmp_zone_str))
    self.invalid_format(self.runConf(direct_conf="[general]\n[zone]" + tmp_zone_str +
                                     "\nzone]" + tmp_zone_str))
    self.invalid_format(self.runConf(direct_conf="[general]\n[zone]" + tmp_zone_str +
                                     "\n[zone" + tmp_zone_str))
    
  def testVariousBrokenFormat(self):
    '''
    Tests running with broken configuration file - various.  
    '''
    self.invalid_format(self.runConf(direct_conf="[general]\n[zone\ntype]=file\nzone=" + 
                                     self.file_ok + "\ntrust=" + self.file_anchors))
    self.invalid_format(self.runConf(direct_conf="[general]\n[zone]\n=\ntype=file\nzone=" + 
                                     self.file_ok + "\ntrust=" + self.file_anchors))
    self.invalid_format(self.runConf(direct_conf="[general]\n[zone]\n=random\ntype=file\nzone=" + 
                                     self.file_ok + "\ntrust=" + self.file_anchors))    
    self.invalid_format(self.runConf(direct_conf="[general]\n[zone]\n\ttype=file\nzone=" + 
                                     self.file_ok + "\ntrust=" + self.file_anchors))
    self.invalid_format(self.runConf(direct_conf="randomData-ad54ss1|n32afd|n|n123sfgg|nf456321g|nerwojw"))
    
class ConfWrongValuesTests(BasicDNSSECTest):
  def no_value_test(self, ret):
    '''
    Makes testNoValue() shorter.
    '''
    self.assertRunFailed(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: Parameter") != -1, 
                    "Error caused by not giving any value expected:\n" + ret.stderr +
                    "Configuration file:\n" + ret.configuration)
  
  def testNoValue(self):
    '''
    Tests running various parameters with no value.
    '''
    self.no_value_test(self.runConf(type="", input=self.file_ok))
    self.no_value_test(self.runConf(type="file", input=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, level=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, time=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, sformat=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, dformat=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, anchor=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, resolver=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, key=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, bs=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, bw=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, sn=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, check=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, nocheck=""))
    self.no_value_test(self.runConf(type="file", input=self.file_ok, z_enabled=""))
    
  def wrong_value_test(self, ret, expect):
    '''
    Makes testWrongValue() shorter.
    '''
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.find(expect) != -1, 
                    "Error caused by giving wrong value expected:\n" + ret.stderr)
  
  def testWrongValue(self):
    '''
    Tests running various parameters with wrong values.
    '''
    self.wrong_value_test(self.runConf(type="nonsense", input=self.file_ok),
                          "CRITICAL: Source Zone0: Invalid type")
    self.wrong_value_test(self.runConf(type="file", input="ToTaLyR4nD0mNaM3"),
                          "CRITICAL: Source Zone0: Zone master file can't be read. Disabling.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, level="what"),
                          "CRITICAL: Parameter --level has invalid value")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, time="notadate"),
                          "CRITICAL: Parameter --time has invalid value")
    #message format can be broken and cause a lot of exceptions, but there is
    #no way to catch it
    #date format is always valid
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, anchor="ToTaLyR4nD0mNaM3"),
                          'ERROR: No trust anchor was read from file "ToTaLyR4nD0mNaM3".')
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, resolver="abcd"),
                          "CRITICAL: No valid IP address for resolver available.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, resolver='192.168.1.1;abcd'),
                          "CRITICAL: IP address abcd can't be resolved.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, resolver=';'),
                          "CRITICAL: IP address  can't be resolved.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, resolver='abcd;192.168.1.1'),
                          "CRITICAL: IP address abcd can't be resolved.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, key='one two'),
                          "CRITICAL: For using TSIG there has to be specified its name, data and algorithm. Disabling TSIG authentication.")
    self.wrong_value_test(self.runConf(type="axfr", input=self.axfr_sec_domain,
                      anchor=self.axfr_sec_anchor, resolver=self.axfr_sec_resolver,
                      key='"abc def ghi"'), "CRITICAL: Can't start AXFR. Error: Could not create TSIG signature")
    self.wrong_value_test(self.runConf(type="axfr", input=self.axfr_sec_domain,
                      anchor=self.axfr_sec_anchor, resolver=self.axfr_sec_resolver,
                      key='"  "'), "CRITICAL: Can't start AXFR. Error: Could not create TSIG signature")
    self.wrong_value_test(self.runConf(type="axfr", input=self.axfr_sec_domain,
                      anchor=self.axfr_sec_anchor, resolver=self.axfr_sec_resolver,
                      key='examples.com HMAC-SHA1 21pffl6ZCb34t6qKr4mP2A=='), "Error in AXFR: NOTAUTH")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, bs="nan"),
                          "CRITICAL: Parameter buffersize has invalid value")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, bs="-3"),
                          "CRITICAL: Parameter buffersize has invalid value")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, bs="0"),
                          "CRITICAL: Parameter buffersize has invalid value")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, bs='2.3'),
                          "CRITICAL: Parameter buffersize has invalid value")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, bw="nab"),
                          "CRITICAL: Parameter bufferwarn has invalid value")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, check="not_a_option"),
                          "CRITICAL: Check option not_a_option is unknown.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, nocheck="not_a_option"),
                          "CRITICAL: Check option not_a_option is unknown.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, sn="nab"),
                          "CRITICAL: Parameter sncheck has invalid value.")
    self.wrong_value_test(self.runConf(type="file", input=self.file_ok, z_enabled="nab"),
                          "CRITICAL: Parameter enabled has invalid value.")

if __name__ == "__main__":
    unittest.main()