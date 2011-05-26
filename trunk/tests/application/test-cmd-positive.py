# -*- coding: utf-8 -*-
'''
File:        test-all.py
Date:        9.4.2011
Author:      Radek Lát, xlatra00@stud.fit.vutbr.cz
Project:     Bachelor thesis:
             Automatic tracking of DNSSEC configuration on DNS servers
Description: Contains positive automated tests for testing command line options.  
'''
import unittest
from subprocess import Popen, PIPE
import subprocess

from UnittestHelper import *
  
class CmdHelpTests(BasicDNSSECTest):
  def testHelpShort(self):
    '''
    Tests parametr -h.
    '''
    ret = self.runCmd(_h=None)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
  
  def testHelpLong(self):
    '''
    Tests parametr --help.
    '''
    ret = self.runCmd(help=None)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testHelpCombination(self):
    '''
    Tests parametr --help and its combination with other paramters. The result
    should be the same as -h or --help alone.
    '''
    help_content = self.runCmd(help=None).stdout
    ret = self.runCmd(help=None, sn=None)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
    self.assertTrue(ret.stdout == help_content, 
                    "Output is not the same as with parameters -h or --help alone:\n" +
                    ret.stdout)
    
class CmdDateFormatTests(BasicDNSSECTest):
  def testDateFormatDefault(self):
    '''
    Tests if date is in default format and correct.
    '''
    #get current date
    proc = Popen('date "+%Y-%m-%d %H:%M:%S"', shell=True, stdout=PIPE, stderr=PIPE)
    cur_date = proc.communicate()[0][:-1]
    
    ret = self.runCmd(nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    
    ret_date = " ".join(ret.stderr.split(" ")[:2])
    self.assertTrue(ret_date == cur_date,
                    "Default time format might be broken. This may be caused " +
                    "by time delay. \"" + ret_date + '" != "' + cur_date + '".')
    
  def testDateFormatCustom(self):
    '''
    Tests if date is in custom format correct.
    '''
    #get current date
    proc = Popen('date "+%d.%m. %Y %H::%M::%S"', shell=True, stdout=PIPE, stderr=PIPE)
    cur_date= proc.communicate()[0][:-1]
    
    ret = self.runCmd(dformat='"%d.%m. %Y %H::%M::%S"', nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    
    ret_date = " ".join(ret.stderr.split(" ")[:3])
    self.assertTrue(ret_date == cur_date,
                    "Default time format might be broken. This may be caused " +
                    "by time delay. \"" + ret_date + '" != "' + cur_date + '".')
    
class CmdMessageFormatTests(BasicDNSSECTest):
  def testMessageFormatDefault(self):
    '''
    Tests if message is in default format and correct.
    '''
    #get current date
    proc = Popen('date "+%Y"', shell=True, stdout=PIPE, stderr=PIPE) #get year
    cur_date= proc.communicate()[0][:-1]
    
    ret = self.runCmd(dformat='"%Y"', nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr == cur_date + " CRITICAL: Parameter --nonExistCommand=RandomValue is unknown.\n", 
                    "Unexpected message format: \n" + ret.stderr)
    
  def testMessageFormatCustom(self):
    '''
    Tests if message is in custom format and correct.
    '''
    #get current date
    proc = Popen('date "+%Y"', shell=True, stdout=PIPE, stderr=PIPE) #get year
    cur_date= proc.communicate()[0][:-1]
    
    ret = self.runCmd(dformat='"%Y"', sformat='"%(levelname)s - %(message)s (%(asctime)s)"',
                      nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr == "CRITICAL - Parameter --nonExistCommand=RandomValue is unknown. (" +
                    cur_date + ")\n", "Unexpected message format: \n" + ret.stderr)
    
class CmdLevelTests(BasicDNSSECTest):
  def testLevelDefault(self):
    '''
    Tests if default level is set to error (messages with severity warning or
    lower should not be printed).
    '''
    ret = self.runCmd(type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"')
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher than WARNING.\n" +
                    ret.stderr)
    
    ret = self.runCmd(nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher than WARNING.\n" +
                    ret.stderr)
    
  def testLevelDebug(self):
    '''
    Tests custom level debug.
    '''
    ret = self.runCmd(level="debug", type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"')
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    
    ret = self.runCmd(level="debug", nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    
  def testLevelInfo(self):
    '''
    Tests custom level info.
    '''
    ret = self.runCmd(level="info", type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"')
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than INFO.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    
    ret = self.runCmd(level="info", nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    
  def testLevelWarning(self):
    '''
    Tests custom level warning.
    '''
    ret = self.runCmd(level="warning", type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"')
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than WARNING.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") == -1, "There should not be anything with severity lower than WARNING.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
    ret = self.runCmd(level="warning", nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
  def testLevelError(self):
    '''
    Tests custom level error.
    '''
    ret = self.runCmd(level="error", type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"')
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
    ret = self.runCmd(level="error", nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
  def testLevelCritical(self):
    '''
    Tests custom level critical.
    '''
    ret = self.runCmd(level="critical", type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"')
    self.assertRunOK(ret)
    self.assertHasNoStderr(ret)
    
    ret = self.runCmd(level="critical", nonExistCommand="RandomValue")
    self.assertRunFailed(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity equal to CRITICAL.\n" +
                    ret.stderr)
    
class CmdInputTests(OutputDNSSECTest):
  #check lists expected outputs
  
  def testFileMinimal(self):
    '''
    Tests reading zone from file with minimal configuration.
    '''
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"')
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testAXFRMinimal(self):
    '''
    Tests reading zone from axfr with minimal configuration. All AXFR tests
    assume to fetch good zone.
    '''
    ret = self.runCmd(type="axfr", input=self.axfr_domain, anchor=self.axfr_anchor,
                      resolver='"' + self.axfr_resolver + '"')
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testAXFRSecured(self):
    '''
    Tests reading zone from secured axfr with minimal configuration.
    '''
    ret = self.runCmd(type="axfr", input=self.axfr_sec_domain,
                      anchor=self.axfr_sec_anchor, resolver='"' + self.axfr_sec_resolver + '"',
                      key='"' + self.axfr_sec_key + '"')
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testFileSerialNumber(self):
    '''
    Tests reading zone from file with --sn option (should not try to verify the
    same zone twice).
    '''
    #remove list of serial numbers
    proc = Popen('rm /tmp/dnssec_last_serial_numbers', shell=True, stdout=PIPE, stderr=PIPE)
    tmp = proc.communicate()
    
    #first time should have output
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"',
                      level="info", sn=None)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
    #second time should not have output
    ret = self.runCmd(type="file", input=self.file_ok, anchor='"' + self.file_anchors + '"',
                      level="info", sn=None)
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testAXFRSerialNumber(self):
    '''
    Tests reading zone from axfr with --sn option (should not try to verify the
    same zone twice). All AXFR tests assume to fetch good zone.
    '''
    #remove list of serial numbers
    proc = Popen('rm /tmp/dnssec_last_serial_numbers', shell=True, stdout=PIPE, stderr=PIPE)
    tmp = proc.communicate()
    
    #first time should have output
    ret = self.runCmd(type="axfr", input=self.axfr_domain, anchor=self.axfr_anchor,
                      resolver='"' + self.axfr_resolver + '"', level="info", sn=None)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
    #second time should not have output
    ret = self.runCmd(type="axfr", input=self.axfr_domain, anchor=self.axfr_anchor,
                      resolver='"' + self.axfr_resolver + '"', level="info", sn=None)
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testFileCheckOption(self):
    '''
    Tests all --check and --nocheck options using file as an input.
    '''
    #type of check and meaning inverse
    for t, inv in [("check", False),("nocheck", True)]:    
      #check single options
      self.generalChecklist(self.runCmd, t, "RRSIG", self.list_RRSIG, self.list_RRSIG_T + self.list_RRSIG_A + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runCmd, t, "RRSIG_T", self.list_RRSIG_T, self.list_RRSIG + self.list_RRSIG_A + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runCmd, t, "RRSIG_A", self.list_RRSIG_A, self.list_RRSIG + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runCmd, t, "RRSIG_S", self.list_RRSIG_S, self.list_RRSIG + 
                            self.list_RRSIG_A + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runCmd, t, "NSEC", self.list_NSEC, self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runCmd, t, "NSEC_S", self.list_NSEC_S, self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S + self.list_NSEC + self.list_TTL, inv)
      self.generalChecklist(self.runCmd, t, "TTL", self.list_TTL, self.list_RRSIG + self.list_RRSIG_A + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S, inv)
      
      #check combinations
      self.generalChecklist(self.runCmd, t, "RRSIG;RRSIG_T;RRSIG_A;RRSIG_S", self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S, self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runCmd, t, "NSEC;NSEC_S;TTL", self.list_NSEC + self.list_NSEC_S + self.list_TTL, self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S, inv)
      
      #check all or none
      self.generalChecklist(self.runCmd, t, "RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL",
                            self.list_RRSIG + self.list_RRSIG_A + self.list_RRSIG_S + 
                            self.list_NSEC + self.list_NSEC_S + self.list_TTL, None, inv)
    
    t = "check"
    #check if all check list options have same output as no options, disregarding time 
    retAll = self.runCmd(type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"',
                         level="debug", check='"RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL"',
                         sformat='"%(levelname)s: %(message)s"')
    retNone = self.runCmd(type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"',
                         level="debug", sformat='"%(levelname)s: %(message)s"')
    
    self.assertTrue(retAll.stdout + retAll.stderr == retNone.stdout + retNone.stderr,
                    "Output of full check with --check and full check with no --check is not the same.")
    
  def testFileBuffer(self):
    '''
    Tests buffer options --bw and --bs.
    '''
    #check default buffer setting. should fail for test15 as it is on different
    #sides of the zone
    ret = self.runCmd(type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"',
                      level="warning")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertTrue(ret.stderr.find("WARNING: test15.a.example.com. owner " + 
                    "name seen more than once, but no longer in memory. " + 
                    "Verification may fail") != -1, "Warning about discontinued " +
                    "test15 record expected:\n" + ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: test15.a.example.com. NSEC type " + 
                    "record not present") != -1, "Error from discontinued " +
                    "test15 record expected:\n" + ret.stderr)
    
    #check buffer large enough. should not fail for test15 this time
    ret = self.runCmd(type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"',
                      level="warning", bs="18")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertTrue(ret.stderr.find("WARNING: test15.a.example.com. owner " + 
                    "name seen more than once, but no longer in memory. " + 
                    "Verification may fail") == -1, "Warning about discontinued " +
                    "test15 record not expected:\n" + ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: test15.a.example.com. NSEC type " + 
                    "record not present") == -1, "Error from discontinued " +
                    "test15 record not expected:\n" + ret.stderr)
    
    #disable warnings. now test15 will fail but no warning will be printed
    ret = self.runCmd(type="file", input=self.file_bad, anchor='"' + self.file_anchors + '"',
                      level="warning", bw="no")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertTrue(ret.stderr.find("WARNING: test15.a.example.com. owner " + 
                    "name seen more than once, but no longer in memory. " + 
                    "Verification may fail") == -1, "Warning about discontinued " +
                    "test15 record not expected:\n" + ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: test15.a.example.com. NSEC type " + 
                    "record not present") != -1, "Error from discontinued " +
                    "test15 record expected:\n" + ret.stderr)

if __name__ == "__main__":
    unittest.main()