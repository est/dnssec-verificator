#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
File:        test-all.py
Date:        9.4.2011
Author:      Radek Lát, xlatra00@stud.fit.vutbr.cz
Project:     Bachelor thesis:
             Automatic tracking of DNSSEC configuration on DNS servers
Description: Contains positive automated tests for testing options give to
             program over configuration file and --config command line option.  
'''
import unittest
from subprocess import Popen, PIPE
import subprocess

from UnittestHelper import *
      
class ConfDateFormatTests(BasicDNSSECTest):
  def testDateFormatDefault(self):
    '''
    Tests if date is in default format and correct.
    '''
    #get current date
    proc = Popen('date "+%Y-%m-%d %H:%M:%S"', shell=True, stdout=PIPE, stderr=PIPE)
    cur_date = proc.communicate()[0][:-1]
    
    ret = self.runConf()
    self.assertRunOK(ret)
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
    
    ret = self.runConf(dformat='%d.%m. %Y %H::%M::%S')
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    
    ret_date = " ".join(ret.stderr.split(" ")[:3])
    self.assertTrue(ret_date == cur_date,
                    "Default time format might be broken. This may be caused " +
                    "by time delay. \"" + ret_date + '" != "' + cur_date + '".')
    
class ConfMessageFormatTests(BasicDNSSECTest):
  def testMessageFormatDefault(self):
    '''
    Tests if message is in default format and correct.
    '''
    #get current date
    proc = Popen('date "+%Y"', shell=True, stdout=PIPE, stderr=PIPE) #get year
    cur_date= proc.communicate()[0][:-1]
    
    ret = self.runConf(dformat='%Y')
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr.startswith(cur_date + " CRITICAL: Source Zone0:" +
                    " Invalid. File name or address can't be empty. Disabling."), 
                    "Unexpected message format: \n" + ret.stderr)
    
  def testMessageFormatCustom(self):
    '''
    Tests if message is in custom format and correct.
    '''
    #get current date
    proc = Popen('date "+%Y"', shell=True, stdout=PIPE, stderr=PIPE) #get year
    cur_date= proc.communicate()[0][:-1]
    
    ret = self.runConf(dformat='%Y', sformat='%(levelname)s - %(message)s (%(asctime)s)')
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasStderr(ret)
    self.assertTrue(ret.stderr == "CRITICAL - Source Zone0: Invalid. File name or address can't be empty. Disabling. (" +
                    cur_date + ")\n", "Unexpected message format: \n" + ret.stderr)
    
class ConfEnabledTests(BasicDNSSECTest):
  def testEnabledDefault(self):
    '''
    Tests if zone is enabled by default.
    '''
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
  def testEnabledOn(self):
    '''
    Tests if zone is enabled when enabled option is set to 1, on or true.
    '''
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors, z_enabled="1")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors, z_enabled="on")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors, z_enabled="true")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
  def testEnabledOff(self):
    '''
    Tests if zone is not enabled when enabled option is set to 0, off or false.
    '''
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors, z_enabled="0")
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasNoStderr(ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors, z_enabled="off")
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasNoStderr(ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors, z_enabled="false")
    self.assertRunOK(ret)
    self.assertHasNoStdout(ret)
    self.assertHasNoStderr(ret)
    
class ConfLevelTests(BasicDNSSECTest):
  def testLevelDefault(self):
    '''
    Tests if default level is set to error (messages with severity warning or
    lower should not be printed).
    '''
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher than WARNING.\n" +
                    ret.stderr)
    
    ret = self.runConf()
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher than WARNING.\n" +
                    ret.stderr)
    
  def testLevelDebug(self):
    '''
    Tests custom level debug.
    '''
    ret = self.runConf(level="debug", type="file", input=self.file_bad, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    
    ret = self.runConf(level="debug")
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to DEBUG.\n" +
                    ret.stderr)
    
  def testLevelInfo(self):
    '''
    Tests custom level info.
    '''
    ret = self.runConf(level="info", type="file", input=self.file_bad, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than INFO.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    
    ret = self.runConf(level="info")
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to INFO.\n" +
                    ret.stderr)
    
  def testLevelWarning(self):
    '''
    Tests custom level warning.
    '''
    ret = self.runConf(level="warning", type="file", input=self.file_bad, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than WARNING.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") == -1, "There should not be anything with severity lower than WARNING.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
    ret = self.runConf(level="warning")
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
  def testLevelError(self):
    '''
    Tests custom level error.
    '''
    ret = self.runConf(level="error", type="file", input=self.file_bad, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("DEBUG: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("INFO: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("WARNING: ") == -1, "There should not be anything with severity lower than ERROR.\n" +
                    ret.stderr)
    self.assertTrue(ret.stderr.find("ERROR: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
    ret = self.runConf(level="error")
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity higher or equal to WARNING.\n" +
                    ret.stderr)
    
  def testLevelCritical(self):
    '''
    Tests custom level critical.
    '''
    ret = self.runConf(level="critical", type="file", input=self.file_bad, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertHasNoStderr(ret)
    
    ret = self.runConf(level="critical")
    self.assertRunOK(ret)
    self.assertTrue(ret.stderr.find("CRITICAL: ") != -1, "There should be something with severity equal to CRITICAL.\n" +
                    ret.stderr)
    
class ConfParametersFormatTests(OutputDNSSECTest):
  def verify_same_output(self, ret_ref, ret):
    '''
    Makes testCaseInsensivity shorter.
    '''
    self.assertTrue(ret == ret_ref, "Configuration files with different case " +
                    "of parameters should have same output.\nReferential " +
                    "configuration:\n" + ret_ref.configuration + "\nTested " + 
                    "configuration:\n" + ret.configuration + "\nReferential " + 
                    "output:\n" + ret_ref.stderr + ret_ref.stdout + "Tested " +
                    "output:\n" + ret.stderr + ret.stdout)
      
  def testCaseInsensivity(self):
    '''
    Tests that all parameters are case insensitive.
    '''
    ret_ref = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    
    ret = self.runConf(z_TyPe="file", input=self.file_bad, anchor=self.file_anchors,
                           check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", z_ZoNe=self.file_bad, anchor=self.file_anchors,
                           check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, z_TrUsT=self.file_anchors,
                           check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_ChEcK="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           g_oUtPuTFoRmATDaTe="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", g_oUtPuTFoRmAt='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", g_OuTpUtLeVeL="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', z_ReSoLvEr=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           z_KeY=self.axfr_sec_key, bs="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, z_bS="1", bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_check="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sformat='%(levelname)s - %(message)s (%(asctime)s)', resolver=self.axfr_sec_resolver, 
                           key=self.axfr_sec_key, bs="1", z_bW="1")
    self.verify_same_output(ret_ref, ret)
    
    ret_ref = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           nocheck="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug")
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_NoChEcK="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug")
    self.verify_same_output(ret_ref, ret)
    
    self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                 nocheck="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL", dformat="%Y",
                 level="debug", sn="1")
    ret_ref = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           nocheck="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", sn="1")
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_NoChEcK="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", z_sNcHeCk="1")
    self.verify_same_output(ret_ref, ret)
    
    ret_ref = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           nocheck="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", z_enabled="0")
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           z_NoChEcK="RRSIG;RRSIG_T;RRSIG_S;NSEC;TTL",
                           dformat="%Y", level="debug", z_eNaBlEd="0")
    self.verify_same_output(ret_ref, ret)
    
  def testIgnoreUnknown(self):
    '''
    Tests ignoring of unknown options in configuration file.
    '''
    ret_ref = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                          dformat="%Y", level="debug")
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", level="debug", g_GeneralUnknownOption="12",
                        g_GeneralUnknownOptionEmpty="", z_ZoneUnknownOption="12",
                        z_ZoneUnknownOptionEmpty="")
    self.verify_same_output(ret_ref, ret)
    
    ret_ref = self.runConf(direct_conf="[general]\ntime="+self.def_time+"\noutputLevel=debug\n" + 
                           "outputFormatDate=%Y\n[zone]\ntype=file\nzone=" + 
                           self.file_bad + "\ntrust=" + self.file_anchors)
    ret = self.runConf(direct_conf="[general]]\ntime="+self.def_time+"\noutputLevel=debug\n" + 
                       "outputFormatDate=%Y\n[zone]\ntype=file\nzone=" + 
                       self.file_bad + "\ntrust=" + self.file_anchors)
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(direct_conf="[general]\ntime="+self.def_time+"\noutputLevel=debug\n" + 
                       "outputFormatDate=%Y\n[zone]]\ntype=file\nzone=" + 
                       self.file_bad + "\ntrust=" + self.file_anchors)
    self.verify_same_output(ret_ref, ret)
    
  def testDefaultOptionValues(self):
    '''
    Tests default options values.
    '''
    ret_ref = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                           dformat="%Y", level="error", sn="0", 
                           sformat="%(asctime)s %(levelname)s: %(message)s", bs="1",
                           bw="1", check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL')
    
    ret = self.runConf(input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", level="error", sn="0",
                       sformat="%(asctime)s %(levelname)s: %(message)s", bs="1",
                       bw="1", check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL')
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", sn="0",
                       sformat="%(asctime)s %(levelname)s: %(message)s", bs="1",
                       bw="1", check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL')
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", level="error",
                       sformat="%(asctime)s %(levelname)s: %(message)s", bs="1",
                       bw="1", check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL')
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", level="error", sn="0", bs="1", bw="1",
                       check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL')
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", level="error", sn="0",
                       sformat="%(asctime)s %(levelname)s: %(message)s", bw="1",
                       check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL')
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", level="error", sn="0",
                       sformat="%(asctime)s %(levelname)s: %(message)s", bs="1",
                       check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL')
    self.verify_same_output(ret_ref, ret)
    
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                       dformat="%Y", level="error", sn="0", 
                       sformat="%(asctime)s %(levelname)s: %(message)s", bs="1",
                       bw="1")
    self.verify_same_output(ret_ref, ret)
    
    ret_ref = self.runConf(direct_conf="[general]\ntime="+self.def_time+"\noutputLevel=debug\n" + 
                       "outputFormatDate=%Y\n[zone]\ntype=file\nzone=" + 
                      self.file_bad + "\ntrust=" + self.file_anchors +
                      "\nenabled=1")
    ret = self.runConf(direct_conf="[general]\ntime="+self.def_time+"\noutputLevel=debug\n" + 
                       "outputFormatDate=%Y\n[zone]\ntype=file\nzone=" + 
                      self.file_bad + "\ntrust=" + self.file_anchors)
    self.verify_same_output(ret_ref, ret)
    
    ret_ref = self.runConf(direct_conf="[general]\ntime="+self.def_time+"\noutputLevel=debug\n" + 
                       "outputFormatDate=%Y-%m-%d %H\n[zone]\ntype=file\nzone=" + 
                      self.file_bad + "\ntrust=" + self.file_anchors)
    ret = self.runConf(direct_conf="[general]\ntime="+self.def_time+"\noutputLevel=debug\n" + 
                       "outputFormatDate=%Y-%m-%d %H\n[zone]\ntype=file\nzone=" + 
                      self.file_bad + "\ntrust=" + self.file_anchors)
    self.verify_same_output(ret_ref, ret)
    
class ConfInputTests(OutputDNSSECTest):
  #check lists expected outputs
  
  def testFileMinimal(self):
    '''
    Tests reading zone from file with minimal configuration.
    '''
    ret = self.runConf(type="file", input=self.file_ok, anchor=self.file_anchors)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testAXFRMinimal(self):
    '''
    Tests reading zone from axfr with minimal configuration. All AXFR tests
    assume to fetch good zone.
    '''
    ret = self.runConf(type="axfr", input=self.axfr_domain, anchor=self.axfr_anchor,
                      resolver=self.axfr_resolver)
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasNoStderr(ret)
    
  def testAXFRSecured(self):
    '''
    Tests reading zone from secured axfr with minimal configuration.
    '''
    ret = self.runConf(type="axfr", input=self.axfr_sec_domain,
                      anchor=self.axfr_sec_anchor, resolver=self.axfr_sec_resolver,
                      key=self.axfr_sec_key)
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
    ret = self.runConf(type="file", input=self.file_ok, anchor=self.file_anchors,
                      level="info", sn="1")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
    #second time should not have output
    ret = self.runConf(type="file", input=self.file_ok, anchor=self.file_anchors,
                      level="info", sn="1")
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
    ret = self.runConf(type="axfr", input=self.axfr_domain, anchor=self.axfr_anchor,
                      resolver=self.axfr_resolver, level="info", sn="1")
    self.assertRunOK(ret)
    self.assertHasStdout(ret)
    self.assertHasStderr(ret)
    
    #second time should not have output
    ret = self.runConf(type="axfr", input=self.axfr_domain, anchor=self.axfr_anchor,
                      resolver=self.axfr_resolver, level="info", sn="1")
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
      self.generalChecklist(self.runConf, t, "RRSIG", self.list_RRSIG, self.list_RRSIG_T + self.list_RRSIG_A + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runConf, t, "RRSIG_T", self.list_RRSIG_T, self.list_RRSIG + self.list_RRSIG_A + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runConf, t, "RRSIG_A", self.list_RRSIG_A, self.list_RRSIG + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runConf, t, "RRSIG_S", self.list_RRSIG_S, self.list_RRSIG + 
                            self.list_RRSIG_A + self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runConf, t, "NSEC", self.list_NSEC, self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runConf, t, "NSEC_S", self.list_NSEC_S, self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S + self.list_NSEC + self.list_TTL, inv)
      self.generalChecklist(self.runConf, t, "TTL", self.list_TTL, self.list_RRSIG + self.list_RRSIG_A + 
                            self.list_RRSIG_S + self.list_NSEC + self.list_NSEC_S, inv)
      
      #check combinations
      self.generalChecklist(self.runConf, t, "RRSIG;RRSIG_T;RRSIG_A;RRSIG_S", self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S, self.list_NSEC + self.list_NSEC_S + self.list_TTL, inv)
      self.generalChecklist(self.runConf, t, "NSEC;NSEC_S;TTL", self.list_NSEC + self.list_NSEC_S + self.list_TTL, self.list_RRSIG +
                            self.list_RRSIG_A + self.list_RRSIG_S, inv)
      
      #check all or none
      self.generalChecklist(self.runConf, t, "RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL",
                            self.list_RRSIG + self.list_RRSIG_A + self.list_RRSIG_S + 
                            self.list_NSEC + self.list_NSEC_S + self.list_TTL, None, inv)
    
    t = "check"
    #check if all check list options have same output as no options, disregarding time 
    retAll = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                         level="debug", check='RRSIG;RRSIG_T;RRSIG_A;RRSIG_S;NSEC;NSEC_S;TTL',
                         sformat='%(levelname)s: %(message)s')
    retNone = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
                         level="debug", sformat='%(levelname)s: %(message)s')
    
    self.assertTrue(retAll.stdout + retAll.stderr == retNone.stdout + retNone.stderr,
                    "Output of full check with --check and full check with no --check is not the same:\n" +
                    retAll.stdout + retAll.stderr + "\n\n!=\n\n" + retNone.stdout + 
                    retNone.stderr)
    
  def testFileBuffer(self):
    '''
    Tests buffer options --bw and --bs.
    '''
    #check default buffer setting. should fail for test15 as it is on different
    #sides of the zone
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
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
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
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
    ret = self.runConf(type="file", input=self.file_bad, anchor=self.file_anchors,
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