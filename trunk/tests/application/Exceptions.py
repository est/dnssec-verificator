#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
Contains hierarchical set of Exception classes used in entire application.

  - B{File}: I{Exceptions.py}
  - B{Date}: I{20.8.2010}
  - B{Author}: I{Radek Lát, U{xlatra00@stud.fit.vutbr.cz<mailto:xlatra00@stud.fit.vutbr.cz>}}

I{Bachelor thesis - Automatic tracking of DNSSEC configuration on DNS servers}
'''

class Error(Exception):
  '''Base class for all exceptions in this module.'''
  
  def __init__(self, err_msg):
    '''
    Constructor of the Error class.
    @param err_msg: Error message.
    '''
    self.err_msg = err_msg
    '''Error message.'''
    
  def __str__(self):
    return str(self.err_msg)

class ParamError(Error):
  '''
  Exception raised by an error in parameters given over command line or over
  configuration file.
  '''

  def __init__(self, err_code, err_msg):
    '''
    Constructor of the ParamError class.
    @param err_code: Error code.
    @param err_msg: Error message.
    '''
    self.err_code = err_code
    '''Error code (can be used as application exit code).'''
    
    self.err_msg = err_msg
    '''Error message.'''
    
  def __str__(self):
    return str(self.err_msg) + " (" + str(self.err_code) + ")"
  
class AXFRError(Error):
  '''
  Exception raised on error during AXFR.
  '''
  pass

class FileError(Error):
  '''
  Exception raised on error during reading from zone master file.
  '''
  pass

class ResolverError(Error):
  '''
  Exception raised on error during setting up a SafeResolver instance.
  '''
  pass

class LoadingDone(Error):
  '''
  Exception raised on after loading is done.
  '''
  pass
    