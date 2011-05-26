#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
Contains a class for parsing input parameters from console or for
reading them from file if requested. Also remembers and handles
these parameters for later use and detects errors.

  - B{File}: I{ParamParser.py}
  - B{Date}: I{20.8.2010}
  - B{Author}: I{Radek Lát, U{xlatra00@stud.fit.vutbr.cz<mailto:xlatra00@stud.fit.vutbr.cz>}}

I{Bachelor thesis - Automatic tracking of DNSSEC configuration on DNS servers}
'''

import ConfigParser
import logging
import sys
import os
from Exceptions import ParamError
from ZoneChecker import TimeVerify

class ZoneParams(object):
  '''
  A set of parameters of a zone that works basically the same way, as structure
  from C.
  '''
  
  __fullcheck = ('RRSIG', 'RRSIG_T', 'RRSIG_A', 'RRSIG_S', 'NSEC', 'NSEC_S',
                 'TTL', 'DS')
  '''List of check values available.'''
  
  def __init__(self, *args):
    '''
    Initializes objects variables. Accepts same arguments as method
    L{set_params} for initial settings.
    '''
    self.name = None
    self.type = None
    self.source = None
    self.trust = None
    self.resolver = None
    self.keyname = None
    self.keyalg = None
    self.keydata = None
    self.buffer_size = None
    self.buffer_warn = None
    self.__check = []
    self.sn_check = None
    self.set_params(*args)
    
  def set_params(self, z_name, z_type, z_source, z_trust, z_resolver,\
                 t_keyname = None, t_keyalg = None, t_keydata = None,
                 z_buffer_size = 1, z_buffer_warn = True, z_check = None,
                 z_nocheck = None, z_sn = None):
    '''
    Rewrites objects parameters.
    
    @param z_name: Name of the source.
    @type z_name: String
    @param z_type: Type of the source.
    @type z_type: "file" | "axfr"
    @param z_source: Source type specific string.
    @type z_source: String - filename or domain
    @param z_trust: List of files with trust anchors.
    @param z_resolver: List of additional IP addresses for resolver.
    @param t_keyname: Name part of TSIG used by AXFR.
    @param t_keyalg: Algorithm part of TSIG used by AXFR.
    @param t_keydata: Data part of TSIG used by AXFR.
    @param z_buffer_size: Size of the input buffer.
    @type z_buffer_size: Integer = count of RRCollection objects
    @param z_buffer_warn: Warn if creating RRCollection for some owner name more than once.
    @type z_buffer_warn: Boolean
    @param z_check: List of checks to be performed.
    @param z_nocheck: List of checks not to be performed.
    @param z_sn: Should be SOA serial number checked?
    @type z_sn: Boolean
    '''
    self.name = z_name
    
    if not z_type:
      self.type = None
    else:
      self.type = z_type
      
    if not z_source:
      self.source = None
    else:
      self.source = z_source
      
    if not z_trust:
      self.trust = None
    else:
      self.trust = z_trust.split(";")
      
    if not z_resolver or z_resolver == "default":
      self.resolver = None
    else:
      self.resolver = z_resolver.split(";")
      
    self.keyname = t_keyname
    self.keyalg = t_keyalg
    self.keydata = t_keydata
    self.buffer_size = z_buffer_size
    self.buffer_warn = z_buffer_warn
    
    if z_check or (z_check and z_nocheck): #inclusive check
      z_check = z_check.split(';')
      for i in z_check:
        if i.upper() in self.__fullcheck: #remember only those known
          self.__check.append(i.upper())
        else: #warn when not known, logging module is not set up yet
          print >>sys.stderr, "CRITICAL: Check option " + i + " is unknown."
    elif z_nocheck: #exclusive check
      self.__check.extend(self.__fullcheck)
      z_nocheck = z_nocheck.split(';')
      for i in z_nocheck:
        if i.upper() in self.__check: #remove only those known
          self.__check.remove(i.upper())
        elif i.upper() not in self.__fullcheck:
          #warn when not known, logging module is not set up yet
          print >>sys.stderr, "CRITICAL: Check option " + i + " is unknown."
    else: #full check
      self.__check.extend(self.__fullcheck)
      
    if z_sn:
      self.sn_check = True
    else:
      self.sn_check = False
          
  def check_wanted(self, check_name):
    '''
    Returns true, if specified check is wanted. Returns false if not.
    '''
    check_name = check_name.upper()    
    return check_name in self.__check    
  
  def check_wanted_only(self, check_name):
    '''
    Returns true, when no other, than specified check is wanted. Returns false
    when other checks wanted too or specified not.
    '''  
    return self.check_wanted(check_name) and len(self.__check) == 1

class ParamParser(object):
  '''
  This class can parse input program parameters and store them for later use.
  It may raise L{ParamError} exception during initialization in case of error
  in parameters. Also initializes L{logging} module for later use in entire
  application.
  
  It provides a list of L{ZoneParams} objects, that describe zones to be
  checked. For object attributes see L{ZoneParams.set_params} method.
  '''
  
  boolean_states = {'1': True, 'yes': True, 'true': True, 'on': True,
                    '0': False, 'no': False, 'false': False, 'off': False}
  '''
  Lower case string representation of boolean values, that may be used for
  boolean parameters.
  '''

  def __init__(self, argv, argc):
    '''
    Constructor of the class, arguments from console required. May raise
    L{ParamError} exception in case of error in input parameters.
    @param argv: List of arguments.
    @param argc: Count of the arguments.
    '''
    self.__paramShort = {'--help': 0, '-h': 0, '--sn': 0 }
    '''
    Dictionary that lists available parameters from command line, without char =
    '''

    self.__paramLong = { '--time': 0, '--level': 0, '--input': 0, '--anchor': 0,
                         '--type': 0, '--resolver': 0, '--config': 0,
                         '--sformat': 0, '--dformat': 0, '--key': 0, '--bs': 0,
                         '--bw': 0, '--check': 0, '--nocheck': 0}
    '''
    Dictionary that lists available parameters from command line, with char =
    '''
  
    self.__LEVELS = {'debug': logging.DEBUG, 'info': logging.INFO, 'warning': logging.WARNING,
          'error': logging.ERROR, 'critical': logging.CRITICAL}
    '''Mapping of lower case strings to logging levels.'''
  
    self.zones = []
    '''List for storing info about zones in L{ZoneParams} objects.'''    
    
    try: #present just for finally section, exceptions will propagate to upper levels
      #strip first parameter, that is script path, then do actual parsing
      self.__parse_params(argv[1:], argc-1)
      
      if self.is_help(): #was help requested?
        return
      
      if self.__paramLong['--config']: #parameters should be read from a file
        self.__erase_params() #erase the old ones from command line
        self.__load_params(self.__paramLong['--config']) #load new ones
        
      self.__check_parsed() #checks parsed parameters if they are valid
    finally:    
      #configure logging in any case, needed for printing exceptions too
      logging.basicConfig(level=self.get_level(),
                          format=self.__get_format(),
                          datefmt=self.__get_format_date(),
                          stream=sys.stderr)
    
    # until here no properly formated debug output is possible -----------------
    self.__check_zones()
  
  def is_help(self):
    '''
    Informs whether a help was selected as an option.
    '''
    return self.__paramShort['--help'] or self.__paramShort['-h']
  
  def get_time(self):
    '''
    Returns a L{TimeVerify} object, that is based on users configuration.
    '''
    return self.__paramLong['--time']
    
  def __erase_params(self):
    '''
    Resets all parameters, except C{--config}.
    '''
    for k in self.__paramLong.keys():
      if k != '--config':
        self.__paramLong[k] = 0
       
    for k in self.__paramShort.keys():
      self.__paramShort[k] = 0
      
  def __load_params(self, fname):
    '''
    Loads parameters from configuration file using L{ConfigParser} module.
    May raise L{ParamError} exception in case of error.
    @param fname: Path to a configuration file.
    '''
    p = ConfigParser.SafeConfigParser()
    try:
      if (len(p.read(fname)) != 1): #try to read configuration file
        raise ParamError(7, "File "+str(fname)+" could not be read.")
    except ConfigParser.ParsingError, detail:
      raise ParamError(7, "File "+str(fname)+" could not be parsed. " + str(detail))
    
    try: #section general does not have to be present at all
      #these parameters are optional, ignore if the don't exist
      try:
        self.__paramLong['--level'] = p.get("general", "outputLevel", True).lower()
        if self.__paramLong['--level'] == "":
          raise ParamError(6, "Parameter outputLevel can't be empty.")
      except ConfigParser.NoOptionError:
        pass
      
      try:
        self.__paramLong['--sformat'] = p.get("general", "outputFormat", True)
        if self.__paramLong['--sformat'] == "":
          raise ParamError(6, "Parameter outputFormat can't be empty.")
      except ConfigParser.NoOptionError:
        pass
      
      try:
        self.__paramLong['--dformat'] = p.get("general", "outputFormatDate", True)
        if self.__paramLong['--dformat'] == "":
          raise ParamError(6, "Parameter outputFormatDate can't be empty.")
      except ConfigParser.NoOptionError:
        pass
      
      try:
        self.__paramLong['--time'] = p.get("general", "time", True)
        if self.__paramLong['--time'] == "":
          raise ParamError(6, "Parameter time can't be empty.")
      except ConfigParser.NoOptionError:
        pass
    except ConfigParser.NoSectionError:
      pass
    
    for z_name in p.sections(): #read all sections (= sources)      
      if z_name == "general": #skip general section
        continue
      
      try:
        enabled = p.getboolean(z_name, "enabled")
      except ConfigParser.NoOptionError:
        enabled = True #default
      except ValueError, detail:
        raise ParamError(6, "Parameter enabled has invalid value. " + str(detail))
      
      if enabled:
        try:
          z_type = p.get(z_name, "type", True)
          if z_type == '':
            raise ParamError(6, "Parameter type can't be empty.")
        except ConfigParser.NoOptionError:
          z_type = "file" #default
        
        try:  
          z_source = p.get(z_name, "zone", True)
          if z_source == '':
            raise ParamError(6, "Parameter zone can't be empty.")
        except ConfigParser.NoOptionError:
          z_source = None #default
          
        try:
          z_trust = p.get(z_name, "trust", True)
          if z_trust == '':
            raise ParamError(6, "Parameter trust can't be empty.")
        except ConfigParser.NoOptionError:
          z_trust = None #default
          
        try:  
          z_resolver = p.get(z_name, "resolver", True)
          if z_resolver == '':
            raise ParamError(6, "Parameter resolver can't be empty.")
        except ConfigParser.NoOptionError:
          z_resolver = None #default
          
        try:  
          z_buffer_size = p.getint(z_name, "buffersize")
          if z_buffer_size == '':
            raise ParamError(6, "Parameter buffersize can't be empty.")
          if z_buffer_size <= 0:
            raise ValueError("")
        except ConfigParser.NoOptionError:
          z_buffer_size = 1 #default
        except ValueError, detail:
          raise ParamError(8, "Parameter buffersize has invalid value. " + 
                         "Use positive integer number higher or equal to 1. " + 
                         str(detail))
          
        try:
          z_buffer_warn = p.getboolean(z_name, "bufferwarn")            
        except ConfigParser.NoOptionError:
          z_buffer_warn = True #default
        except ValueError, detail:
          raise ParamError(6, "Parameter bufferwarn has invalid value. " + str(detail))
          
        try:  
          z_check = p.get(z_name, "check", True)
          if z_check == '':
            raise ParamError(6, "Parameter check can't be empty.")
        except ConfigParser.NoOptionError:
          z_check = None #default
          
        try:  
          z_nocheck = p.get(z_name, "nocheck", True)
          if z_nocheck == '':
            raise ParamError(6, "Parameter nocheck can't be empty.")
        except ConfigParser.NoOptionError:
          z_nocheck = None #default
          
        try:  
          t_key = p.get(z_name, "key", True)
          if t_key == '':
            t_key = []
            raise ParamError(6, "Parameter key can't be empty.")
          t_key = t_key.split(" ")
        except ConfigParser.NoOptionError:
          t_key = []
        finally: #just to make sure there are always at least 3 values
          t_key.extend([None, None, None])
          
        try:
          z_sn = p.getboolean(z_name, "sncheck")
          if z_sn == '':
            raise ParamError(6, "Parameter sncheck can't be empty.")
        except ConfigParser.NoOptionError:
          z_sn = False #default
        except ValueError, detail:
          raise ParamError(6, "Parameter sncheck has invalid value. " + str(detail))
          
        self.__add_zone(z_name, z_type, z_source, z_trust, z_resolver, t_key[0],\
                        t_key[1], t_key[2], z_buffer_size, z_buffer_warn, z_check,
                        z_nocheck, z_sn)        
  
  def get_level(self):
    '''
    Returns current logging level based on users configuration. Default is
    logging.ERROR, if nothing set.
    '''
    return self.__LEVELS.get(self.__paramLong['--level'], logging.ERROR);
  
  def __add_zone(self, *args):
    '''
    Adds a zone source parameters to the list. For available options see
    L{ZoneParams.set_params}.
    '''
    self.zones.append(ZoneParams(*args))
  
  def __get_format(self):
    '''
    Gets current formatter string for output. Default is
    C{%(asctime)s %(levelname)s: %(message)s}.
    '''
    if self.__paramLong['--sformat']:
      return self.__paramLong['--sformat']
    else:
      return "%(asctime)s %(levelname)s: %(message)s"
    
  def __get_format_date(self):
    '''
    Gets current formatter string for output. The date format string follows the
    requirements of
    U{time.strftime()<http://docs.python.org/library/time.html#time.strftime>}
    Default is C{%Y-%m-%d %H:%M:%S}.
    '''
    if self.__paramLong['--dformat']:
      return self.__paramLong['--dformat']
    else:
      return "%Y-%m-%d %H:%M:%S"
  
  def __parse_params(self, argv, argc):
    '''
    Parses parameters from command line.
    It raises L{ParamError} exception if an error occurred.
    '''
    if argc == 0:
      raise ParamError(1, "Not enough parameters. Try using -h or --help for list of available parameters.")
  
    for param in argv:
      #simple parameter
      if self.__paramShort.has_key(param): #know parameter
        if self.__paramShort[param]: #already seen, thats an error
          raise ParamError(2, "Multiple usage of parameter "+param+".")
        else: #first time seen, make a record of it
          self.__paramShort[param] = 1;
      #complex parameter
      elif self.__paramLong.has_key(param.split('=', 1)[0]): #known parameter
        param = param.split('=', 1);
        if len(param) < 2: #missing char =
          raise ParamError(3, "Parameter "+param[0]+" is not complete.")
        else: #char = present
          if param[1] != '': #part self.__paramLong[param[0]]after char = is not empty
            if self.__paramLong[param[0]]: #already seen, thats an error
              raise ParamError(2, "Multiple usage of parameter "+param[0]+".")
            else: #first time seen, make a record of it
              self.__paramLong[param[0]] = param[1]
          else: #part after char = is empty
            raise ParamError(3, "Parameter "+param[0]+" is not complete.")
      #unknown parameter
      else:
        raise ParamError(4, "Parameter "+param+" is unknown.")
  
  def __check_parsed(self):
    '''
    Checks parsed parameters C{--level}, C{--time}, C{--input}, C{--anchor},
    C{--bs} and C{--bw}, if they contain valid values.
    
    The C{--time} parameter is passed directly to L{TimeVerify} object, which
    can be obtained later using L{get_time()} method.

    Parameters C{--input} and C{--anchor} should contain semicolon separated
    list of files. They are parsed and added.
    
    Raises L{ParamError} exception in case of an error.
    '''
    
    #check if the level is known
    if self.__paramLong['--level'] != 0:
      self.__paramLong['--level'] = self.__paramLong['--level'].lower()
      if not self.__LEVELS.has_key(self.__paramLong['--level']):
        raise ParamError(5, "Parameter --level has invalid value ("+str(self.__paramLong['--level'])+").")
    
    #try to create time object
    try:
      oldvalue = self.__paramLong['--time']
      self.__paramLong['--time'] = TimeVerify(self.__paramLong['--time'])
    except ValueError as detail:
      raise ParamError(6, "Parameter --time has invalid value ("+str(oldvalue)+"). " + str(detail))
      
    #parse zone files
    if not self.__paramLong['--anchor']: #put default value
      self.__paramLong['--anchor'] = None
      
    if not self.__paramLong['--resolver']: #put default value
      self.__paramLong['--resolver'] = None
      
    if not self.__paramLong['--key']: #put default value
      self.__paramLong['--key'] = [None, None, None]
    else:
      self.__paramLong['--key'] = self.__paramLong['--key'].split(" ")
      self.__paramLong['--key'].extend([None, None, None]) #make sure there are at least 3 items
      
    if not self.__paramLong['--bs']: #put default value
      self.__paramLong['--bs'] = 1
    else:
      try:
        self.__paramLong['--bs'] = int(self.__paramLong['--bs'])
        if self.__paramLong['--bs'] <= 0:
          raise ValueError("")
      except ValueError:
        raise ParamError(8, "Parameter --bs has invalid value ("+str(self.__paramLong['--bs'])+\
                         "). Use positive integer number higher or equal to 1.")
        
    if not self.__paramLong['--bw']: #put default value
      self.__paramLong['--bw'] = True
    else:
      if self.__paramLong['--bw'].lower() not in self.boolean_states:
        raise ParamError(8, "Parameter --bs has invalid value ("+str(self.__paramLong['--bw'])+\
                         "). Not a boolean.")
      else:
        self.__paramLong['--bw'] = self.boolean_states[self.__paramLong['--bw'].lower()]
        
    if not self.__paramLong['--check']: #put default value
      self.__paramLong['--check'] = None
      
    if not self.__paramLong['--nocheck']: #put default value
      self.__paramLong['--nocheck'] = None
    
    if self.__paramLong['--input']:
      flist = str(self.__paramLong['--input']).split(';')
      for i in range(len(flist)): # add sources to list
        self.__add_zone("Zone"+str(i), self.__paramLong['--type'], flist[i], \
        self.__paramLong['--anchor'], self.__paramLong['--resolver'],
        self.__paramLong['--key'][0], self.__paramLong['--key'][1], self.__paramLong['--key'][2],
        self.__paramLong['--bs'], self.__paramLong['--bw'], self.__paramLong['--check'],
        self.__paramLong['--nocheck'], self.__paramShort['--sn'])
        
  def __check_zones(self):
    '''
    Checks if all parsed sources are sane.
    '''
    r = range(len(self.zones))
    r.reverse()
    for i in r:
      z = self.zones[i]
      if z.type is None:
        logging.critical("Source " + str(z.name) + ": Type not set. Disabling.")
        self.zones.pop(i)
      elif not z.type in ("file","axfr"):
        logging.critical("Source " + str(z.name) + ": Invalid type \"" + str(z.type) + "\". Disabling.")
        self.zones.pop(i)
      elif not z.source:
        logging.critical("Source " + str(z.name) + ": Invalid. File name or address can't be empty. Disabling.")
        self.zones.pop(i)
      elif z.type == "file" and not os.path.exists(z.source):
        logging.critical("Source " + str(z.name) + ": Zone master file can't be read. Disabling.")
        self.zones.pop(i)
