#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
Contains verifying functions, which are using PyLDNS library.

  - B{File}: I{ZoneChecker.py}
  - B{Date}: I{20.8.2010}
  - B{Author}: I{Radek Lát, U{xlatra00@stud.fit.vutbr.cz<mailto:xlatra00@stud.fit.vutbr.cz>}}

I{Bachelor thesis - Automatic tracking of DNSSEC configuration on DNS servers} 
'''

import time
import ldns
import logging
from copy import deepcopy
import ConfigParser

from Exceptions import AXFRError, FileError, LoadingDone, ResolverError
from Statistics import Statistics

class Alg:
  '''
  Class for storing values to algorithm lists. Used in
  L{ZoneChecker.get_valid_keys()} and L{RRCollection.verify_rrsigs_algorithms()}.
  '''
  def __init__(self, a, f):
    '''
    @param a: Algorithms number.
    @param f: Flags number.
    '''
    self.alg = a
    '''DNSKEY I{Algorithm} field.'''
    self.flag = f
    '''DNSKEY I{Flags} field.'''
  def __eq__(self, other):
    return self.alg == other.alg and self.flag == other.flag
  def __ne__(self, other):
    return self.alg != other.alg or self.flag != other.flag
  def __str__(self):
    return str(self.alg) + " " + str(self.flag)

class TimeVerify(object):
  '''
  Provides custom time for signature verification as well as functions to
  compare and verify provided time. It can handle both formats of time as
  specified in
  U{RFC 4034, section 3.2<http://tools.ietf.org/html/rfc4034#section-3.2>}.
  '''
  RRSIG_VALID = 1
  '''RRSIG time validity identificator - RRSIG is time-valid, used by L{is_valid()} method.'''
  RRSIG_INVALID = 0
  '''RRSIG time validity identificator - RRSIG is time-invalid, used by L{is_valid()} method.'''
  RRSIG_FUTURE = -1
  '''RRSIG time validity identificator - RRSIG is will be valid in future, used by L{is_valid()} method.'''
  
  def __init__(self, value):
    '''
    Initializes time provider with a specific time value.
    @param value: Time-symbolizing value. Following values are acceptable:
      - "now" - will provide every time actual time
      - "run" - will remember time of object creation
      - <time> - will use provided time value (must be in format C{%Y-%m-%d %H:%M:%S}, 
      otherwise will raise L{ValueError} exception)
    '''
    self.__time_type = None
    '''Type of providing time.'''
    self.__time_value = None
    '''Actual time value, if any supplied.'''
    
    if value and value != 'run' and value != 'now': #probably time value, check it
      self.__time_value = time.mktime(time.strptime(value, '%Y-%m-%d %H:%M:%S'))
      self.__time_type = 'custom'
    else:
      self.__time_type = value

    if value == 'run' or (not value): #selected "run" or default (the same)
      self.__time_value = time.time()
      self.__time_type = 'run'
      
  def is_valid(self, t_inception, t_expiration):
    '''
    Checks if current time is within provided inception and expiration time
    interval. Returns L{RRSIG_VALID} if so, L{RRSIG_INVALID} if current time is lower,
    than expiration time and L{RRSIG_FUTURE} if if current time if below inception
    time.
    
    May raise L{ValueError} exception, if provided time is in incorrect format.
    
    @param t_inception: C{Signature Inception} field value.
    @param t_expiration: C{Signature Expiration} field value.
    '''
    ti = self.normalize_time(t_inception)
    
    if self.__get_time() >= ti and self.__get_time() <= self.normalize_time(t_expiration):
      return self.RRSIG_VALID
    elif self.__get_time() < ti:
      return self.RRSIG_FUTURE
    else:
      return self.RRSIG_INVALID
    
  def time_left(self, t_expiration):
    '''
    Returns a number of seconds between internal object time and specified 
    expiration time. If the value is lower than a zero, 0 is returned.
    @param t_expiration: C{Signature Expiration} field value. 
    '''
    te = self.normalize_time(t_expiration)
    tdiff = te - self.__get_time()
    
    if tdiff < 0:
      return 0
    else:
      return int(tdiff)
  
  def __get_time(self):
    '''
    Gets current time according to how was the object initialized.
    '''
    if self.__time_type == "run" or self.__time_type == "custom":
      return self.__time_value #we already know the time, it does not change
    else:
      return time.time() #get current time
  
  @staticmethod
  def normalize_time(t_denorm):
    '''
    Takes as parameter time in two possible formats (see 
    U{RFC 4034, section 3.2<http://tools.ietf.org/html/rfc4034#section-3.2>})
    and makes from it a time as a floating point number expressed in seconds
    since the epoch.
    
    May raise L{ValueError} exception if time not in correct format.
    
    @param t_denorm: Input time value.
    '''
    strt = str(t_denorm)
    if len(strt) == 14: #in format YYYYMMDDHHmmSS
      return time.mktime(time.strptime(strt, '%Y%m%d%H%M%S'))
    else: #should be already in needed format
      return float(strt)
    
class SafeResolver(object):
  '''
  Wrapper of U{ldns.ldns_resolver<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__resolver.html>}
  providing safe cycling of name servers.
  '''
  
  def __init__(self, res):
    '''
    Initialization of the object.
    @param  res: U{ldns.ldns_resolver<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__resolver.html>}
    object to be used for cycling. Can be obtained by
    U{ldns.ldns_resolver.new_frm_file()<http://www.nlnetlabs.nl/projects/ldns/doc/resolver_8c.html#a783fdb0e6523eb6c1f4a1563b32ac135>}.
    '''
    self.__res = res
    '''
    Storage for U{ldns.ldns_resolver<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__resolver.html>}
    instance.
    '''
    
    self.__res.set_dnssec(True) #set to get DNSSEC records too
    self.__res.set_fail(False) #continue with next nameserver in case of fail
    self.__res.set_recursive(False) 
    
  def __res_addr_add(self, ip):
    '''
    Adds an IP address to a list of addresses to be used by resolver. Prints
    an error using L{logging} module with critical severity, when the provided
    IP address cannot be resolved.
    @param ip: New IP address.
    @type ip: String
    '''
    try: #catch error if IP invalid or other error
      tmp = ldns.ldns_rdf.new_frm_str(ip, ldns.LDNS_RDF_TYPE_A)
      self.__res_ips.append(tmp)
    except Exception:
      logging.critical("IP address "+ip+" can't be resolved.") 
    
  def set_resolver(self, ip_str, keyname = None, keyalg = None, keydata = None):
    '''
    Sets a new addresses and TSIG parameters for resolver.
    May raise L{ResolverError} when no valid IP address provided.
    
    @param ip_str: List or tuple of IP addresses.
    @type ip_str: [String, ...]
    @param keyname: Name part of TSIG
    @type keyname: String
    @param keyalg: Algorithm part of TSIG
    @type keyalg: String
    @param keydata: Data part of TSIG
    @type keydata: String
    @return: U{ldns.ldns_resolver<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__resolver.html>}
    instance with first name server active.
    '''
    self.__res_ips = [] #initialize list of addresses for resolver
    '''
    List of IP addresses for U{ldns.ldns_resolver<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__resolver.html>}
    instance.
    '''
    
    while self.__res.pop_nameserver(): #pop all existing name servers
      pass
    
    for i in ip_str:
      self.__res_addr_add(i)
      
    if len(self.__res_ips) <= 0: #none of given addresses valid or none given
      raise ResolverError("No valid IP address for resolver available.")
      
    if keyname != None and keydata != None and keyalg != None: #all specified, set TSIG
      ldns.ldns_resolver_set_tsig_keyname(self.__res, keyname)
      ldns.ldns_resolver_set_tsig_keydata(self.__res, keydata)
      ldns.ldns_resolver_set_tsig_algorithm(self.__res, keyalg.lower())
    elif keyname != None or keydata != None or keyalg != None: #some specified, warn that this is not enough
      logging.critical("For using TSIG there has to be specified its name, data and algorithm. Disabling TSIG authentication.")
      
    #set first address as active
    self.__res_active = 0 #index of it
    '''
    Index to L{__res_ips} meaning currently active IP address in
    U{ldns.ldns_resolver<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__resolver.html>}
    instance.
    '''
    self.__res.push_nameserver(self.__res_ips[0])
    
    return self.__res
      
  def resolver(self):
    '''
    Returns resolver instance with current name server set.
    '''
    return self.__res
  
  def resolver_next(self):
    '''
    Returns
    U{ldns.ldns_resolver<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__resolver.html>}
    instance with next name server IP from L{__res_ips} list active.
    '''
    #next position
    self.__res_active = (self.__res_active + 1) % len(self.__res_ips)    
    
    while self.__res.pop_nameserver(): #pop all existing name servers
      pass
    
    self.__res.push_nameserver(self.__res_ips[self.__res_active]) #push new
    return self.__res 
  
  def count(self):
    '''
    Returns a number of name servers in the L{__res_ips} list.
    '''
    return len(self.__res_ips)
    
    
class RRCollection(object):
  '''
  Multiple
  U{ldns_rr<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr.html>}
  objects joined together. All have to have the same owner name.
  '''
  NSEC_NOT_SECURED = 0
  '''NSEC type presence indicator - no NSEC record present.'''
  NSEC = 1
  '''NSEC type presence indicator - present NSEC type record.'''
  NSEC3 = 2
  '''NSEC type presence indicator - present NSEC3 type record.'''
  NSEC_OTHER = 3
  '''NSEC type presence indicator - present other NSEC type record.'''
  
  ns_exclude_list = (ldns.LDNS_RR_TYPE_DS, ldns.LDNS_RR_TYPE_NS, ldns.LDNS_RR_TYPE_NSEC, \
                     ldns.LDNS_RR_TYPE_NSEC3)
  '''List of types that should not be checked for determining, if there is present
  NS record only.'''
  
  def __init__(self, owner):
    '''
    The owner name has to be set during initialization.
    @param owner: Owner name that should have all newly added records.
    @type owner: String 
    '''
    self.__rrs = {}
    '''
    Dictionary of regular RRs, I{key} is their type. If multiple records with
    the same type present, they form a list.
    '''
    
    self.__rrsigs = {}
    '''
    Dictionary of RRSIG type RRs, I{key} is type they cover. If multiple records
    with the same type covered present, they form a list.
    '''
    
    self.__nsec = None
    '''
    NSEC type record for current owner name. Only one is allowed to be
    present.
    '''
    
    self.__owner = owner
    '''
    Current owner name, has to match all records in L{__rrs}, L{__rrsigs} and
    L{__nsec}.
    '''
    
    self.__nsec_type = self.NSEC_NOT_SECURED
    '''NSEC type presence indicator.'''
    
    self.__has_ns_only = True
    '''
    Indicator if only NS record type is present in L{RRCollection} object.
    Types from L{ns_exclude_list} are excluded.
    '''
    
  def __custom_list_print(self, l):
    '''
    Returns a string of a list items in custom format. Used by L{__str__}
    method.
    '''
    ret = ""
    ll = len(l) - 1
    for i in range(ll + 1):
      if i < ll:
        ret += str(l[i]) + ", "
      else:
        ret += str(l[i])
        
    return ret
  
  def __str__(self):
    ret = ""
    
    ret += self.owner() + "\n"
    
    for i in self.__rrs.keys(): #go through types
      for j in self.__rrs[i]: #go through RRs
        if j:
          tmpstr = "    " + str(j)
          if len(tmpstr) > 80:
            ret += tmpstr[:77] + "...\n"
          else:
            ret += tmpstr
            
    for i in self.__rrsigs.keys(): #go through types
      for j in self.__rrsigs[i]: #go through RRSIGs
        if j:
          tmpstr = "    " + str(j)
          if len(tmpstr) > 80:
            ret += tmpstr[:77] + "...\n"
          else:
            ret += tmpstr

    if self.__nsec:
      ret += "    " + str(self.__nsec)    
    
    return ret
  
  def get_nsec_type(self):
    '''
    Returns NSEC type presence status (L{NSEC_NOT_SECURED}, L{NSEC}, L{NSEC3} or
    L{NSEC_OTHER}. 
    '''
    return self.__nsec_type
  
  def get_algs(self):
    '''
    Returns list integer identificators of algorithm numbers used by RRSIGs in
    L{__rrsigs}. 
    '''
    ret = []
    
    for key in self.__rrsigs:
      for rrsig in self.__rrsigs[key]:
        if not rrsig.rrsig_algorithm() in ret:
          ret.append(rrsig.rrsig_algorithm())
        
    return ret
    
  def get_ns_dnames(self):
    '''
    Returns a list of domain names from NS type resource record, in a string
    representation.
    
    To check if there are any NS records present use L{has_ns()} or
    L{has_ns_only()} methods. If there are no NS records, returns empty list.
    '''
    ret = []
    
    if self.has_ns():   
      for rr in self.__rrs['NS']:
        dname = str(rr.ns_nsdname())
        if not dname in ret:
          ret.append(dname)
                   
    return ret

  def get_rrs(self, type):
    '''
    Gets a list of regular records for given type (from L{__rrs}).
    @param type: Type of record you want to fetch.
    @type type: int
    '''
    return self.__rrs.get(type.upper())
  
  def rrs(self):
    '''
    Returns resource records list iterator (to L{__rrs}).
    '''
    for i in self.__rrs.keys(): #iterate through types      
      for j in self.__rrs[i]: #iterate through signatures
        yield j
        
  def rrsigs(self):
    '''
    Returns RRSIGs list iterator (to L{__rrsigs}).
    '''
    for i in self.__rrsigs.keys(): #iterate through types      
      for j in self.__rrsigs[i]: #iterate through signatures
        yield j
  
  def has_ns(self):
    '''
    Returns True, if there is some NS record present, False otherwise.
    '''
    return self.__rrs.has_key("NS")
  
  def has_ns_only(self):
    '''
    Returns True, if there are only NS record present, False otherwise. Records
    types from L{ns_exclude_list} are excluded.
    '''
    return self.__has_ns_only
    
  def add_record(self, rr):
    '''
    Looks at RR type and then places it in the right place (L{__rrs},
    L{__rrsigs} or L{__nsec}).
    @param rr: Resource record to be added.
    @type rr: U{ldns_rr<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr.html>}
    '''
    rr_type = rr.get_type()
    
    #make special record of all NSEC type records, but include it also among
    #regular records for signature verification
    if rr_type == ldns.LDNS_RR_TYPE_NSEC or rr_type == ldns.LDNS_RR_TYPE_NSEC3:
      if self.__nsec: #already present one NSEC record, that should not happen
        logging.warning("Multiple NSEC type records for single owner name (" + str(rr.owner()) + ").")
        
      self.__nsec = rr
      
      if rr_type == ldns.LDNS_RR_TYPE_NSEC:
        self.__nsec_type = self.NSEC
      else:
        self.__nsec_type = self.NSEC3
        
    #another way how to determine NSEC type
    if rr_type == ldns.LDNS_RR_TYPE_NSEC3PARAMS:
      self.__nsec_type = self.NSEC3
        
    if rr_type == ldns.LDNS_RR_TYPE_RRSIG:
      type_cov = str(rr.rrsig_typecovered()).upper()
      if not self.__rrsigs.has_key(type_cov): #this type not present, make a list for him
        self.__rrsigs[type_cov] = []
      self.__rrsigs[type_cov].append(rr)
    else: #other record, regular RR which should be signed
      if not rr_type in self.ns_exclude_list: #exclude NS and other records present every time
        self.__has_ns_only = False
        
      rr_type = rr.get_type_str().upper() #get a string representation
      
      if not self.__rrs.has_key(rr_type): #this type not present, make a list for him
        self.__rrs[rr_type] = []
      self.__rrs[rr_type].append(rr)
      
  def owner(self):
    '''
    Returns an owner of all records as a String.
    '''
    return str(self.__owner)
      
  def verify_signatures(self, trust, domain, time_check = False, tv = None):
    '''
    Verifies RRSIGs signatures with given list of trusted keys. Status of
    signatures is written out using L{logging} module.
    Also checks if I{Signers Name} field matches current L{domain}.
    
    When optional parameter L{time_check} is set to True, this checks also
    signatures time validity according to given L{TimeVerify} object as
    parameter L{tv}. Default is False.
    
    Using this this method to verify time validity and signatures together
    should make check faster and find more errors, that using this method just
    for signature check and L{verify_rrsigs_times()} for time validity check.
    
    @param trust: List of trusted keys.
    @type trust: U{ldns_rr_list<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr__list.html>}
    @param domain: Domain that should match Signers Name field of RRSIGs.
    @type domain: String
    @param time_check: Is time check of signatures needed?
    @type time_check: Boolean
    @param tv: Object to be used in time-verifying operations.
    @type tv: L{TimeVerify}
    '''
    cnt = { 'count': 0, 'invalid': 0, 'tags': [], 'typecnt': 0} #counter
    
    for rrtype in self.__rrs.keys(): #iterate through types
      rrlist = ldns.ldns_rr_list() #prepare RR for verification function
      
      for rr in self.__rrs[rrtype]: #iterate through records of that type        
        #add it to the list
        rrlist.push_rr(rr)
        cnt['typecnt'] += 1
        
      try: #signature may not be present, give it a try
        for rrsig in self.__rrsigs[rrtype]: #iterate through its signatures          
          #check signers name
          s_name = str(rrsig.rrsig_signame())
          if s_name != domain:
            logging.error('Signatures check - ' + self.owner() + ' ' + rrtype +\
                          ' - RRSIGs Signers Name does not match domain (' + s_name +
                          ' != ' + domain + ').')
          
          cnt['count'] += 1
          
          status = ldns.ldns_verify_rrsig_keylist_notime_status_only(rrlist, rrsig, trust)
          if time_check and tv.is_valid(rrsig.rrsig_inception(), rrsig.rrsig_expiration()) != \
          tv.RRSIG_VALID: #check time too
            status = ldns.LDNS_STATUS_INVALID_TIME
          
          if status != ldns.LDNS_STATUS_OK:
            cnt['invalid'] += 1 #signature does not verify this record, other however still could
          else:
            cnt['tags'].append(rrsig.rrsig_keytag())
            
      except KeyError:
        pass #this will be catched in next if
      
      if cnt['count'] == 0: #no signatures for this RR
        logging.info('Signatures check - ' + self.owner() + ' ' + rrtype + ' - ' + str(cnt['typecnt']) + ' RRs' + ' not secured.')
      elif cnt['invalid'] == cnt['count']: #all signatures for this RR type are invalid
        logging.error('Signatures check - ' + self.owner() + ' ' + rrtype + ' - ' + str(cnt['typecnt']) + ' RRs' + ', ' +\
        str(cnt['count']) + ' RRSIGs, 0 valid.')
      elif cnt['invalid'] == 0: #all signatures for this RR type are valid 
        logging.info('Signatures check - ' + self.owner() + ' ' + rrtype + ' - ' + str(cnt['typecnt']) + ' RRs' + ', ' +\
        str(cnt['count']) + ' RRSIGs, all valid.')
      else: #some signatures for this RR type are valid 
        logging.info('Signatures check - ' + self.owner() + ' ' + rrtype + ' - ' + str(cnt['typecnt']) + ' RRs' + ', ' +\
        str(cnt['count']) + ' RRSIGs, ' + str(cnt['count'] - cnt['invalid']) + ' valid (keytags: ' + self.__custom_list_print(cnt['tags']) + ').')
        
      cnt = { 'count': 0, 'invalid': 0, 'tags': [], 'typecnt': 0} #counter
        
  def verify_rrsigs_times(self, tv):
    '''
    Verifies times of RRSIGs according to given L{TimeVerify} object. The
    status if written out using L{logging} module (debug for OK, error for
    invalid, info for statistics).
    
    For checking both time and signature validity, use L{verify_signatures()}
    method.
    
    @param tv: Object to be used in time-verifying operations.
    @type tv: L{TimeVerify}
    '''
    total = { 'count': 0, 'invalid': 0, 'valid': 0, 'future': 0 }
    
    for i in self.__rrsigs.keys(): #iterate through types
      type = { 'count': 0, 'invalid': 0, 'valid': 0, 'future': 0 }
      
      for j in self.__rrsigs[i]: #iterate through signatures
        val = tv.is_valid(j.rrsig_inception(), j.rrsig_expiration())
        total['count'] += 1
        type['count'] += 1
        
        if val == tv.RRSIG_VALID:
          total['valid'] += 1
          type['valid'] += 1
        elif val == tv.RRSIG_INVALID:
          total['invalid'] += 1
          type['invalid'] += 1
        else:
          total['future'] += 1
          type['future'] += 1
      
      if type['valid'] == 0: #none of the signatures is valid for current type
        logging.error('Signatures time check - ' + self.owner() + " " + i +\
        ' - 0 valid, ' + str(type['count']) + " total, " + str(type['invalid']) +
        ' old, ' + str(type['future']) + ' future.')
      else: #some of them are time-valid
        logging.info('Signatures time check - ' + self.owner() + " " + i + ' - ' + \
        str(type['count']) + " total, " + str(type['valid']) + ' valid, ' +
        str(type['invalid']) + ' old, ' + str(type['future']) + ' future.')
    
    #statistics
    if total['count'] == 0: #no signatures checked
      logging.debug('Signatures time check - ' + self.owner() + ' no signatures.')
    elif total['count'] != type['count']: #needed only if multiple records per type
      logging.info('Signatures time check - ' + self.owner() + ' ' + \
      str(total['count']) + " total, " + str(total['valid']) + ' valid, ' +
      str(total['invalid']) + ' old, ' + str(total['future']) + ' future.')
    
  def verify_rrsigs_remaining(self, tv, tmin):
    '''
    Verifies, that remaining validity time of RRSIGs, according to given
    L{TimeVerify} object, is higher than a L{tmin} value. The status if written
    out using L{logging} module as a warning, if the value is lower.
    
    @param tv: Object to be used in time-verifying operations.
    @type tv: L{TimeVerify}
    @param tmin: Minimum remaining validity time, that is acceptable.
    @type tmin: int [seconds] 
    '''    
    for i in self.__rrsigs.keys(): #iterate through types
      tlmax = 0 #initial value
      
      for j in self.__rrsigs[i]: #iterate through signatures and max. validity time from set of signatures
        tl = tv.time_left(j.rrsig_expiration())
        if tl > tlmax:
          tlmax = tl
      
      if tlmax < tmin:
        logging.warning(self.owner() + " " + j.get_type_str() + \
        " Remaining validity time of RRSIG is too low (" + str(tlmax) + " < " +
        str(tmin) + ").")
    
  def verify_rrsigs_ttl(self):
    '''
    Verifies, that all RRSIG records have TTL lower, than total signature
    validity time (expiration - inception), all have the same TTL as record they
    cover and all have Original TTL value the same as record they cover. Status
    is written out using L{logging} module with warning severity, if any
    problems found. Also writes error when some RRSIG record does not have
    any record to cover.
    '''    
    for rr_type in self.__rrsigs.keys(): #iterate through types
      for rrsig in self.__rrsigs[rr_type]: #iterate through records of that type
        #verify total signature validity time
        if int(str(rrsig.ttl())) > TimeVerify.normalize_time(rrsig.rrsig_expiration()) - \
        TimeVerify.normalize_time(rrsig.rrsig_inception()):
          logging.warning(self.owner() + " " + rr_type + " - TTL of the RRSIG record should be lower, than the total validity time.")
          
        #rr does not have to be present
        try:
          #verify RRSIG TTL
          cnt_valid_ttl = 0 #count valid TTLs, at least one required
          cnt_valid_orig_ttl = 0 #count valid Original TTLs, at least one required
          
          for rr in self.__rrs[rr_type]:
            if rr.ttl() == rrsig.ttl():
              cnt_valid_ttl += 1
            if rr.ttl() == int(str(rrsig.rrsig_origttl())):
              cnt_valid_orig_ttl += 1
          
          if cnt_valid_ttl == 0:
            logging.warning(self.owner() + " " + rr_type + " - TTL of RRSIG does not match TTL of RR it covers.")
          if cnt_valid_orig_ttl == 0:
            logging.warning(self.owner() + " " + rr_type + " - Original TTL of RRSIG does not match TTL of RR it covers.")
        except KeyError:
          pass
        
  def verify_rrsigs_algorithms(self, alg_list):
    '''
    Verifies, that all algorithms from provided list are used to make RRSIG
    records.
    
    Prints a warning using logging module and WARNING severity, if some of
    provided algorithms is not used.
    
    @param alg_list: List of int values representing signing algorithms.
    @note: Uses L{Alg} class for internal operations.
    '''
    if len(self.__rrsigs.keys()) > 0: #if signed      
      for rr_type in self.__rrsigs.keys(): #iterate through types
        l = deepcopy(alg_list) #make a deep copy of the list, original needed later
        checked = [] #list of already checked types
        dnskey_seen = False #some DNSKEY RRSIG present?
        
        for rrsig in self.__rrsigs[rr_type]: #iterate through rrsigs
          try: #might be present algorithm but not a DNSKEY with it
            a = int(str(rrsig.rrsig_algorithm()))
            
            #DNSKEY can be signed with ZSK (256) and KSK (257), other records only with ZSK
            if rr_type != "DNSKEY" and not Alg(a,256) in checked:
              l.remove(Alg(a,256))
              checked.append(Alg(a,256))
            elif rr_type == "DNSKEY":
              dnskey_seen = True
              if Alg(a,256) not in checked and Alg(a,256) in l: #KSK
                l.remove(Alg(a,256))
                checked.append(Alg(a,256))
              elif Alg(a,257) not in checked and Alg(a,257) in l: #KSK
                l.remove(Alg(a,257))
                checked.append(Alg(a,257))
              elif Alg(a,256) not in checked and Alg(a,257) not in checked: #none of them
                raise ValueError("")
          except ValueError: #not present, couldn't be removed (but should be)
            b = ldns.ldns_buffer(0)
            ldns.ldns_algorithm2buffer_str(b,a)
            logging.warning(self.owner() + " - " + str(b) + " algorithm not expected for creating RRSIG.")
            
        #go through the rest of algorithms (there should not be any, Except ZSK)
        for alg in l:
          if alg.flag != 257 or dnskey_seen:
            b = ldns.ldns_buffer(0)
            ldns.ldns_algorithm2buffer_str(b,alg.alg)
            logging.warning(self.owner() + " - " + str(b) + " algorithm not used for creating RRSIG.")
        
  def verify_nsec_presence(self, ns_list):
    '''
    Verifies that NSEC record is present. Requires list of already seen NS RR
    domain names as a parameter, to distinguish glue records.
    
    Prints error using L{logging} module, when there is no NSEC type record and
    there is some "non-glue" record.
    
    @param ns_list: List of already seen NS RR domain names, in a String
    representation.
    @note: If A / AAAA record does not have matching NS record pointing to it, it
    does not mean that it is not glue record, NS record may appear later, so
    we should also check it at the end with complete NS records list. For this
    reason this method returns a list of "potential glue records".
    @warning: Don't use this for checking NSEC3 type record presence, it does
    not work reliably. See TODO for explanation.
    @todo: Fix NSEC3 presence verification after next release of ldns library.
    '''
    #list of potential glue A / AAAA records, that need to be checked later
    non_macthed = []
    
    if self.__nsec:
      #nsec record present, nothing else to verify
      return non_macthed
    elif self.has_ns_only():
      #only NS record, that does not require NSEC records as it is glue record
      return non_macthed
    
    #So no NSEC record is not present. That is allowed for glue records only.
    #We should verify, that all present records are glue records then.
    
    for i in self.rrs():
      if (i.get_type() != ldns.LDNS_RR_TYPE_A and i.get_type() != ldns.LDNS_RR_TYPE_AAAA):
        #not A nor AAAA record, this can never be a glue record and thus needs NSEC
        logging.error(self.owner() + " NSEC type record not present.")
        return non_macthed
      
      rr_owner = str(i.owner())
      
      try:
        #if could be removed, there was some NS record pointing to it
        ns_list.remove(rr_owner)
      except:
        #no NS record was painting to it, however it could later, so this still
        #might be A / AAAA glue record
        non_macthed.append(rr_owner)
        
    return non_macthed      
      
  def verify_nsec_bitmap(self):
    '''
    Verifies that NSEC record has in its Type Bitmap field present not only NSEC
    and RRSIG types, but also all the ones that are actually present at the same
    wners name. Prints error using L{logging} module, when some expected type is
    not present.
    '''
    if self.__nsec: #if some NSEC at all
      #make a list of record types, that should appear in bitmap field. should
      #not be empty (eg. RRSIG and NSEC only are not allowed, there would be
      #nothing to secure)
      types = self.__rrs.keys()
      
      if len(types) <= 0:
        logging.error(self.owner() + " There should be more than 2 types in NSEC bitmap field.")
      
      #get bitmap from NSEC record and make a list from it
      all_types = str(ldns.ldns_nsec_get_bitmap(self.__nsec)).strip().upper()
      bm = all_types.split(" ") #make from it a list of types
      
      if self.__nsec.get_type() == ldns.LDNS_RR_TYPE_NSEC3:
        try:
          types.remove('NSEC3') #NSEC3 itself never present (unlike NSEC)
        except:
          pass
        
        if "DS" in types or "SOA" in types: #present only for secured delegations
          types.append('RRSIG')
      elif self.__nsec.get_type() == ldns.LDNS_RR_TYPE_NSEC:
        types.append('RRSIG') #present for NSEC every time
        
      all_valid = True
      
      for t in types:
        try:
          bm.remove(t) #if present, can be removed
        except ValueError:
          logging.error(self.owner() + " " + t + " type not present in NSEC.")
          all_valid = False
      
      #if there is something left from bitmap, it does not exist and that is an error
      for t in bm:
        logging.error(self.owner() + " " + t + " type present in NSEC but does not exist.")
        all_valid = False
        
      if all_valid:
        logging.info(self.owner() + " NSEC record type coverage OK (" + all_types + ").")
          
  def verify_nsec_min_ttl(self, min_ttl):
    '''
    Verifies, that the NSEC type record has the same TTL value as "minimum TLL"
    field from SOA record. Prints warnings using L{logging} module, when they
    don't match.
    
    @param min_ttl: Minimum TTL value to be matched.
    @param min_ttl: int
    '''
    if self.__nsec:
      if int(self.__nsec.ttl()) != min_ttl:
        logging.warning(str(self.__nsec.owner()) + " NSEC record has TTL " + \
        str(self.__nsec.ttl()) + ", should be the same as SOAs minimum TTL field (" +
        str(min_ttl) + ").")
        
class ZoneProvider(object):
  '''
  Generic zone provides class. Use L{ZoneProviderFile} or L{ZoneProviderAXFR}
  for actual reading from sources and obtaining L{RRCollection} objects.
  '''
  
  __sn_path = "/tmp/dnssec_last_serial_numbers"
  '''Path to a temporary file for storing zones serial numbers.'''
  
  def __init__(self, buffer_size = 1, warn = True):
    '''
    Initializes object with given buffer size (number of L{RRCollection} objects
    to keep) and warning option.
    
    @param buffer_size: Initial buffer size. Minimum allowed value is 1 and
    means discarding when new owner name appears.
    @type buffer_size: int
    @param warn: Turns on/off warnings, when some owner name found more than
    once, but no longer in buffer.
    @type warn: Boolean
    @note: Uses L{Statistics} class to work with warnings.
    @attention: Turning on buffer warnings may be quite memory consuming.
    '''
    if buffer_size < 1:
      raise ValueError("Buffer size has to be positive number, greater or equal to 1.")
    
    self.__buff_size = int(buffer_size)
    '''Buffer size (number of L{RRCollection} objects to keep).'''
    self.__warn = warn
    '''Buffer warnings.'''
    self.__buff_ptr = []
    '''Keys to L{__buff}. This allows tracking last changed object.'''
    self.__buff = {} #buffer
    '''Dictionary of L{RRCollection} objects. Works as buffer.'''
    self.finished = False
    '''Has loading finished? If so, on reading just empty buffer.'''
    self.soa = None
    '''SOA record remebered from reading.'''
    self.domain = None
    '''Current domain.'''
    
    if warn:
      self.__warn_stat = Statistics("warning statistic")
  
  def __warning(self, name):
    '''
    Logs owner name and print warning using L{logging} module, if needed.
    
    @param name: Owner name to log.
    @type name: String
    '''
    if not self.__warn: #no warnings needed
      return
    
    if self.__warn_stat.inc(name) > 1: #seen more than once, that should no happen
      logging.warning(name + " owner name seen more than once, but no longer in memory. Verification may fail.")
      
  def __pop_rr(self):
    '''
    Pops and returns the oldest L{RRCollection} object from buffer (L{__buff}).
    Returns L{None} if there are no L{RRCollection} objects in the buffer.
    '''
    try:
      rr_ptr = self.__buff_ptr.pop(0) #get name of last used RRCollection
      rr_ret = self.__buff[rr_ptr] #remember it
      del self.__buff[rr_ptr] #delete it from buffer
      return rr_ret
    except IndexError: #there was nothing to pop, bufer was empty
      return None
  
  def match_rrs(self, rr = None):
    '''
    Joins
    U{ldns_rr<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr.html>}
    objects with the same owner name and puts it in a buffer (L{__buff}). Uses
    L{RRCollection} object to join them. Returns oldest L{RRCollection} object,
    when buffer is full or immediately if rr is None.
    
    Raises L{LoadingDone} exception when loading is finished (no objects in
    buffer L{__buff}).
    
    @param rr: Resource record to be joined.
    @type rr: U{ldns_rr<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr.html>}
    '''
    if not rr:
      rr_ret = self.__pop_rr()
      if not rr_ret:
        raise LoadingDone("Loading finished.")
      else:
        return rr_ret        
        
    rr_key = str(rr.owner()) #get owner name
    rr_ret = None
    
    if not self.__buff.has_key(rr_key): #first of that name
      if len(self.__buff) >= self.__buff_size: #buffer full
        rr_ret = self.__pop_rr()
        
      self.__buff[rr_key] = RRCollection(rr.owner()) #create new RRCollection
      self.__buff_ptr.append(rr_key) #append pointer
      self.__warning(rr_key) #make warning if necessary
      
    self.__buff[rr_key].add_record(rr) #add record to 
    
    return rr_ret
  
  def store_sn(self, z_name, sn):
    '''
    Stores a serial number from SOA record to temporary file L{__sn_path}.
    Can be used later by L{is_new()} method.
    
    @param z_name: Zone identificator (case insensitive).
    @type z_name: String
    @param sn: Serial number to be stored.
    '''
    p = ConfigParser.SafeConfigParser()
    p.read(self.__sn_path) #we don't care if exists
    
    if not p.has_section("zones"):
      p.add_section("zones")
    
    p.set("zones", str(z_name), str(sn))
    
    p.write(open(self.__sn_path, "w"))
  
  def is_new(self, z_name, store_current = True):
    '''    
    Checks serial number (SN) from SOA record and compares it with stored value.
    Returns True when SN number is higher, than the stored one or there is none
    stored yet. Returns false when current SN is lower or equal to stored one.
    
    Raises L{ValueError} in case no SOA record present.
    
    Raises ConfigParser.ParsingError in case of broken format.
    
    @param z_name: Zone identificator (case insensitive).
    @type z_name: String
    @param store_current:  When set to True, current value will be stored to 
    temporary file L{__sn_path} using L{store_sn()} method.
    '''
    if self.soa is None:
      raise ValueError("SOA record not present. Can't check serial number.")
    
    sn_new = int(str(self.soa.rdf(2)))
    
    p = ConfigParser.SafeConfigParser()
    if (len(p.read(self.__sn_path)) != 1): #if could not be read
      if store_current: #store current value if needed
        self.store_sn(z_name, sn_new)
      return True
    
    try: #these parameters are optional, ignore if the don't exist
      sn = int(p.get("zones", z_name.upper(), -1))
      if sn < sn_new:
        return True
    except ConfigParser.NoOptionError:
      if store_current: #store current value if needed
        self.store_sn(z_name, sn_new)
      return True
    except ValueError, detail:
      raise ConfigParser.ParsingError(str(detail))
    
    if store_current: #store current value if needed
      self.store_sn(z_name, sn_new)
    return False
        
class ZoneProviderFile(ZoneProvider):
  '''
  Class for providing L{RRCollection} objects from file.
  
  Uses buffer L{ZoneProvider.__buff} of variable size, to help joining discontinuous sets of
  RRs with the same owner name. Has possibility to warn, if there appear some
  discontinuous RRs and it is not possible to join them (one or more parts are
  no longer in memory).
  '''    
  
  def load_start(self, fname):
    '''
    Starts loading from provided file name. Use L{load_next()} to obtain
    L{RRCollection} objects.
    
    May raise L{FileError} exception in case of error with input file.
    
    @param fname: Path to zone master file.
    @type fname: String
    '''
    try:
      self.__fp = open(fname,"r")
      '''File pointer to opened zone master file.'''

      #state variables
      self.my_ttl = 3600
      '''State variable storing default TTL value.'''
      self.my_origin = None
      '''State variable storing default resource record origin value.'''
      self.my_prev = None
      '''State variable storing previous owner name value.'''
      
      # additional state variables
      self.last_pos = 0
      '''State variable storing last position in read file.'''
      self.line_nr = 0
      '''State variable storing count of read lines.'''
    except Exception, detail:
      raise FileError(str(detail))
    
  def load_next(self):
    '''
    Loads next L{RRCollection} object from zone master file. Use L{load_start()}
    method before calling this one.
    
    May raise L{FileError} exception in case of error in input zone master file.
    '''
    try:
      ret_rrcol = None
      
      while ret_rrcol == None and not self.finished: #while not received enough rrs
        self.last_pos = self.__fp.tell()
        ret = ldns.ldns_rr_new_frm_fp_l_(self.__fp, self.my_ttl, self.my_origin, self.my_prev) #get new RR from file
        
        status, rr, line_inc, new_ttl, new_origin, new_prev = ret  # unpack the result
        self.line_nr += line_inc # increase number of parsed lines
        self.my_prev = new_prev  # update ref to previous owner
        
        if status == ldns.LDNS_STATUS_SYNTAX_TTL:
          self.my_ttl = new_ttl  # update default TTL
        elif status == ldns.LDNS_STATUS_SYNTAX_ORIGIN:
          self.my_origin = new_origin  # update reference to origin
        elif status == ldns.LDNS_STATUS_SYNTAX_EMPTY:
          if self.last_pos == self.__fp.tell():
            self.finished = True
            break  # no advance since last read - EOF
        elif status != ldns.LDNS_STATUS_OK:
          raise FileError("Parsing error at line " + str(self.line_nr) + \
                          " of zone master file (errno = " + str(status) + ").")
          
        #here we are sure to have correct RR
        ret_rrcol = self.match_rrs(rr)
        
        if rr.get_type() == ldns.LDNS_RR_TYPE_SOA: #if SOA record set domain
          self.domain = str(rr.owner())[:-1]
          self.soa = rr
    except Exception, detail:
      raise FileError(str(detail))
    
    if self.finished:
      ret_rrcol = self.match_rrs()
    
    return ret_rrcol
  
class ZoneProviderAXFR(ZoneProvider):
  '''
  Class for providing L{RRCollection} objects from zone transfer (AXFR).
  
  Uses buffer L{ZoneProvider.__buff} of variable size, to help joining discontinuous sets of
  RRs with the same owner name. Has possibility to warn, if there appear some
  discontinuous RRs and it is not possible to join them (one or more parts are
  no longer in memory).
  '''
  
  def load_start(self, domain, resolver):
    '''
    Starts loading using zone transfer (AXFR) from provided domain using
    provided resolver.
    
    Use L{load_next()} to obtain L{RRCollection} objects.
    
    May raise L{AXFRError} exception in case of error.
    
    @param domain: Domain from which should be AXFR performed.
    @type domain: String
    @param resolver: Preconfigured resolver to be used for performing zone
    transfer.
    @type resolver: L{SafeResolver}
    '''
    #AXFR transfer
    self.domain = domain #set domain for resolving keys
    
    self.__res = resolver.resolver() #get current name server
      
    for i in range(resolver.count()): #try all name servers if needed
      status = self.__res.axfr_start(ldns.ldns_rdf.dname_new_frm_str(self.domain), ldns.LDNS_RR_CLASS_IN)
      if status == ldns.LDNS_STATUS_OK: #if ok, don't try other
        break
      else: #try other name server
        logging.debug("Can't start AXFR. Error: %s" % ldns.ldns_get_errorstr_by_id(status))
        logging.debug("Trying next name server.")
        self.__res = resolver.resolver_next()
    
    if status != ldns.LDNS_STATUS_OK:
      raise AXFRError("Can't start AXFR. Error: %s" % ldns.ldns_get_errorstr_by_id(status))
    
  def load_next(self):
    '''
    Loads next L{RRCollection} object using zone transfer. Use L{load_start()}
    method before calling this one.
    
    May raise L{AXFRError} exception in case of error.
    '''
    ret_rrcol = None
    
    while ret_rrcol == None and not self.finished: #while not received enough rrs      
      rr = self.__res.axfr_next() #fetch next
      if not rr:
        if not self.__res.axfr_complete(): # nothing more to read but transfer not completed
          raise AXFRError("Transfer not fully completed.")
        else: #end of transfer
          self.finished = True
      else: #there is a record
        if rr.get_type() == ldns.LDNS_RR_TYPE_SOA: #if SOA record remember it
          if self.soa: #already seen, do not remember again
            continue
          else: #first time seen
            self.soa = rr
        
        ret_rrcol = self.match_rrs(rr)
    
    if self.finished:
      ret_rrcol = self.match_rrs()
    
    return ret_rrcol

class ZoneChecker(object):
  '''
  A class wrapping entire zone and providing high level checking functions.
  '''
  
  __alg_deprecated = [1]
  '''List of deprecated algorithm numbers for signing.'''
    
  def __init__(self, time, safe_res):
    '''
    Constructor of the object. Needs a L{TimeVerify} object and an instance of a
    L{SafeResolver} object, to be able to perform additional DNS queries.
    Raises L{TypeError} if other classes provided.
    
    @param time: A preconfigured L{TimeVerify} object.
    @param safe_res: A preconfigured L{SafeResolver} object.
    '''
    if not isinstance(safe_res, SafeResolver):
      raise TypeError("SafeResolver class object needed as parameter.")
    
    if not isinstance(time, TimeVerify):
      raise TypeError("TimeVerify class object needed as parameter.")
    
    self.__t = time
    '''L{TimeVerify} object obratined during initialization.'''
    
    self.__a = None
    '''
    U{ldns_rr_list<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr__list.html>}
    of trust anchor records.
    '''
    
    self.init_trust_anchors() #initialize list of trust anchors
    
    self.__trusted = None
    '''List of all trusted keys, including trust anchors.'''
    
    self.__res = safe_res
    '''L{SafeResolver} object obratined during initialization.'''
    
    self.__nsec_stat = Statistics("Usage of NSEC")
    '''NSEC usage L{Statistics} object.'''
    
    self.__alg_stat = Statistics("Usage of RRSIG algorithms")
    '''RRSIG signing algorithms usage L{Statistics} object.'''
    
    self.__soa_checked = False #check only once
    '''State variable saying, whether was SOA record already checked.'''
    
    self.__ns_list = []
    '''List of already seen NS records domain names.'''
    
    self.__glue_list = []
    '''List of potential glue records.'''    
    
    self.__alg_list = []
    '''List of DNSKEY algorithms in current domain.'''
    
  def init_trust_anchors(self):
    '''
    Initializes the list of trust anchors (L{__a}) and tries to add a root
    trust anchor.
    '''
    self.__a = ldns.ldns_rr_list() #new list of trust anchors
    rr = ldns.ldns_read_anchor_file('ds-root')
    if not rr: #nothing read
      logging.error("Could not read the root trust anchor from file \"ds-root\".")
    else:
      self.__a.push_rr(rr)
      logging.debug("Root trust anchor loaded.")
        
  def load_trust_anchors(self, fnames):
    '''
    Imports trust keys from files.
    
    @param fnames: List or tuple of paths to files with trust keys.
    @type fnames: Strings
    
    @note: Uses L{init_trust_anchors()}.
    '''
    self.init_trust_anchors()
    
    if fnames: #if something new, add it
      for i in fnames:
        rr = ldns.ldns_read_anchor_file(i)
        if not rr: #nothing read
          logging.error("No trust anchor was read from file \"" + i + "\".")
        else:
          self.__a.push_rr(rr)
      
  def __get_valid_keys(self, resolver, domain, keys):
    '''
    Obtains valid DNSSEC keys for given domain, using given resolver and taking
    in consideration existing trusted keys.
    
    @param resolver: Preconfigured resolver.
    @type resolver: L{SafeResolver}
    @param domain: Domain for which should be trusted keys fetched.
    @type domain: String
    @param keys: List of trusted keys.
    @type keys: U{ldns_rr_list<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr__list.html>}
    @return: Tuple C{(<status code>, <trusted keys>)}.
    '''    
    trusted_keys = None
    ds_keys = None
    status = None 
 
    if resolver and domain and keys:
      res = resolver.resolver() #get current name server
      
      for i in range(resolver.count()): #try all name servers if needed
        trusted_keys = ldns.ldns_validate_domain_dnskey(res, domain, keys)
        if trusted_keys: #if something found, don't try other
          break
        else: #try other name server
          res = resolver.resolver_next()
        
      if trusted_keys:
        status = ldns.LDNS_STATUS_OK
      else:
        #No trusted keys in this domain, we'll have to find some in the parent domain
        status = ldns.LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;

        if ldns.ldns_rdf_size(domain) > 1:
          #Fail if we are at the root
          parent_keys = ldns.ldns_rr_list()
          parent_domain = ldns.ldns_dname_left_chop(domain)
          (status, parent_keys) = self.__get_valid_keys(resolver, parent_domain, keys)

          if parent_keys:
            #Check DS records
            for i in range(resolver.count()): #try all name servers if needed
              ds_keys = ldns.ldns_validate_domain_ds(res, domain, parent_keys)
              if ds_keys: #if something found, don't try other
                break
              else: #try other name server
                res = resolver.resolver_next()
            
            if ds_keys:
              (status, trusted_keys) = self.__get_valid_keys(resolver, domain, ds_keys)
            else:
              #No valid DS at the parent -- fail
              status = ldns.LDNS_STATUS_CRYPTO_NO_TRUSTED_DS
    
    return (status, trusted_keys);
    
  def __min_soa(self, soa):
    '''
    Returns the lowest SOA TTL value (not value of field minimum TTL!).
    '''
    min = int(str(soa.rdf(3))) #init with refresh value
    for i in range(4,7): #go through retry, expire and min values
      tmp = int(str(soa.rdf(i))) 
      if tmp < min:
        min = tmp
        
    return min
  
  def __soa_field_min(self, soa):
    '''
    Returns the field "minimum TTL" from SOA record.
    '''
    return int(str(soa.rdf(6)))
    
  def __max_soa(self, soa):
    '''
    Returns the highest TTL from SOA record.
    '''
    max = int(str(soa.rdf(3))) #init with refresh value
    for i in range(4,7): #go through retry, expire and min values
      tmp = int(str(soa.rdf(i))) 
      if tmp > max:
        max = tmp
        
    return max 
  
  def get_ds_records(self, domain):
    '''
    Gets all DS records from parent zone for given domain. Uses L{__res} for
    performing DNS queries.
    '''
    res = self.__res.resolver() #get current name server
    
    for i in range(self.__res.count()): #try all name servers if needed
      pkt = res.query(domain, ldns.LDNS_RR_TYPE_DS, ldns.LDNS_RR_CLASS_IN, ldns.LDNS_RD)
      if pkt: #if something found, don't try other
        ds_rrs = pkt.rr_list_by_type(ldns.LDNS_RR_TYPE_DS, ldns.LDNS_SECTION_ANSWER)
        if ds_rrs is not None:
          return ds_rrs
        break
      else: #try other name server
        res = self.__res.resolver_next()
    
    return [] #nothing found
  
  def get_valid_keys(self, domain):
    '''
    Tries to obtain valid keys for given domain using L{__get_valid_keys()}
    method and store them in L{__trusted} list. If there already are some keys,
    it won't try again. If after this function is C{__trusted == None},
    there were no trusted keys obtained.
    
    Also fills L{__alg_list} with obtained algorithm numbers using L{Alg} class.
    '''    
    if not self.__trusted: #keys were not obtained yet            
      self.domain = str(domain)
      
      logging.debug("Building chain of trust.")
      (status, self.__trusted) = self.__get_valid_keys(self.__res, self.domain, self.__a)
      
      #check whether there are any keys for current domain among trust anchors
      if not self.__trusted: #there is no list yet, create it
        self.__trusted = ldns.ldns_rr_list()
      for i in self.__a.rrs():
        if i.get_type() == ldns.LDNS_RR_TYPE_DNSKEY and str(i.owner()) == self.domain:
          self.__trusted.push_rr(i)
    
      if status != ldns.LDNS_STATUS_OK:
        if not self.__trusted: #if no other keys
          logging.critical('Signature check - domain ' + self.domain + ' - error while fetching trusted keys (errno = ' + str(status) + ').')
        else:
          logging.warning('Signature check - domain ' + self.domain + ' - error while fetching trusted keys (errno = ' + str(status) + '). Using only keys configured as trust anchors.')
      else:
        try:
          # This would fail if no keys present. There will be None, but it can't
          # be used as compare value, because it produces an assertion error when
          # there are some keys (eg. you can't use "if trusted_keys == None")
          logging.debug("Obtained " + str(self.__trusted.rr_count()) + " trusted keys.")
        except AttributeError:
          logging.critical('Signature check - domain ' + self.domain + ' - could not get any trusted keys.')
          
      for rr in self.__trusted.rrs():
        if rr.get_type() == ldns.LDNS_RR_TYPE_DNSKEY and str(rr.owner()) == self.domain:
          alg = Alg(int(str(rr.dnskey_algorithm())), int(str(rr.dnskey_flags())))          
          if alg not in self.__alg_list:
            self.__alg_list.append(alg)
            
  def verify_signatures(self, rrs, soa, time_check = False, tv = None):
    '''
    Checks whether at least one signature for each record from given
    L{RRCollection} object is valid (if that record is secured by a signature at
    all).
    
    @param rrs: Object to be checked.
    @type rrs: L{RRCollection}
    @param soa: SOA record.
    @type soa: U{ldns_rr<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr.html>}
    @param time_check: When set to True, forces this function to check also
    signatures times. When set to False, only signature will be check, not
    signatures times.
    @type time_check: Boolean
    @param tv: Object needed for time checking.
    @type tv: L{TimeVerify}
    
    @return: True, if there was verification possible (eg. there are some valid
    keys) or False otherwise.
    '''
    self.get_valid_keys(soa.owner())
    
    if self.__trusted:
      rrs.verify_signatures(self.__trusted, self.domain, time_check, tv)
      return True
    else:
      logging.critical('Signature check - ' + rrs.owner() + ' - no trusted keys, can\'t verify.')
      return False
    
  def verify_signatures_algorithm(self, rrs, soa):
    '''
    Verifies, that all algorithms used by DNSKEYS are also used to make RRSIG
    records. Requires SOA record to determine which DNSKEYS are for current
    domain.
    
    @param rrs: Object to be checked.
    @type rrs: L{RRCollection}
    @param soa: SOA record.
    @type soa: U{ldns_rr<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr.html>}
    
    @return: True if there was at least one DNSKEY obtained.
    '''
    self.get_valid_keys(soa.owner())
    
    if len(self.__alg_list) > 0:
      rrs.verify_rrsigs_algorithms(self.__alg_list)
      return True
    else:
      logging.critical('Signature algorithm check - ' + rrs.owner() + ' - no trusted keys for domain ' +\
                       self.domain + ', can\'t verify algorithms usage.')
      return False
  
  def verify_ttls(self, rr, soa):
    '''
    Checks whether various TTL values are OK. SOA record is checked only once.
    
    @param rr: Object to be checked.
    @type rr: L{RRCollection}
    @param soa: SOA record.
    @type soa: U{ldns_rr<http://www.nlnetlabs.nl/projects/ldns/doc/structldns__struct__rr.html>}
    '''
    if not self.__soa_checked:
      self.__minsoa = self.__min_soa(soa)
      self.__maxsoa = self.__max_soa(soa)
      self.__soa_field_min = self.__soa_field_min(soa) 
    
      if self.__minsoa < 600: #minimum TTL from SOA should not be lower, than 10 minutes
        logging.warning("Minimum TTL from SOA should not be lower than 5-10 minutes"+\
        "(600 s), to ensure successful verification of signatures. Current value is "
        + str(self.__minsoa) + ".")
        
      self.__soa_checked = True
    
    rr.verify_nsec_min_ttl(self.__soa_field_min)
    rr.verify_rrsigs_remaining(self.__t, self.__maxsoa)
    rr.verify_rrsigs_ttl()
      
  def verify_nsecs(self, rrs, disable_presence_check = False):
    '''
    Checks validity of NSEC records. In order to determine glue records (NS
    records and A / AAAA records at which it points), it remembers to what
    records points all seen NS records (until a matching A / AAAA record is
    found) and all potential A / AAAA glue records (until matching NS record
    found).
    
    At the end of checking the entire zone, should be called method
    L{write_error_remaining_glue()}, that writes on the output information about
    all records, that were marked as potential glue records, but did not have
    any matching NS record during entire zone check. 
    
    @param rrs: Object to be checked.
    @type rrs: L{RRCollection}
    @param disable_presence_check: Disables NSEC record presence check.
    This is useful for zones secured by NSEC3, because ldns library does not
    provide necessary functions to perform such a check yet.
    @type disable_presence_check: Boolean
    
    @warning: Don't use this for checking NSEC3 type record presence, it does
    not work reliably. See TODO for explanation.
    @todo: Fix NSEC3 presence verification after next release of ldns library.
    '''
    rrs.verify_nsec_bitmap()
    
    if not disable_presence_check:
      if rrs.has_ns(): #make list of NS records domain names to which they point
        for dname in rrs.get_ns_dnames():
          try: #check remove glue records
            self.__glue_list.remove(dname)
          except:
            self.__ns_list.append(dname) #remember it
        
      glue = rrs.verify_nsec_presence(self.__ns_list) #check presence
      
      #remember potential glue records and check them later
      self.__glue_list.extend(glue)
    
  def write_error_remaining_glue(self):
    '''
    Writes error on output about non-glue records that don't have matching NSEC
    records. These are generated by L{verify_nsecs()} method.
    '''
    for dname in self.__glue_list:
      logging.error(dname + " NSEC type record not present.")
    
  def verify_ds_records(self, rrs):
    '''
    Checks if all signing algorithms from DS records for current zone are used
    to create DNSKEYs (Key Signing Keys).
    
    Zone and its parent are determined from given L{RRCollection} owner name.
    This object has to contain zones DNSKEYs in order to make verification
    possible. If not, verification will probably fail.
    
    Prints error message using L{logging} module and ERROR severity.
    
    @param rrs: Object containg DNSKEY records.
    @type rrs: L{RRCollection} 
    '''
    ds_alg_found = []
    ds_alg_not_found = []    
    ds_rrs = self.get_ds_records(rrs.owner()) #get DS records
    
    if isinstance(ds_rrs, ldns.ldns_rr_list):
      ds_rrs = ds_rrs.rrs()
    
    #iterate through DS records  
    for ds in ds_rrs:
      alg = str(ds.rdf(1))          
      if alg not in ds_alg_found:
        #iterate through a list of RRs
        for rr in rrs.rrs():
          #we are interested only in KSK
          if rr.get_type() == ldns.LDNS_RR_TYPE_DNSKEY and str(rr.dnskey_flags()) == "257":
            #is there matching DNSKEY?
            if rr.compare_ds(ds):
              ds_alg_found.append(alg)
              try:
                ds_alg_not_found.remove(alg)
              except ValueError:
                pass
            elif alg not in ds_alg_not_found:
              ds_alg_not_found.append(alg)
              
    for alg in ds_alg_not_found:
      tmp = ldns.ldns_buffer(0);
      ldns.ldns_algorithm2buffer_str(tmp, int(str(alg)));
      logging.error("DS record with algorithm " + str(tmp) +
                    " found, but no DNSKEY record with the same algorithm present.")
      
  def nsec_log(self, rrs):
    '''
    Makes statistics about NSEC type records usage. For obtaining final
    statistic use L{nsec_log_print()} method. 
    '''
    self.__nsec_stat.inc(rrs.get_nsec_type())
    
  def nsec_log_print(self):
    '''
    Prints statistics about NSEC type records usage on stdout. They can be
    made by calling L{nsec_log()} method.  
    '''
    print '{0:-^80}'.format(" Statistics - NSEC usage ")
    
    not_secured = self.__nsec_stat.get(RRCollection.NSEC_NOT_SECURED)
    nsec = self.__nsec_stat.get(RRCollection.NSEC)
    nsec3 = self.__nsec_stat.get(RRCollection.NSEC3)
    other = self.__nsec_stat.get(RRCollection.NSEC_OTHER)
    
    if nsec != 0 and nsec3 == 0:
      print "Zone is secured with NSEC."
    elif nsec == 0 and nsec3 != 0:
      print "Zone is secured with NSEC3."
    elif nsec != 0 and nsec3 != 0:
      print "Zone is secured with NSEC " + '({:.2f}%)'.format((100*nsec)/(nsec+nsec3)) +\
                   " and NSEC3 " + '({:.2f}%)'.format((100*nsec3)/(nsec+nsec3)) + "."
    elif other == 0 and not_secured != 0:
      print "Zone is not secured with NSEC."
    
    if other != 0:
      print "Zone secured with unknown NSEC type algorithm."
      
  def alg_log(self, rrs):
    '''
    Makes statistics about RRSIG signing algorithm usage. For obtaining final
    statistic use L{alg_log_print()} method. 
    '''
    for alg in rrs.get_algs():
      tmp = ldns.ldns_buffer(0);
      ldns.ldns_algorithm2buffer_str(tmp, int(str(alg)));
      self.__alg_stat.inc(str(tmp))
    
  def alg_log_print(self):
    '''
    Prints statistics about RRSIG signing algorithm usage on stdout. They can be
    made by calling L{alg_log()} method. Also prints warning when some of
    present algorithms is deprecated (determined by L{__alg_deprecated} list).
    '''
    print '{0:-^80}'.format(" Statistics - RRSIG signing algorithm usage ")
    
    for i in self.__alg_stat.values():
      print i.name + ' ({:d}x, {:.2f}%)'.format(i.value, i.percent)
      if int(str(ldns.ldns_str2rdf_alg(i.name)[1])) in self.__alg_deprecated:
        print "Algorithm " + i.name + " is deprecated."