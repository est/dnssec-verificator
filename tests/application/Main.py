#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
Main module, that should be used to running the application. The goal is to
perform signature verification, time validity,
tracking of cryptographic algorithms being used, types of records for
denial of existence and inform about potential or found problems.

  - B{File}: I{Main.py}
  - B{Date}: I{20.8.2010}
  - B{Author}: I{Radek Lát, U{xlatra00@stud.fit.vutbr.cz<mailto:xlatra00@stud.fit.vutbr.cz>}}

I{Bachelor thesis - Automatic tracking of DNSSEC configuration on DNS servers} 
'''

import sys
import logging

try:
  from ParamParser import ParamParser
  from ZoneChecker import ZoneChecker, ZoneProviderFile, ZoneProviderAXFR, SafeResolver, RRCollection
  from Exceptions import AXFRError, FileError, LoadingDone, ParamError,\
    ResolverError
except ImportError, detail:
  print >>sys.stderr, "Program source files are broken:\n" + str(detail)
  sys.exit(1)

try:
  import ldns
except ImportError:
  print >>sys.stderr, "PyLDNS library is not installed!"
  sys.exit(1)


def print_help():
  '''
  Prints help to sys.stdout.
  '''
  print '''
  DNSSEC-Verificator: Automatic tracking of DNSSEC configuration on DNS servers
  
  Description:
  The goal is to perform signature verification and their time validity,
  tracking of cryptographic algorithms being used, types of records for
  denial of existence and inform about potential or found problems.
  
  Parameters:
  -h, --help       Displays this help.
  
  --config=<file>  A configuration should be loaded from specified file.
                   Anything else specified over command line will be ignored. If
                   the file does not exists, is damaged or does not contain all
                   required information, the program will end with an error.
                   
  --level=<lev>    Sets the lowest error level for being displayed on the
                   output. Possible values are debug, info, warning, error and
                   critical, default value is error.
                   
  --time=<time>    Referential time to be used when comparing times in NSEC type
                   records. Possible is static value in format %Y-%m-%d %H:%M:%S
                   (see [1] for more info), value "run" which will use the time,
                   when was program executed or "now", which will use everytime
                   current time. Default is "run".
                   
  --sformat=<str>  Format of output string with errors. See [2] for details.
                   Default is "%(asctime)s %(levelname)s: %(message)s"
                   
  --dformat=<str>  Format of time in output. See [1] for more details.
                   Default is "%Y-%m-%d %H:%M:%S"
                   
  --type=<type>    Type of input, can be "file" for zone master file or "axfr"
                   for full zone transfer. File is default.
                   
  --input=<file>   A semicolon separated list of zone files or zone fetched by
                   axfr to be checked. If a file does not exist or can't be
                   fetched it is ignored.
                   
  --anchor=<file>  A semicolon separated list of files with trust anchors. A
                   root anchor is loaded always.
                   
  --resolver=<ip>  A semicolon separated list of IP addresses that will be used
                   by resolver to make additional queries. Default list if based
                   on values from /etc/resolv.conf.
                   
  --key=<key str>  TSIG key to be during AXFR authentication. It has to be space
                   separated set of name, algorithm and key data.
                   
  --bs=<int>       Size of input buffer (in sets with same owner name). Has to
                   be positive integer greater or equal to 1. Default value 1.
                   
  --bw=<bool>      Turns on/off warnings, if one owner name seen twice but no
                   longer in memory. Valid values are true/yes/1/on and
                   false/no/0/off (case insensitive). Default value is "on".
                   
  --sn             When this parameter specified, one zone will not be checked
                   more than once, unless its serial number in SOA record
                   increases. This is disabled by default.
                   
  --check=<list>   List of checks to be performed on zone data (for valid values
                   see bellow).
                   
  --nocheck=<list> List of checks NOT to be performed on zone data (for valid
                   values see bellow). If both --check and --nocheck specified,
                   --nocheck will be ignored. If none of them specified, full
                   check will be performed.
                   
  <list>           Semicolon separated list of following values (case
                   insensitive):
                   
  RRSIG   - check RRSIG (when no RRSIG_T, will disregard time)
  RRSIG_T - check RRSIG time, when used with RRSIG, will not be used
  RRSIG_A - check if all DNSKEY algorithms are used to create RRSIG records
  RRSIG_S - make statistics about RRSIG signing algorithms usage
  NSEC    - check NSEC records
  NSEC_S  - make statistics about NSEC usage
  TTL     - check TTL values
  DS      - check all necessary DS records at parent exist

  [1] http://docs.python.org/library/time.html#time.strftime
  [2] http://docs.python.org/library/logging.html#formatter-objects
  '''
  
def main(argc, argv):
  '''
  Entry point of the whole program.
  @param argc: Count of command line parameters.
  @param argv: Command line parameters.
  '''
  try: #try to parse parameters, do all actions required to obtain valid parameters
    params = ParamParser(argv, argc)
    logging.debug('Parameters parsing and check OK.')
  except ParamError, e:
    logging.critical(e.err_msg)  
    sys.exit(e.err_code)
  
  #print help if requested and end script
  if params.is_help():
    print_help()
    sys.exit(0)
  
  res = ldns.ldns_resolver.new_frm_file() #default resolver  
  def_ip = []
  
  while True: #pop all default name servers
    ip = res.pop_nameserver()
    if ip:
      def_ip.append(str(ip))
    else:
      break
    
  if len(def_ip) == 0: #no default resolver, internet connection not available?
    logging.warning("No default resolver address available. Setting to localhost (127.0.0.1)")
    def_ip.append("127.0.0.1")
    
  safe_res = SafeResolver(res)
    
  for z in params.zones:
    try:
      ######################### PREPARE ########################################      
      if z.resolver: #custom addresses
        safe_res.set_resolver(z.resolver, z.keyname, z.keyalg, z.keydata)
      else: #default addresses
        safe_res.set_resolver(def_ip, z.keyname, z.keyalg, z.keydata)
        
      logging.debug("Resolver address source changed.")  
      zc = ZoneChecker(params.get_time(), safe_res) #create zone checker

      if z.type == "file": #type is file
        logging.debug("Loading data from zone master file.")
        provider = ZoneProviderFile(z.buffer_size, z.buffer_warn)
        provider.load_start(z.source)
      elif z.type == "axfr": #type is zone transfer
        logging.debug("Loading data over axfr.")
        provider = ZoneProviderAXFR(z.buffer_size, z.buffer_warn)
        provider.load_start(z.source, safe_res)        
      else:
        logging.critical("Unknown source type \"" + str(z.type) + "\", skipping this source.")
        continue
      
      logging.debug("Loading trust anchors.")
      zc.load_trust_anchors(z.trust)
      logging.debug("Trust anchors loaded.")
      
      ######################### VERIFY #########################################
      
      #load first RRCollection, it should include SOA record
      rrs = provider.load_next()
      
      #we need SOA record, check if there is any. if not it is an error
      if not provider.soa:
        logging.critical("No SOA record available. Skipping this source.")
        continue
      
      if z.sn_check and not provider.is_new(str(provider.soa.owner()), True):
        logging.debug("Current serial number of the zone is not higher, than the previous. Skipping this source.")
        continue        
      
      has_trusted_keys = True
      nsec3_presence_check_disabled = False
      
      logging.info('\n{0:=^80}'.format(' Verification of source ' + str(z.name) + ' '))  # use '=' as a fill char
      
      #load other RRCollections and performs checks on each of them. loading
      #finished by exception LoadingDone
      while True:
        #special checks might be needed for records with the same owner name
        #as is the zone itself (like DNSKEYs)
        if rrs.owner() == str(provider.soa.owner()):
          if rrs.get_nsec_type() == RRCollection.NSEC3:
            #there is no way to check NSEC3 presence correctly at this time
            nsec3_presence_check_disabled = True
            #print warning when this check disabled
            if z.check_wanted('NSEC'):
              logging.warning("Zone appears to be secured with NSEC3. NSEC type records presence check will be disabled.")
          if z.check_wanted('DS'):
            zc.verify_ds_records(rrs)
            if z.check_wanted_only('DS'):
              raise LoadingDone("Loading not finished, but no other records needed.")
        
        #check signatures inception and expiration dates, but only when this is
        #the only signature check
        if z.check_wanted('RRSIG_T') and not z.check_wanted('RRSIG'):
          rrs.verify_rrsigs_times(params.get_time())
        
        if has_trusted_keys:
          if z.check_wanted('RRSIG'): #check signatures and also their times, when wanted
            has_trusted_keys = zc.verify_signatures(rrs, provider.soa, z.check_wanted('RRSIG_T'),
                                                    params.get_time())
          if z.check_wanted('RRSIG_A'): #check signatures algorithms usage
            has_trusted_keys = zc.verify_signatures_algorithm(rrs, provider.soa)
          if not has_trusted_keys: #just disabled
            logging.critical("No trusted keys available. Disabling signature verification.")
            
        #log NSEC usage statistics
        if z.check_wanted('NSEC_S'):
          zc.nsec_log(rrs)
          
        #log RRSIG signing algorithm usage
        if z.check_wanted('RRSIG_S'):
          zc.alg_log(rrs)
         
        #Verifying various TTL values
        if z.check_wanted('TTL'):  
          zc.verify_ttls(rrs, provider.soa)
        
        #Verifying NSEC type records
        if z.check_wanted('NSEC'):
          zc.verify_nsecs(rrs, nsec3_presence_check_disabled)
        
        rrs = provider.load_next()
    except AXFRError, detail:
      logging.critical(str(detail))
    except FileError, detail:
      logging.critical(str(detail))
    except ResolverError, detail:
      logging.critical(str(detail))
    except LoadingDone, detail:
      #Verifying NSEC type records
      if z.check_wanted('NSEC'):
        zc.write_error_remaining_glue()
      
      logging.debug(str(detail))
      
      ######################### STATISTICS ###################################
      if z.check_wanted('NSEC_S') and not nsec3_presence_check_disabled:
        zc.nsec_log_print()
      if z.check_wanted('RRSIG_S'):
        zc.alg_log_print()

if __name__ == '__main__':
  main(len(sys.argv), sys.argv)