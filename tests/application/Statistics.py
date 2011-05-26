#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
Contains classes for tracking statistics.

  - B{File}: I{ZoneChecker.py}
  - B{Date}: I{12.2.2011}
  - B{Author}: I{Radek Lát, U{xlatra00@stud.fit.vutbr.cz<mailto:xlatra00@stud.fit.vutbr.cz>}}

I{Bachelor thesis - Automatic tracking of DNSSEC configuration on DNS servers}
'''

class Statistics(object):
  '''
  Provides a way to track occurrences of any string.
  '''

  def __init__(self, title):
    '''
    @param title: Object is initialized with this title.
    '''
    self.title = title
    self.__track = {}
    self.__sum = 0
    
  def inc(self, name, value = 1):
    '''
    Increases value of given name, by default by 1.
    @param name: Name for which should be value changed.
    @param value: A value that should be added to given name, can be also
    negative or even zero.
    @return: New value for given name.
    '''
    if self.__track.has_key(name): #already some value, safe to add
      self.__track[name] += value
    else: #first time seen
      self.__track[name] = value
      
    self.__sum += value
      
    return self.__track[name]
  
  def dec(self, name, value = 1):
    '''
    Decreases value of given name, by default by 1.
    @param name: Name for which should be value changed.
    @param value: A value that should be subtracted from given name, can be also
    negative or even zero.
    @return: New value for given name.
    '''
    if self.__track.has_key(name): #already some value, safe to add
      self.__track[name] -= value
    else: #first time seen
      self.__track[name] = value
      
    self.__sum -= value
      
    return self.__track[name]
  
  def get(self, name):
    '''
    Gets value of given name.
    @param name: Name which value should be returned.
    @return: Returns 0 if specified name is not present. It's value otherwise.
    '''
    return self.__track.get(name, 0)
  
  def __str__(self):
    return self.title + ': ' + str(len(self.__track)) + " values"
  
  def values(self):
    '''
    Iterator that returns all values in custom class.
    @return: In each iteration returns class Stat with attributes I{name}, 
    I{value} and I{percent}.
    '''
    class Stat:
      pass
    
    for key in self.__track.keys():
      s = Stat()
      s.name = key
      s.value = self.__track[key]
      s.percent = (100.0 * s.value) / self.__sum
      yield s
  