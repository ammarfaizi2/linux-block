#!/usr/bin/env python

import os
from subprocess import *
import sys
import yaml
import pyaml
#import pprint

def check_version(doc):
	err=True
	if not ('version' in doc and doc['version'] == 1):
		print '%s: error: missing or invalid version: %s' % (doc['id'], doc['version'])
		err=False
	if not ('description' in doc and doc['description']):
		print '%s: error: missing or invalid description' % (doc['id'])
		err=False
	if not ('title' in doc and doc['title']):
		print '%s: error: missing or invalid title' % (doc['id'])
		err=False
	return err

def check_maintainer(doc):
	if not ('maintainer' in doc and doc['maintainer']):
		print '%s: error: missing or invalid maintainer' % (doc['id'])
		return False
	m=doc['maintainer']
	if not ('name' in m and m['name']):
		print '%s: error: missing maintainer' % doc['id']
		return False
	# TODO: valid email format
	return True

def check_properties(doc):
	if not 'properties' in doc:
		print '%s: warning: missing properties' % doc['id']
		return False
	err=True
	props=doc['properties']
	#print props
	if not 'compatible' in props:
		print '%s: error: no compatible property' % doc['id']
	for p in props:
		#print p
		v=props[p]
		if v is None:
			print '%s: %s: warning: missing properties' % (doc['id'], p)
			continue
		#print v
		if not 'type' in v:
			print '%s: %s: error: no type property' % (doc['id'], p)
			err = False
		else:
			type=v['type']
			if not type in ['string', 'empty', 'int', 'phandle', 'phandle-args']:
				print '%s: %s: error: invalid type property %s' % (doc['id'], p, type)			
				err = False
		if not 'constraint' in v:
			print '%s: %s: warning: no constraint property' % (doc['id'], p)
		if not 'category' in v:
			print '%s: %s: error: no category property' % (doc['id'], p)
			err = False
		else:
			category=v['category']
			if not category in ['required', 'optional', 'deprecated', 'required-for-new']:
				print '%s: %s: error: invalid category property' % (doc['id'], p)			
				err = False
	return err

def check_id(docs):
	ids =[]
	for doc in docs:
		if not doc['id']:
			return False
		#print doc['id']
		ids.append(doc['id'])
		#ids += '\n'
	ids.sort()
	print ids

def print_compat(docs):
	for doc in docs:
		props=doc['properties']
		for p in props:
			#v=p['constraint']
			v=props[p]
			if (p == 'compatible' and v['constraint']):
				print '%s - %s' % (p, v['constraint'])

def merge(user, default):
	if isinstance(user,dict) and isinstance(default,dict):
		for k,v in default.iteritems():
			if k not in user:
				user[k] = v
			else:
				user[k] = merge(user[k],v)
	if user is None:
		user = default
	return user

def merge_inherits(doc, id_map):
	if "inherits" in doc and doc['inherits'] is not None:
		inherits = doc['inherits']
		for i in inherits:
			try:
				f = open(id_map[i])
			except:
				continue
			parent_doc = yaml.load(f)
			#print parent_doc
			doc = merge(doc, parent_doc)
#	print doc
	return doc
		

def main():
	if len(sys.argv) == 2:
		input_file = open(sys.argv[1])
	elif len(sys.argv) == 1:
		input_file = sys.stdin
	else:
		print "Usage error: %s [DT yaml file]" % sys.argv[0]
		sys.exit(1)
	
	id_map = dict()
	id_list = []
	
	output = Popen(["find", "Documentation/devicetree/bindings/", "-name", "*.yaml"], stdout=PIPE).communicate()[0]
	for f in output.split('\n'):
		if f == '':
			break;
		fd = open(f)
		docs = yaml.load_all(fd)
		for doc in docs:
			if doc and doc['id']:
				#print doc['id']
				id_list.append(doc['id'])
				if id_list.count(doc['id']) >= 2:
					print "%s: warning: duplicate id '%s' also in file %s" % (f, doc['id'], id_map[doc['id']])
					continue
				id_map[doc['id']] = f
		fd.close()

	id_list.sort()


	docs=yaml.load_all(input_file)
	#print docs
	
	for doc in docs:
		doc = merge_inherits(doc, id_map)
		if doc is None:
			print "Error merging inheritted properties"
			continue

		check_version(doc)
		check_maintainer(doc)
		check_properties(doc)

#for project in yaml.load_all(open('Documentation/devicetree/bindings/spi/spi-slave.yaml')):
#    pprint.pprint(project)

if __name__ == "__main__":
	main()

