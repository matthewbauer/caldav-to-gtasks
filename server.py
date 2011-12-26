#!/usr/bin/env python

import re
import random
import string
import xml.etree.ElementTree
import httplib
import httplib2
import urllib
import urlparse
import md5
import base64

import apiclient.discovery
import apiclient.oauth
import icalendar
import oauth2client.file
import oauth2client.tools
import gflags

import wsgiref.util
import wsgiref.simple_server

# config
tasklist_id = '@default'
tmp_dir = '/tmp'

namespaces = {}

def add_namespace(key, namespace):
	xml.etree.ElementTree.register_namespace(key, namespace)
	namespaces[key] = namespace

add_namespace('A', 'http://apache.org/dav/props/')
add_namespace('D', 'DAV:')
add_namespace('C', 'urn:ietf:params:xml:ns:caldav')
add_namespace('CS', 'http://calendarserver.org/ns/')
add_namespace('AP', 'http://apple.com/ns/ical/')

prefix_syntax = re.compile('{(.*)}(.*)')
digest_syntax = re.compile('^Digest (.*)')

statvalues = {
	'needsAction': 'NEEDS-ACTION',
	'completed': 'COMPLETED',
	'inProcess': 'IN-PROCESS',
	'cancelled': 'CANCELLED',
}

httplib.responses[207] = 'Multi-Status'

def _response(code):
	return "%i %s" % (code, httplib.responses[code])

def _tag(namespace, tagname):
	return '{%s}%s' % (namespaces[namespace], tagname)

def _pretty_xml(element, level=0):
	"""Indent an ElementTree ``element`` and its children."""
	i = "\n" + level * "  "
	if len(element):
		if not element.text or not element.text.strip():
			element.text = i + "  "
		if not element.tail or not element.tail.strip():
			element.tail = i
		for sub_element in element:
			_pretty_xml(sub_element, level + 1)
		if not sub_element.tail or not sub_element.tail.strip():
			sub_element.tail = i
	else:
		if level and (not element.tail or not element.tail.strip()):
			element.tail = i
	if not level:
		return ('<?xml version="1.0"?>\n' + xml.etree.ElementTree.tostring(
			element, 'utf-8').decode('utf-8')).encode('utf-8')

def resourcetype(element, environ, service):
	if service['kind'] == 'tasks#taskList':
		collection = xml.etree.ElementTree.Element(_tag('D', 'collection'))
		element.append(collection)
		resourcetype = xml.etree.ElementTree.Element(_tag('C', 'calendar'))
		element.append(resourcetype)
	return element

def script_name(element, environ, service):
	href = xml.etree.ElementTree.Element(_tag('D', 'href'))
	href.text = environ['SCRIPT_NAME']
	element.append(href)
	return element

def displayname(element, environ, service):
	element.text = service['title']
	return element

def principal_url(element, environ, service):
	href = xml.etree.ElementTree.Element(_tag('D', 'href'))
	href.text = environ['SCRIPT_NAME']
	return element

def webdav_set(element, environ, service):
	if service['kind'] == 'tasks#taskList':
		href = xml.etree.ElementTree.Element(_tag('D', 'principal-collection-set'))
		href.text = environ['SCRIPT_NAME']
		element.append(href)

def supported_report_set(element, environ, service):
	for report_name in ("principal-property-search", "sync-collection"
			"expand-property", "principal-search-property-set"):
		supported = xml.etree.ElementTree.Element(_tag("D", "supported-report"))
		report_tag = xml.etree.ElementTree.Element(_tag("D", "report"))
		report_tag.text = report_name
		supported.append(report_tag)
		element.append(supported)
	return element

def getlastmodified(element, environ, service):
	if service['kind'] == 'tasks#task':
		element.text = service['updated']
		return element
	else:
		return

def calendar_description(element, environ, service):
	element.text = service['title']
	return

def getetag(element, environ, service):
	element.text = service['etag']
	return element

prop_functions = {
#	rfc 4918 (webdav)
	'resourcetype': resourcetype,
	'getlastmodified': getlastmodified,
	'displayname': displayname,

#	rfc 3744 (webdav access control)
	'principal-URL': principal_url,
	'principal-collection-set': webdav_set,

#	ietf draft desruisseaux-caldav-sched (extension to rfc4918)
	'calendar-home-set': webdav_set,
	'calendar-user-address-set': webdav_set,

	'supported-report-set': supported_report_set,
	'current-user-privilege-set': script_name,
	'schedule-default-calendar-URL': script_name,
	'calendar-description': calendar_description,

	'getctag': getetag,
	'getetag': getetag,
}

def propfind(environ, start_response, headers, service):
	headers.append(('Content-Type', 'application/xml; charset="utf-8"'))
	input = environ['wsgi.input']
	data = input.read()
	if not data:
		start_response(_response(400), headers)
		return ['error']

	root = xml.etree.ElementTree.fromstring(data)

	props = root.find(_tag('D', 'prop')).getchildren()

	multistatus = xml.etree.ElementTree.Element(_tag('D', 'multistatus'))

	if environ['PATH_INFO'] == '/':
		tasklist = service.tasklists().get(tasklist=tasklist_id).execute()
		tasks = service.tasks().list(tasklist=tasklist_id).execute()
		containers = [tasklist] + tasks['items']
	else:
		task_id = environ['PATH_INFO'].split('/')[1]
		task = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
		containers = [task]

	for container in containers:
		response = xml.etree.ElementTree.Element(_tag('D', 'response'))
		href = xml.etree.ElementTree.Element(_tag('D', 'href'))
		if container['kind'] == 'tasks#taskList':
			href.text = environ['SCRIPT_NAME']
		else:
			href.text = '%s/%s' % (environ['SCRIPT_NAME'], container['id'])
		response.append(href)
		propstat = xml.etree.ElementTree.Element(_tag('D', 'propstat'))
		prop_element = xml.etree.ElementTree.Element(_tag('D', 'prop'))
		for prop in props:
			element = xml.etree.ElementTree.Element(prop.tag)
			match = prefix_syntax.match(prop.tag)
			if match:
				propname = match.group(2)
			else:
				propname = prop.tag
			if propname in prop_functions:
				element = prop_functions[propname](element, environ, container)
			else:
				element = None
				print >> environ['wsgi.errors'], 'no method for %s' % propname
			if element is not None:
				prop_element.append(element)
			else:
				print >> environ['wsgi.errors'], 'no method for %s' % propname
		propstat.append(prop_element)
		status = xml.etree.ElementTree.Element(_tag('D', 'status'))
		status.text = 'HTTP/1.1 %s' % _response(httplib.OK)
		propstat.append(status)
		response.append(propstat)
		multistatus.append(response)

	start_response(_response(httplib.MULTI_STATUS), headers)
	data = _pretty_xml(multistatus)
	return [data]

def put(environ, start_response, headers, service):
	headers.append(('Content-Length', '0'))
	resource = environ['PATH_INFO']
	if resource == '':
		return ['']
	input = environ['wsgi.input']
	data = input.read()

	cal = icalendar.Calendar.from_string(data)
	for event in cal.walk():
		if event.name != 'VEVENT':
			continue
		if 'summary' in event:
			summary = event['summary']
		else:
			summary = 'no summary'

	tasks = service.tasks().list(tasklist=tasklist_id).execute()
	for task in tasks['items']:
		if task['title'] == summary:
			start_response(_response(httplib.CONFLICT), headers)
			return ['']

	task = {
		'title': summary,
		'notes': 'added from CalDav client',
	}

	result = service.tasks().insert(tasklist=tasklist_id, body=task).execute()
	if result:
		start_response(_response(httplib.CREATED), headers)
	else:
		start_response(_response(httplib.INTERNAL_SERVER_ERROR), headers)

	return ['']

def delete(environ, start_response, headers, service):
	if environ['PATH_INFO'] != '/' and environ['PATH_INFO'] != '':
		headers.append(('Content-Length', '0'))
		task_id = environ['PATH_INFO'].split('/')[1]
		result = service.tasks().delete(tasklist=tasklist_id, task=task_id).execute()
		if not 'error' in result:
			start_response(_response(httplib.INTERNAL_SERVER_ERROR), headers)
			return ['SUCCESS']
		else:
			start_response(_response(httplib.INTERNAL_SERVER_ERROR), headers)
			return ['FAILURE']
	else:
		start_response(_response(httplib.INTERNAL_SERVER_ERROR), headers)
		return ['NOT SUPPORTED']

def get(environ, start_response, headers, service):
	if environ['PATH_INFO'] != '/' and environ['PATH_INFO'] != '':
		headers.append(('Content-Type', 'text/calendar'))
		task_id = environ['PATH_INFO'].split('/')[1]
		task = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
		event = icalendar.Todo()
		event.add('summary', task['title'])
		event.add('status', statvalues[task['status']])
		start_response(_response(httplib.OK), headers)
		return [event.as_string()]
	else:
		start_response(_response(httplib.INTERNAL_SERVER_ERROR), headers)
		return ['NOT SUPPORTED']

def options(environ, start_response, headers, service):
	headers.append(('Allow', ', '.join(methods.keys())))
	headers.append(('DAV', '1, 2, access-control, calendar-access'))
	headers.append(('Content-Length', '0'))
	start_response(_response(httplib.NO_CONTENT), headers)
	return ['']

def report(environ, start_response, headers, service):
	if environ['PATH_INFO'] != '/':
		start_response(_response(httplib.METHOD_NOT_ALLOWED), headers)
		return ['ERROR!!!']

	start_response(_response(httplib.OK), headers)

	input = environ['wsgi.input']
	data = input.read()

	root = xml.etree.ElementTree.fromstring(data)

	props = root.find(_tag('D', 'prop')).getchildren()

	multistatus = xml.etree.ElementTree.Element(_tag('D', 'multistatus'))

	response = xml.etree.ElementTree.Element(_tag('D', 'response'))

	href = xml.etree.ElementTree.Element(_tag('D', 'href'))
	href.text = '%s' % (environ['SCRIPT_NAME'])
	response.append(href)

	propstat = xml.etree.ElementTree.Element(_tag('D', 'propstat'))

	container = service.tasklists().get(tasklist=tasklist_id).execute()
	prop_element = xml.etree.ElementTree.Element(_tag('D', 'prop'))
	for prop in props:
		element = xml.etree.ElementTree.Element(prop.tag)
		match = prefix_syntax.match(prop.tag)
		if match:
			propname = match.group(2)
		else:
			propname = prop.tag
		if propname in prop_functions:
			element = prop_functions[propname](element, environ, container)
		else:
			element = None
			print >> environ['wsgi.errors'], 'no method for %s' % propname
		if element is not None:
			prop_element.append(element)
		else:
			print >> environ['wsgi.errors'], 'no method for %s' % propname

	propstat.append(prop_element)

	status = xml.etree.ElementTree.Element(_tag('D', 'status'))
	status.text = 'HTTP/1.1 %s' % _response(httplib.OK)
	propstat.append(status)

	response.append(propstat)

	multistatus.append(response)

	return ['REPORT']

methods = {
	'OPTIONS': options,
	'PUT': put,
	'PROPFIND': propfind,
	'DELETE': delete,
	'GET': get,
	'REPORT': report,
}

def application(environ, start_response, exc_info=None):
	headers = []

	path = environ['SCRIPT_NAME'] + environ['PATH_INFO']

	flow = oauth2client.client.OAuth2WebServerFlow(
		client_id='555352022035-d09npv5ih7mf9v8e7t53m5db76ll5aof.apps.googleusercontent.com',
		client_secret='KwvtlxMblJwGWsjidXbDklIx',
		scope='https://www.googleapis.com/auth/tasks',
		user_agent='caldav to gtasks/1')

	redirect_uri = '%s://%s%s?oauth=2' % (environ['wsgi.url_scheme'], \
		environ['SERVER_NAME'], path)

	query = dict(urlparse.parse_qsl(environ['QUERY_STRING']))

	identifier = 'tasks' # terribly insecure

	auth_storage = '%s/%s.dat' % (tmp_dir, identifier)

	if 'oauth' in query:
		if query['oauth'] == '1':
			url = flow.step1_get_authorize_url(redirect_uri)
			headers.append(('Location', url))
			start_response(_response(httplib.TEMPORARY_REDIRECT), headers)
			return ['oauth authentication required - %s?oauth=2' % path]
		elif query['oauth'] == '2':
			flow.redirect_uri = redirect_uri
			try:
				credential = flow.step2_exchange(query['code'])
				storage = oauth2client.file.Storage(auth_storage)
				storage.put(credential)
				credential.set_store(storage)
				start_response(_response(httplib.NO_CONTENT), headers)
				return ['oauth successful']
			except oauth2client.client.FlowExchangeError:
				headers.append(('Location', '%s?oauth=1' % path))
				start_response(_response(httplib.TEMPORARY_REDIRECT), headers)
				return ['oauth failed']

	storage = oauth2client.file.Storage(auth_storage)
	credential = storage.get()

	if credential is None or credential.invalid == True:
		start_response(_response(httplib.UNAUTHORIZED), headers)
		return ['cannot authenticate with Google Tasks, visit %s?oauth=1' % path]

	http = httplib2.Http()
	http = credential.authorize(http)

	service = apiclient.discovery.build(serviceName='tasks',
		version='v1', http=http)

	method = environ['REQUEST_METHOD']
	if method in methods:
		try:
			return methods[method](environ, start_response, headers, service)
		except(oauth2client.client.AccessTokenRefreshError):
			start_response(_response(httplib.UNAUTHORIZED), headers)
			return ['revisit %s?oauth=1' % path]
	else:
		print >> environ['wsgi.errors'], '%s is not allowed' % method
		start_response(_response(httplib.METHOD_NOT_ALLOWED), headers)
		return ['%s not allowed' % method]

if __name__ == '__main__':
	httpd = wsgiref.simple_server.make_server('', 8000, application)
	print('Serving on port 8000)')
	httpd.serve_forever()

