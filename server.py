#!/usr/bin/env python

import re
import random
import string
import xml.etree.ElementTree
import httplib
import urllib
import urlparse
import md5
import base64

import httplib2
import apiclient.discovery
import apiclient.oauth
import icalendar
import oauth2client.file
import oauth2client.tools

import wsgiref.util

# config
tasklist_id = '@default'
tmp_dir = '/tmp'
client_id='555352022035-d09npv5ih7mf9v8e7t53m5db76ll5aof.apps.googleusercontent.com'
client_secret='KwvtlxMblJwGWsjidXbDklIx'

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

statvalues = {
	'needsAction': 'NEEDS-ACTION',
	'completed': 'COMPLETED',
	'inProcess': 'IN-PROCESS',
	'cancelled': 'CANCELLED',
}

httplib.responses[207] = 'Multi-Status'

def _response(code):
	return '%i %s' % (code, httplib.responses[code])

def _tag(namespace, tagname):
	return '{%s}%s' % (namespaces[namespace], tagname)

def _pretty_xml(element, level=0):
	i = '\n' + level * '  '
	if len(element):
		if not element.text or not element.text.strip():
			element.text = i + '  '
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
		return ('<?xml version="1.0"?>\n' + xml.etree.ElementTree.tostring(element) + '\n')

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

def supported_report_set(element, environ, service):
	for report_name in ('principal-property-search', 'sync-collection'
			'expand-property', 'principal-search-property-set'):
		supported = xml.etree.ElementTree.Element(_tag('D', 'supported-report'))
		report_tag = xml.etree.ElementTree.Element(_tag('D', 'report'))
		report_tag.text = report_name
		supported.append(report_tag)
		element.append(supported)
	return element

def supported_calendar_component_set(element, environ, service):
	for component in ('VTODO', 'VEVENT', 'VJOURNAL'):
		comp = xml.etree.ElementTree.Element(_tag('C', 'comp'))
		comp.set('name', component)
		element.append(comp)
	return element

def getlastmodified(element, environ, service):
	if 'updated' in service:
		element.text = service['updated']
	return element

def calendar_description(element, environ, service):
	element.text = service['title']
	return element

def getetag(element, environ, service):
	element.text = service['etag']
	return element

def current_user_privilege(element, environ, service):
	href = xml.etree.ElementTree.Element(_tag('D', 'href'))
	href.text = environ['SCRIPT_NAME']
	element.append(href)
	return element

def current_user_privilege_set(element, environ, service):
	privilege = xml.etree.ElementTree.Element(_tag('D', 'privilege'))
	all = xml.etree.ElementTree.Element(_tag('D', 'all'))
	privilege.append(all)
	element.append(privilege)
	return element

def owner(element, environ, service):
	element.text = environ['SCRIPT_NAME']
	return element

def calendar_timezone(element, environ, service):
	return element

prop_functions = {
#	rfc 4918 (webdav)
	'resourcetype': resourcetype,
	'getlastmodified': getlastmodified,
	'displayname': displayname,

	'getctag': getetag,
	'getetag': getetag,
	'owner': owner,

#	rfc 3744 (webdav access control)
	'principal-URL': script_name,
	'principal-collection-set': script_name,

#	ietf draft desruisseaux-caldav-sched (extension to rfc4918)
	'calendar-home-set': script_name,
	'calendar-user-address-set': script_name,
	'calendar-timezone': calendar_timezone,
	'calendar-description': calendar_description,
	'supported-calendar-component-set': supported_calendar_component_set,
	'schedule-default-calendar-URL': script_name,

	'supported-report-set': supported_report_set,
	'current-user-privilege': current_user_privilege,
	'current-user-privilege-set': current_user_privilege_set,
}

def propfind(environ, service):
	headers = []

	input = environ['wsgi.input']
	data = input.read()
	if not data:
		return 'ERROR1\n', httplib.INTERNAL_SERVER_ERROR, headers

	root = xml.etree.ElementTree.fromstring(data)

	main_prop = root.find(_tag('D', 'prop'))
	if main_prop is None:
		return 'ERROR2\n', httplib.INTERNAL_SERVER_ERROR, headers

	props = main_prop.getchildren()


	multistatus = xml.etree.ElementTree.Element(_tag('D', 'multistatus'))

	is_tasklist = False

	containers = []

	if environ['PATH_INFO'] == '/' or environ['PATH_INFO'] == '' or environ['PATH_INFO'].startswith('/principals'):
		is_tasklist = True
	else:
		task_id = environ['PATH_INFO'].split('/')[1]
		try:
			task = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
			if not task:
				is_tasklist = True
			else:
				containers = [task]
		except(apiclient.http.HttpError):
			is_tasklist = True

	if is_tasklist:
		tasklist = service.tasklists().get(tasklist=tasklist_id).execute()
		tasks = service.tasks().list(tasklist=tasklist_id).execute()
		containers = [tasklist] + tasks['items']

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
				print >> environ['wsgi.errors'], 'no method for %s' % propname
			if element is not None:
				prop_element.append(element)
			else:
				prop_element.append(xml.etree.ElementTree.Element(prop.tag))
				print >> environ['wsgi.errors'], 'no method for %s' % propname
		propstat.append(prop_element)
		status = xml.etree.ElementTree.Element(_tag('D', 'status'))
		status.text = 'HTTP/1.1 %s' % _response(httplib.OK)
		propstat.append(status)
		response.append(propstat)
		multistatus.append(response)

	headers.append(('Content-Type', 'application/xml'))
	return _pretty_xml(multistatus), httplib.MULTI_STATUS, headers

def put(environ, service):
	headers = []
	resource = environ['PATH_INFO']
	if resource == '':
		return 'ERROR3', httplib.INTERNAL_SERVER_ERROR, headers
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
			return 'CONFLICT\n', httplib.CONFLICT, headers

	task = {
		'title': summary,
		'notes': 'added from CalDav client',
	}

	result = service.tasks().insert(tasklist=tasklist_id, body=task).execute()
	if result:
		return 'CREATED\n', httplib.CREATED, headers
	else:
		return 'ERROR4\n', httplib.INTERNAL_SERVER_ERROR, headers

def delete(environ, service):
	headers = []
	if environ['PATH_INFO'] != '/' and environ['PATH_INFO'] != '':
		headers.append(('Content-Length', '0'))
		task_id = environ['PATH_INFO'].split('/')[1]
		result = service.tasks().delete(tasklist=tasklist_id, task=task_id).execute()
		if not 'error' in result:
			return 'SUCCESS\n', httplib.OK, headers
		else:
			return 'ERROR5\n', httplib.INTERNAL_SERVER_ERROR, headers
	else:
		return 'NOT SUPPORTED\n', httplib.INTERNAL_SERVER_ERROR, headers

def get(environ, service):
	headers = []
	if environ['PATH_INFO'] != '/' and environ['PATH_INFO'] != '':
		headers.append(('Content-Type', 'text/calendar'))
		task_id = environ['PATH_INFO'].split('/')[1]
		task = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
		event = icalendar.Todo()
		event.add('summary', task['title'])
		event.add('status', statvalues[task['status']])
		return event.as_string() + '\n', httplib.OK, headers
	else:
		return 'NOT SUPPORTED\n', httplib.INTERNAL_SERVER_ERROR, headers

def options(environ, service):
	headers = []
	headers.append(('Allow', ', '.join(methods.keys())))
	headers.append(('DAV', '1, 2, access-control, calendar-access'))
	headers.append(('Content-Length', '0'))
	return '', httplib.NO_CONTENT, headers

def report(environ, service):
	headers = []

	if environ['PATH_INFO'] != '/':
		return 'ERROR6\n', httplib.METHOD_NOT_ALLOWED, []

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

	headers.append(('Content-Type', 'application/xml'))
	return _pretty_xml(multistatus), httplib.OK, headers

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
	output = None
	status = _response(httplib.OK)

	path = environ['SCRIPT_NAME'] + environ['PATH_INFO']

	flow = oauth2client.client.OAuth2WebServerFlow(
		client_id=client_id,
		client_secret=client_secret,
		scope='https://www.googleapis.com/auth/tasks',
		user_agent='caldav to gtasks/1')

	redirect_uri = '%s://%s%s?oauth=2' % (environ['wsgi.url_scheme'], environ['SERVER_NAME'], path)

	query = dict(urlparse.parse_qsl(environ['QUERY_STRING']))

	identifier = 'tasks' # terribly insecure

	auth_storage = '%s/%s.dat' % (tmp_dir, identifier)

	if 'oauth' in query:
		if query['oauth'] == '1':
			print >> environ['wsgi.errors'], redirect_uri
			url = flow.step1_get_authorize_url(redirect_uri)
			headers.append(('Location', url))
			status = httplib.TEMPORARY_REDIRECT
			output = 'oauth authentication required - %s?oauth=2\n' % path
		elif query['oauth'] == '2':
			flow.redirect_uri = redirect_uri
			try:
				credential = flow.step2_exchange(query['code'])
				storage = oauth2client.file.Storage(auth_storage)
				storage.put(credential)
				credential.set_store(storage)
				status = httplib.NO_CONTENT
				output = 'oauth successful\n'
			except oauth2client.client.FlowExchangeError:
				headers.append(('Location', '%s?oauth=1' % path))
				status = httplib.TEMPORARY_REDIRECT
				output = 'oauth failed\n'
	else:
		storage = oauth2client.file.Storage(auth_storage)
		credential = storage.get()

		if credential is None or credential.invalid == True:
			status = httplib.UNAUTHORIZED
			output = 'cannot authenticate with Google Tasks, visit %s?oauth=1\n' % path
		else:
			http = httplib2.Http()
			http = credential.authorize(http)

			service = apiclient.discovery.build(serviceName='tasks',
				version='v1', http=http)

			method = environ['REQUEST_METHOD']
			if method in methods:
				try:
					output, status, new_headers = methods[method](environ, service)
					headers.extend(new_headers)
				except(oauth2client.client.AccessTokenRefreshError):
					status = httplib.UNAUTHORIZED
					output = 'revisit %s?oauth=1\n' % path
			else:
				print >> environ['wsgi.errors'], '%s is not allowed' % method
				status = httplib.METHOD_NOT_ALLOWED
				output = '%s not allowed\n'

	if 'Content-Type' not in [header[0] for header in headers]:
		headers.append(('Content-Type', 'text/plain'))

	headers.append(('Content-Length', str(len(output))))
	headers.append(('Connection', 'close'))
	start_response(_response(status), headers)
	print >> environ['wsgi.errors'], output
	return [output]

if __name__ == '__main__':
	import wsgiref.simple_server
	httpd = wsgiref.simple_server.make_server('', 8000, application)
	print('Serving on port 8000')
	httpd.serve_forever()

