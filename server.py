import re

import apiclient.discovery
import apiclient.oauth
import icalendar
import oauth2client.file
import oauth2client.tools
import gflags

import wsgiref.util
import xml.etree.ElementTree
#import http.client
import httplib
import httplib2

import urllib
import urlparse

# config
tasklist_id = '@default'

namespaces = {}

def add_namespace(key, namespace):
#	xml.etree.ElementTree.register_namespace("" if key == 'D' else key, namespace)
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

def webdav_set(element, environ, service):
	if service['kind'] == 'tasks#taskList':
		href = xml.etree.ElementTree.Element(_tag('D', 'principal-collection-set'))
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

def supported_report_set(element, environ, service):
	for report_name in ("principal-property-search", "sync-collection"
			"expand-property", "principal-search-property-set"):
		supported = xml.etree.ElementTree.Element(_tag("D", "supported-report"))
		report_tag = xml.etree.ElementTree.Element(_tag("D", "report"))
		report_tag.text = report_name
		supported.append(report_tag)
		element.append(supported)
	return element

def executable(element, environ, service):
#	element.text = 'F'
#	return element
	return

def getlastmodified(element, environ, service):
	if service['kind'] == 'tasks#task':
		element.text = service['updated']
		return element
	else:
		return element

def getcontentlength(element, environ, service):
	return

def checked_in(element, environ, service):
	return

def checked_out(element, environ, service):
	return

def schedule_inbox_url(element, environ, service):
	return

def schedule_outbox_url(element, environ, service):
	return

def dropbox_home_url(element, environ, service):
	return

def notification_url(element, environ, service):
	return

def source(element, environ, service):
	return

def pushkey(element, environ, service):
	return

def push_transports(element, environ, service):
	return

def owner(element, environ, service):
	return

def subscribed_strip_attachments(element, environ, service):
	return

def subscribed_strip_alarms(element, environ, service):
	return

def subscribed_strip_todos(element, environ, service):
	return

def current_user_privilege_set(element, environ, service):
	return

def calendar_timezone(element, environ, service):
	return

def quota_used_bytes(element, environ, service):
	return

def quota_available_bytes(element, environ, service):
	return

def schedule_default_calendar_url(element, environ, service):
	return

def schedule_calendar_url(element, environ, service):
	return

def schedule_calendar_transp(element, environ, service):
	return

def calendar_free_busy_set(element, environ, service):
	return

def supported_calendar_component_set(element, environ, service):
	return

def calendar_order(element, environ, service):
	return

def calendar_color(element, environ, service):
	element.text = 'blue'
	return element

def calendar_description(element, environ, service):
	element.text = service['title']
	return

def getetag(element, environ, service):
	element.text = service['etag']
	return element

prop_functions = {
#	rfc4918 (webdav)
	'resourcetype': resourcetype,
	'getcontentlength': getcontentlength,
	'getlastmodified': getlastmodified,
	'displayname': displayname,

#	rfc 3744 (webdav access control)
	'principal-collection-set': webdav_set,
	'principal-URL': principal_url,

#	ietf draft desruisseaux-caldav-sched (extension to rfc4918)
	'calendar-home-set': webdav_set,
	'calendar-user-address-set': webdav_set,
	'schedule-inbox-URL': schedule_inbox_url,
	'schedule-outbox-URL': schedule_outbox_url,

#	rfc 3253 (webdav versioning)
	'checked-in': checked_in,
	'checked-out': checked_out,
	'supported-report-set': supported_report_set,

#	webdav.org/mod_dav
	'executable': executable,

#	calendarserver.org
	'dropbox-home-URL': dropbox_home_url,
	'notification-URL': notification_url,

	'owner': owner,
	'push-transports': push_transports,
	'pushkey': pushkey,
	'source': source,

	'subscribed-strip-attachments': subscribed_strip_attachments,
	'subscribed-strip-alarms': subscribed_strip_attachments,
	'subscribed-strip-todos': subscribed_strip_todos,
	'current-user-privilege-set': current_user_privilege_set,
	'quota-used-bytes': quota_used_bytes,
	'quota-available-bytes': quota_available_bytes,

	'schedule-default-calendar-URL': schedule_default_calendar_url,
	'schedule-calendar-transp': schedule_calendar_transp,
	'supported-calendar-component-set': supported_calendar_component_set,

	'calendar-timezone': calendar_timezone,
	'calendar-free-busy-set': calendar_free_busy_set,
	'calendar-description': calendar_description,
	'calendar-color': calendar_color,

	'getctag': getetag,
	'getetag': getetag,
}

def propfind(environ, start_response, service):
	headers = []
	headers.append(('Content-Type', 'application/xml; charset="utf-8"'))
	input = environ['wsgi.input']
	data = input.read()
	if not data:
		start_response(_response(400), [])
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

def put(environ, start_response, service):
	headers = []
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

def delete(environ, start_response, service):
	if environ['PATH_INFO'] != '/' and environ['PATH_INFO'] != '':
		headers = []
		headers.append(('Content-Length', '0'))
		task_id = environ['PATH_INFO'].split('/')[1]
		result = service.tasks().delete(tasklist=tasklist_id, task=task_id).execute()
		if not 'error' in result:
			start_response(_response(httplib.INTERNAL_SERVER_ERROR), [])
			return ['SUCCESS']
		else:
			start_response(_response(httplib.INTERNAL_SERVER_ERROR), [])
			return ['FAILURE']
	else:
		start_response(_response(httplib.INTERNAL_SERVER_ERROR), [])
		return ['NOT SUPPORTED']

def get(environ, start_response, service):
	if environ['PATH_INFO'] != '/' and environ['PATH_INFO'] != '':
		headers = []
		headers.append(('Content-Type', 'text/calendar'))
		task_id = environ['PATH_INFO'].split('/')[1]
		task = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
		event = icalendar.Todo()
		event.add('summary', task['title'])
		event.add('status', statvalues[task['status']])
		start_response(_response(httplib.OK), headers)
		return [event.as_string()]
	else:
		start_response(_response(httplib.INTERNAL_SERVER_ERROR), [])
		return ['NOT SUPPORTED']

def options(environ, start_response, service):
	headers = []
	headers.append(('Allow', ', '.join(methods.keys())))
	headers.append(('DAV', '1, 2, access-control, calendar-access'))
	headers.append(('Content-Length', '0'))
	start_response(_response(httplib.NO_CONTENT), headers)
	return ['']

def report(environ, start_response, service):
	if environ['PATH_INFO'] != '/':
		start_response(_response(httplib.METHOD_NOT_ALLOWED), [])
		return ['ERROR!!!']

	start_response(_response(httplib.OK), [])

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
	flow = oauth2client.client.OAuth2WebServerFlow(
		client_id='555352022035-d09npv5ih7mf9v8e7t53m5db76ll5aof.apps.googleusercontent.com',
		client_secret='KwvtlxMblJwGWsjidXbDklIx',
		scope='https://www.googleapis.com/auth/tasks',
		user_agent='caldav to gtasks/1')

	storage = oauth2client.file.Storage('/tmp/tasks.dat')

	query = dict(urlparse.parse_qsl(environ['QUERY_STRING']))

	redirect_uri = '%s://%s%s?oauth=2' % (environ['wsgi.url_scheme'], \
			environ['SERVER_NAME'], environ['SCRIPT_NAME'])

	if ('oauth' in query and query['oauth'] == '1') \
			or environ['QUERY_STRING'] == 'oauth':
#		print >> environ['wsgi.errors'], environ
		url = flow.step1_get_authorize_url(redirect_uri)
		headers = []
		headers.append(('Location', url))
		start_response(_response(httplib.TEMPORARY_REDIRECT), headers)
		return ['oauth authentication required']
	elif 'oauth' in query and query['oauth'] == '2':
		headers = []
		flow.redirect_uri = redirect_uri
		try:
			credential = flow.step2_exchange(query['code'])
			storage.put(credential)
			credential.set_store(storage)
			start_response(_response(httplib.NO_CONTENT), headers)
			return ['oauth successful']
		except oauth2client.client.FlowExchangeError:
			headers.append(('Location', '%s?oauth=1' % environ['SCRIPT_NAME']))
			start_response(_response(httplib.TEMPORARY_REDIRECT), headers)
			return ['oauth failed']

	credential = storage.get()

	if credential is None or credential.invalid == True:
		headers = []
		start_response(_response(httplib.UNAUTHORIZED), headers)
		return ['cannot authenticate with Google Tasks, visit /cal?oauth=1']

	http = httplib2.Http()
	http = credential.authorize(http)

	service = apiclient.discovery.build(serviceName='tasks',
		version='v1', http=http)

	method = environ['REQUEST_METHOD']
	if method in methods:
		try:
			return methods[method](environ, start_response, service)
		except(oauth2client.client.AccessTokenRefreshError):
			start_response(_response(httplib.UNAUTHORIZED), [])
			return ['revisit /cal?oauth=1']
	else:
		print >> environ['wsgi.errors'], '%s is not allowed' % method
		start_response(_response(httplib.METHOD_NOT_ALLOWED), [])
		return ['%s not allowed' % method]

