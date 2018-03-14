#!/usr/bin/env python
from flask import Flask
from flask import jsonify, render_template, redirect
from flask import request, Response
# Added for providing basic Authentication
from functools import wraps
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
app = Flask(__name__)
app.config['SECRET_KEY'] = 'onelogindemopytoolkit'
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'saml')

import os, sys
try:
	import json
except ImportError:
	# couldn't find json, try simplejson library
	import simplejson as json
import getopt
from operator import itemgetter
from distutils.version import LooseVersion

from reposadolib import reposadocommon

apple_catalog_version_map = {
    'index-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.13',
	'index-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.12',
	'index-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.11',
	'index-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.10',
	'index-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.9',
	'index-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.8',
	'index-lion-snowleopard-leopard.merged-1.sucatalog': '10.7',
	'index-leopard-snowleopard.merged-1.sucatalog': '10.6',
	'index-leopard.merged-1.sucatalog': '10.5',
	'index-1.sucatalog': '10.4',
	'index.sucatalog': '10.4',
}

# cache the keys of the catalog version map dict
apple_catalog_suffixes = apple_catalog_version_map.keys()

def versions_from_catalogs(cats):
	'''Given an iterable of catalogs return the corresponding OS X versions'''
	versions = set()

	for cat in cats:
		# take the last portion of the catalog URL path
		short_cat = cat.split('/')[-1]
		if short_cat in apple_catalog_suffixes:
			versions.add(apple_catalog_version_map[short_cat])

	return versions

def json_response(r):
	'''Glue for wrapping raw JSON responses'''
	return Response(json.dumps(r), status=200, mimetype='application/json')

###################################################################################
#
# Attempting saml auth
#

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth

def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': request.query_string
    }

def check_auth(username, password):
	'''Check if a username / password combination is valid.'''
# Change username and password here for your environment
	return username == 'admin' and password == 'password'

def authenticate():
	return Response("Couldn't verify your user/pass.", 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

def requires_auth(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		auth = request.authorization
		if not auth or not check_auth(auth.username, auth.password):
			return authenticate()
		return f(*args, **kwargs)
	return decorated
#
##################################################################################


@app.route('/', methods=['GET', 'POST'])
# Added to require basic authentication.
#@requires_auth
def index():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    errors = []
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if 'sso' in request.args:
        return redirect(auth.login())
    elif 'sso2' in request.args:
        return_to = '%sattrs/' % request.host_url
        return redirect(auth.login(return_to))
    elif 'slo' in request.args:
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']

        return redirect(auth.logout(name_id=name_id, session_index=session_index))
    elif 'acs' in request.args:
        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        if len(errors) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
    elif 'sls' in request.args:
        dscb = lambda: session.clear()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return redirect(url)
            else:
                success_slo = True

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template('margarita.html')


@app.route('/branches', methods=['GET'])
def list_branches():
	'''Returns catalog branch names and associated updates'''
	catalog_branches = reposadocommon.getCatalogBranches()

	return json_response(catalog_branches.keys())

def get_description_content(html):
	if len(html) == 0:
		return None

	# in the interest of (attempted) speed, try to avoid regexps
	lwrhtml = html.lower()

	celem = 'p'
	startloc = lwrhtml.find('<' + celem + '>')

	if startloc == -1:
		startloc = lwrhtml.find('<' + celem + ' ')

	if startloc == -1:
		celem = 'body'
		startloc = lwrhtml.find('<' + celem)

		if startloc != -1:
			startloc += 6 # length of <body>

	if startloc == -1:
		# no <p> nor <body> tags. bail.
		return None

	endloc = lwrhtml.rfind('</' + celem + '>')

	if endloc == -1:
		endloc = len(html)
	elif celem != 'body':
		# if the element is a body tag, then don't include it.
		# DOM parsing will just ignore it anyway
		endloc += len(celem) + 3

	return html[startloc:endloc]

def product_urls(cat_entry):
	'''Retreive package URLs for a given reposado product CatalogEntry.

	Will rewrite URLs to be served from local reposado repo if necessary.'''

	packages = cat_entry.get('Packages', [])

	pkg_urls = []
	for package in packages:
		pkg_urls.append({
			'url': reposadocommon.rewriteOneURL(package['URL']),
			'size': package['Size'],
			})

	return pkg_urls

@app.route('/products', methods=['GET'])
def products():
	products = reposadocommon.getProductInfo()
	catalog_branches = reposadocommon.getCatalogBranches()

	prodlist = []
	for prodid in products.keys():
		if 'title' in products[prodid] and 'version' in products[prodid] and 'PostDate' in products[prodid]:
			prod = {
				'title': products[prodid]['title'],
				'version': products[prodid]['version'],
				'PostDate': products[prodid]['PostDate'].strftime('%Y-%m-%d'),
				'description': get_description_content(products[prodid]['description']),
				'id': prodid,
				'depr': len(products[prodid].get('AppleCatalogs', [])) < 1,
				'branches': [],
				'oscatalogs': sorted(versions_from_catalogs(products[prodid].get('OriginalAppleCatalogs')), key=LooseVersion, reverse=True),
				'packages': product_urls(products[prodid]['CatalogEntry']),
				}

			for branch in catalog_branches.keys():
				if prodid in catalog_branches[branch]:
					prod['branches'].append(branch)

			prodlist.append(prod)
		else:
			print 'Invalid update!'

	sprodlist = sorted(prodlist, key=itemgetter('PostDate'), reverse=True)

	return json_response({'products': sprodlist, 'branches': catalog_branches.keys()})

@app.route('/new_branch/<branchname>', methods=['POST'])
# Added to require basic authentication.
#@requires_auth
def new_branch(branchname):
    catalog_branches = reposadocommon.getCatalogBranches()
    if branchname in catalog_branches:
        reposadocommon.print_stderr('Branch %s already exists!', branchname)
        abort(401)
    catalog_branches[branchname] = []
    reposadocommon.writeCatalogBranches(catalog_branches)

    return jsonify(result='success')

@app.route('/delete_branch/<branchname>', methods=['POST'])
# Added to require basic authentication.
#@requires_auth
def delete_branch(branchname):
    catalog_branches = reposadocommon.getCatalogBranches()
    if not branchname in catalog_branches:
        reposadocommon.print_stderr('Branch %s does not exist!', branchname)
        return

    del catalog_branches[branchname]

    # this is not in the common library, so we have to duplicate code
    # from repoutil
    for catalog_URL in reposadocommon.pref('AppleCatalogURLs'):
        localcatalogpath = reposadocommon.getLocalPathNameFromURL(catalog_URL)
        # now strip the '.sucatalog' bit from the name
        if localcatalogpath.endswith('.sucatalog'):
            localcatalogpath = localcatalogpath[0:-10]
        branchcatalogpath = localcatalogpath + '_' + branchname + '.sucatalog'
        if os.path.exists(branchcatalogpath):
            reposadocommon.print_stdout(
                'Removing %s', os.path.basename(branchcatalogpath))
            os.remove(branchcatalogpath)

    reposadocommon.writeCatalogBranches(catalog_branches)

    return jsonify(result=True);

@app.route('/add_all/<branchname>', methods=['POST'])
# Added to require basic authentication.
#@requires_auth
def add_all(branchname):
	products = reposadocommon.getProductInfo()
	catalog_branches = reposadocommon.getCatalogBranches()

	catalog_branches[branchname] = products.keys()

	reposadocommon.writeCatalogBranches(catalog_branches)
	reposadocommon.writeAllBranchCatalogs()

	return jsonify(result=True)


@app.route('/process_queue', methods=['POST'])
# Added to require basic authentication.
#@requires_auth
def process_queue():
	catalog_branches = reposadocommon.getCatalogBranches()

	for change in request.json:
		prodId = change['productId']
		branch = change['branch']

		if branch not in catalog_branches.keys():
			print 'No such catalog'
			continue

		if change['listed']:
			# if this change /was/ listed, then unlist it
			if prodId in catalog_branches[branch]:
				print 'Removing product %s from branch %s' % (prodId, branch, )
				catalog_branches[branch].remove(prodId)
		else:
			# if this change /was not/ listed, then list it
			if prodId not in catalog_branches[branch]:
				print 'Adding product %s to branch %s' % (prodId, branch, )
				catalog_branches[branch].append(prodId)

	print 'Writing catalogs'
	reposadocommon.writeCatalogBranches(catalog_branches)
	reposadocommon.writeAllBranchCatalogs()

	return jsonify(result=True)

@app.route('/dup_apple/<branchname>', methods=['POST'])
# Added to require basic authentication.
#@requires_auth
def dup_apple(branchname):
	catalog_branches = reposadocommon.getCatalogBranches()

	if branchname not in catalog_branches.keys():
		print 'No branch ' + branchname
		return jsonify(result=False)

	# generate list of (non-deprecated) updates
	products = reposadocommon.getProductInfo()
	prodlist = []
	for prodid in products.keys():
		if len(products[prodid].get('AppleCatalogs', [])) >= 1:
			prodlist.append(prodid)

	catalog_branches[branchname] = prodlist

	print 'Writing catalogs'
	reposadocommon.writeCatalogBranches(catalog_branches)
	reposadocommon.writeAllBranchCatalogs()

	return jsonify(result=True)

@app.route('/dup/<frombranch>/<tobranch>', methods=['POST'])
# Added to require basic authentication.
#@requires_auth
def dup(frombranch, tobranch):
	catalog_branches = reposadocommon.getCatalogBranches()

	if frombranch not in catalog_branches.keys() or tobranch not in catalog_branches.keys():
		print 'No branch ' + branchname
		return jsonify(result=False)

	catalog_branches[tobranch] = catalog_branches[frombranch]

	print 'Writing catalogs'
	reposadocommon.writeCatalogBranches(catalog_branches)
	reposadocommon.writeAllBranchCatalogs()

	return jsonify(result=True)

@app.route('/config_data', methods=['POST'])
def config_data():
	# catalog_branches = reposadocommon.getCatalogBranches()
	check_prods = request.json

	if len(check_prods) > 0:
		cd_prods = reposadocommon.check_or_remove_config_data_attribute(check_prods, suppress_output=True)
	else:
		cd_prods = []

	response_prods = {}
	for prod_id in check_prods:
		response_prods.update({prod_id: True if prod_id in cd_prods else False})

	print response_prods

	return json_response(response_prods)

@app.route('/remove_config_data/<product>', methods=['POST'])
def remove_config_data(product):
	# catalog_branches = reposadocommon.getCatalogBranches()
	check_prods = request.json

	products = reposadocommon.check_or_remove_config_data_attribute([product, ], remove_attr=True, suppress_output=True)

	return json_response(products)

@app.route('/metadata/')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp

def main():
	optlist, args = getopt.getopt(sys.argv[1:], 'db:p:')

	flaskargs = {}
	flaskargs['host'] = '0.0.0.0'
	flaskargs['port'] = 8089
	flaskargs['threaded'] = True

	for o, a in optlist:
		if o == '-d':
			flaskargs['debug'] = True
		elif o == '-b':
			flaskargs['host'] = a
		elif o == '-p':
			flaskargs['port'] = int(a)

	app.run(**flaskargs)

if __name__ == '__main__':
    main()
