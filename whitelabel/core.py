# -*- coding:utf-8 -*-

# from . import helpers

from pprint import pprint
import sys
import os, re
from ruamel.yaml import YAML
from urllib.parse import urlparse
import json
import boto3

if 'NO_COLOR' in os.environ:
    class bcolors:
        HEADER = ''
        OKBLUE = ''
        OKGREEN = ''
        WARNING = ''
        FAIL = 'FAIL:'
        ENDC = ''
        BOLD = ''
        UNDERLINE = ''
else:
    class bcolors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

this = sys.modules[__name__]

# Set up local valiables
this.services = {}

# Will be set to client Yaml
this.clients = {}

# Will store cloud formation cache to we can look it up when doing DNS
this.cfcache = {}

# Links CF with domains
this.cflink = {}

this.zonecache = {}

this.certs = {}

this.acm_arns = {}

# Will be set to true, if additional execution is required
this.rerun = False

this.log_bucket = os.environ['LOG_BUCKET']+".s3.amazonaws.com"

this.dry_run = 'DRY_RUN' in os.environ and os.environ['DRY_RUN']


# Set this to the Route53 Zone if you wish to
# create all domain names there (for testing) instead
# of using corresponding client zones
#
# e.g. "mytestzone.net"
this.sandbox = os.environ['DNS_SANDBOX'] if 'DNS_SANDBOX' in os.environ else None

# Adds dot to sandbox, e.g. ".mytestzone.net"
this.sandbox_dot = ("." + this.sandbox) if this.sandbox else ""

# If sandbox is set, it will search for appropriate Route53 zone
this.sandbox_zone = None


def eprint(*args, **kwargs):
    print(bcolors.WARNING, *args, bcolors.ENDC, end="", sep='', **kwargs)


def failprint(*args, **kwargs):
    print(bcolors.FAIL, *args, bcolors.ENDC, file=sys.stderr, end="", sep='', **kwargs)


def die(*args, **kwargs):
    failprint(*args, **kwargs)
    sys.exit(2)


def read_yaml_config(f):
    """
    Given a file, will read contents and return as a dictionary.
    """

    yaml=YAML(typ='safe')
    return yaml.load(open(f, 'r'))


def discover_services(defs):
    """
    Pass in service definition (as defined in service-config.yml). This 
    method will populate this.services dictionary. 

    TODO: move service discovery into services.py
    """

    eprint("==[ Fetching service details.. ]==============\n")


    for service in defs:
        # service is a dict containing service description

        if 'serverless' in service:
            eprint("%s (serverless %s): " % (service['name'], service['serverless']))

            l = boto3.client('cloudformation').describe_stacks(
                StackName=service['serverless']
            )


            l = l['Stacks'][0]['Outputs']
            url = ([item for item in l if item['OutputKey'] == 'ServiceEndpoint'][0]['OutputValue'])

            this.services[service['name']] = {'url': url, 'type':'api'}


            eprint("%s\n" % url)
            continue

        if 'endpoint' in service:
            eprint("%s (endpoint): %s\n" % (service['name'], service['endpoint']))

            url = service['endpoint']


            this.services[service['name']] = url

            continue

        if 'loadbalancer' in service:
            eprint("%s (loadbalancer %s): " % (service['name'], service['loadbalancer']))

            dns = boto3.client('elbv2').describe_load_balancers(
                Names=[service['loadbalancer']]
            )['LoadBalancers'][0]['DNSName']

            url="http://"+dns
            this.services[service['name']] = url

            eprint("%s\n" % url)

            continue

        if 's3' in service:
            eprint("%s (s3 %s): " % (service['name'], service['s3']))

            url = "s3://%s" % service['s3']
            if 'folder' in service:
                url = url + "/" + service['folder']
            eprint("%s\n" % url)

            this.services[service['name']] = url
            continue

        if 'lambda-arn' in service:
            eprint("%s (lambda-arn %s): " % (service['name'], service['lambda-arn']))

            stack,output = service['lambda-arn'].split(':')

            l = boto3.client('cloudformation').describe_stacks(
                StackName=stack
            )


            l = l['Stacks'][0]['Outputs']
            arn = ([item for item in l if item['OutputKey'] == output][0]['OutputValue'])

            this.services[service['name']] = arn


            eprint("%s\n" % arn)
            continue


        die("Incorrect service definition: ", pprint(service))


def discover_clients(defs):
    """
    Pass in client definition (as defined in client-config.yml). This 
    method will populate this.clients dictionary
    """

    eprint("==[ Processing client config ]==============\n")


    for client in defs:
        # service is a dict containing service description

       # if 'delete' in client:
            # client is due for deletion, but ignore that for now
        
        this.clients[client['domain'].lower()] = {}

        for subdomain in client['subdomains']:

            this.clients[client['domain'].lower()][subdomain['name'].lower()] = subdomain


def build_distribution_cache():
    """
    Creates local cache for all current cloudfront distributions
    """

    eprint("==[ Reading distributions ]==============\n")

    cf = boto3.client('cloudfront');
    pag = cf.get_paginator('list_distributions').paginate()
    this.cfcache = {}

    for page in pag:
        # Check if there are any current distributions.
        if 'Items' in page['DistributionList']:
          res = page['DistributionList']['Items']

          for res1 in res:
            if 'Items' not in res1['Aliases']:
                continue

            #if len(res1['Origins']) < 1:
                #continue

            # Here lets calculate if the distribution is configured correctly or needs change

            this.cfcache[res1['DomainName']] = {
                'Id': res1['Id'],
                'Alias': res1['Aliases']['Items'][0],
                'Status': res1['Status'],
                'DomainNameSrc': res1['DomainName'],
                'DomainNameDst': res1['Origins']['Items'][0]['DomainName'],
                'Origin': res1['Origins']['Items'][0],
                'ViewerCertificate': res1['ViewerCertificate'],
            }

            this.cflink[res1['Aliases']['Items'][0]] = res1['DomainName']


def get_expected_origin(domain, subdomain):
    """
    Given the subdomain definition, figure out how the distribution origin record would
    look like
    """

    if subdomain is False: 
        service=this.services['redirect']
    else:
        c = this.clients[domain][subdomain]

        service = this.services[c['service']]

        service = service.replace('{$domain}', domain).replace('{$subdomain}', subdomain)

    service_parsed = urlparse(service)

    origin = {}
    origin['CustomHeaders'] = {'Quantity':0}

    if service_parsed.scheme == 's3':
        # Create origin for S3

        origin['DomainName']=service_parsed.netloc+".s3.amazonaws.com"
        origin['Id']='MyS3Origin2'
        origin['OriginPath'] = service_parsed.path
        origin['S3OriginConfig'] = {'OriginAccessIdentity': ''}

        return origin

    if service_parsed.scheme == 'http' or service_parsed.scheme == 'https':
        origin['DomainName']=service_parsed.netloc
        origin['Id']='MyOrigin'
        origin['OriginPath'] = service_parsed.path
        origin['CustomOriginConfig'] = {
            'OriginKeepaliveTimeout': 5,
            'OriginProtocolPolicy': 'http-only',
            'HTTPPort': 80,
            'HTTPSPort': 443,
            "OriginSslProtocols": {
                "Quantity": 2,
                "Items": [
                    "SSLv3",
                    "TLSv1"
                ]
            },
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5
        }

        return origin

    die("Don't know how to convert %s to Origin config" % service)


def validate_distributions():

    """
    Will go through client configuration, and verify if existing distribution (in cache)
    are set up correctly, or would need some alteration. If 'fix' is set, will also
    perform necessary update/create/delete operations
    """

    for domain in this.clients:

        if this.clients[domain] is None: continue

        # TODO - if delete, then find all matching distributions and schedule them
        # for deletion

        eprint("--[ Validating Distributions for: %s ]---------------\n" % (domain + sandbox_dot))

        subdomains=list(this.clients[domain].items())

        if 'www' in this.clients[domain] and 'redirect' in this.services:
            print("Found subdomain 'www', will also create 'redirect' to it from %s" % (domain + sandbox_dot));
            subdomains.append([False, {'service': 'redirect'}])

        for subdomain, client in subdomains:

            fqdn = subdomain + "." + domain if subdomain is not False else domain
            fqdn = fqdn+this.sandbox_dot

            existing = 0

            # skip
            if 'type' in this.services[client['service']]: continue

            desired_origin = get_expected_origin(domain, subdomain)

            schema = urlparse(this.services[client['service']]).scheme


            for cfdns, cf in this.cfcache.items():


                # Skip records that dont match
                if cf['Alias'] != fqdn:
                    continue

                existing +=1

                # matching certificate found. Lets compare Origin with ExpectedOrigin

                cf_new=cf['Origin'].copy()


                dict_merge(cf_new, desired_origin) # mutate cf copy with desired origin

                if cf_new != cf['Origin']:

                    if cf['Status'] != 'Deployed':
                        eprint("Found update-able distribution but cannot update, Status=%s\n" % cf['Status'])
                        eprint("  %s -> %s -> %s\n" % (fqdn, cfdns, cf['DomainNameDst']))
                        #eprint("old: ", json.dumps(cf['Origin'], sort_keys=True), "\n")
                        #eprint("new: ", json.dumps(cf_new, sort_keys=True), "\n")
                        this.rerun = True

                        existing = -1
                        break

                    # eprint("old: ", json.dumps(cf['Origin'], sort_keys=True), "\n")
                    # eprint("new: ", json.dumps(cf_new, sort_keys=True), "\n")

                    if this.dry_run: 
                        eprint("DRY_RUN: Planning to update distribution %s -> %s -> %s\n" % (fqdn, cfdns, cf['DomainNameDst'] ))
                        continue

                    eprint("Updating distribution: %s -> %s -> %s\n" % (fqdn, cfdns, cf['DomainNameDst']))
                    # will have to re-run DNS after
                    this.rerun = True

                    if 'redirectMobileB3' in client and 'redirectMobileB3' in this.services:
                        # should enable redirect lambda
                        redirect_lambda = this.services['redirectMobileB3']
                    else:
                        redirect_lambda = None

                    if schema == 's3': 
                        create_distribution_s3(domain, subdomain, cf['Id'], redirect_lambda=redirect_lambda)
                    else:
                        create_distribution_custom(domain, subdomain, cf['Id'], redirect_lambda=redirect_lambda)

                    # TODO: update distribution here to match, but in case there are multiple distributions,
                    # delete them

            # Something went wrong, so skip this subdomain entirely
            if existing < 0: 
                eprint("!! Skipping %s\n" % fqdn)
                continue

            # If some suitable records were found, GOOD!
            if existing: continue

            if this.dry_run: 
                eprint("DRY_RUN: Planning to create a new distribution %s -> %s\n" % (fqdn, this.services[client['service']] ))
                continue

            eprint("Creating new distribution %s -> %s\n" % (fqdn, this.services[client['service']] ))

            this.rerun = True

            if 'redirectMobileB3' in client and 'redirectMobileB3' in this.services:
                # should enable redirect lambda
                redirect_lambda = this.services['redirectMobileB3']
            else:
                redirect_lambda = None


            if schema == 's3': 
                create_distribution_s3(domain, subdomain, redirect_lambda=redirect_lambda)
            else:
                create_distribution_custom(domain, subdomain, redirect_lambda=redirect_lambda)


def list_merge(existing, new):

    if len(existing) == 1 and len(new) == 1 and type(existing[0]) is dict and type(new[0]) is dict:
        return [dict_merge(existing[0], new[0])]

    return new


def dict_merge(existing, new):

    # new is new dictionary to me added into existing
    for key, value in new.items():

        if type(value) is dict and key in existing:
            # get node or create one
            existing[key] = dict_merge(existing[key], value)
        elif type(value) is list and key in existing:
            existing[key] = list_merge(existing[key], value)
        else:
            existing[key] = value

    return existing


def addLambdaEdge(DistributionConfig, redirect_lambda):

    DistributionConfig['DefaultCacheBehavior']['LambdaFunctionAssociations'] = {
        'Quantity': 1,
        'Items': [ {
            'LambdaFunctionARN': redirect_lambda,
            'EventType': 'origin-request',
            'IncludeBody': False
        } ]

    }

    return DistributionConfig


def create_distribution_s3(domain, subdomain, distribution_id=None, redirect_lambda=None):
    """
    Will create CloudFront distribution for a static site. Destination will be calculated
    according to the config.
    """

    fqdn = (subdomain+'.'+domain+this.sandbox_dot) if subdomain is not False else domain+sandbox_dot

    cf = boto3.client('cloudfront');
    DistributionConfig = { 
            'Comment':"Generated for client %s by V3 (service: %s)" % (domain, subdomain if not False else '_redirect'),
            'Aliases':{ 'Items': [fqdn], 'Quantity':1 },
            'Origins':{ 'Items': [ get_expected_origin(domain, subdomain) ], 'Quantity':1 },
            'Enabled': True,
            'DefaultRootObject':"index.html",
            'PriceClass':'PriceClass_100',
            'DefaultCacheBehavior': {
                'TargetOriginId': 'MyS3Origin2',
                'TrustedSigners': {'Enabled': False, 'Quantity': 0},
                'MinTTL': 0,
                'ForwardedValues': { 
                    'QueryString': False,
                    'Cookies': { 'Forward': 'none' },
                },
                'AllowedMethods': {
                    'Quantity': 2,
                    'Items': ['HEAD','GET'],
                },
                'Compress': True,
                'ViewerProtocolPolicy': 'redirect-to-https',
            },
            'CustomErrorResponses': {
                'Quantity': 1,
                'Items': [
                    {
                        'ErrorCode': 404,
                        'ResponsePagePath': '/index.html',
                        'ResponseCode': '200',
                    }
                ]
            },
            'Logging': {
                'Enabled': True,
                'Bucket': this.log_bucket,
                'Prefix': "%s/" % fqdn,
                'IncludeCookies': False,
            }
        }

    if redirect_lambda:
        die("Redirect may not be used for S3 / Static pages in %s.%s\n" % (subdomain, domain))

    # if ssl
    DistributionConfig['ViewerCertificate']={
        'ACMCertificateArn': this.acm_arns[fqdn],
        'CloudFrontDefaultCertificate': False,
        'SSLSupportMethod': 'sni-only',
        'MinimumProtocolVersion': 'TLSv1.2_2018',
    }

    if distribution_id:


        response = cf.get_distribution_config(Id=distribution_id)
        etag = response.get('ETag')
        config = response.get('DistributionConfig')
        config = dict_merge(config, DistributionConfig)
        if 'CustomOriginConfig' in config['Origins']['Items'][0]: del config['Origins']['Items'][0]['CustomOriginConfig']
        res = cf.update_distribution(
            DistributionConfig=config,
            Id=distribution_id,
            IfMatch=etag
        )
    else:
        DistributionConfig['CallerReference'] = 'cr%s' % hash(domain + '.' + (subdomain or ""))
        res = cf.create_distribution(
            DistributionConfig=DistributionConfig
        )


def create_distribution_custom(domain, subdomain, distribution_id=None, redirect_lambda = None):
    """
    Will create CloudFront distribution for a http proxying. Destination will be calculated
    according to the config.
    """

    fqdn = (subdomain+'.'+domain+this.sandbox_dot) if subdomain is not False else domain+sandbox_dot

    cf = boto3.client('cloudfront');
    DistributionConfig = { 
            #'CallerReference': 'cr%s' % hash(domain + '.' + subdomain),
            'Comment':"Generated for client %s by V3 (service: %s)" % (domain, subdomain if not False else '_redirect'),
            'Aliases':{ 'Items': [fqdn], 'Quantity':1 },
            'Origins':{ 'Items': [ get_expected_origin(domain, subdomain) ], 'Quantity':1 },
            'Enabled': True,
            'DefaultRootObject': "",
            'PriceClass':'PriceClass_100',
            'DefaultCacheBehavior': {
                'TargetOriginId': 'MyOrigin',
                'TrustedSigners': {'Enabled': False, 'Quantity': 0},
                'MinTTL': 0,
                'ForwardedValues': { 
                    'Headers': {
                        'Quantity': 1,
                        'Items': ['*'],
                    },
                    'QueryString': True,
                    'Cookies': { 'Forward': 'all' },
                },
                'AllowedMethods': {
                    'Quantity': 7,
                    'Items': ['HEAD','DELETE','POST','GET','OPTIONS','PUT','PATCH'],
                },
                'Compress': True,
                'ViewerProtocolPolicy': 'redirect-to-https',
            },
            'Logging': {
                'Enabled': True,
                'Bucket': this.log_bucket,
                'Prefix': "%s/" % fqdn,
                'IncludeCookies': False,
            }
        }

    if redirect_lambda:
        DistributionConfig = addLambdaEdge(DistributionConfig, redirect_lambda)

    # if ssl
    DistributionConfig['ViewerCertificate']={
        'ACMCertificateArn': this.acm_arns[fqdn],
        'CloudFrontDefaultCertificate': False,
        'SSLSupportMethod': 'sni-only',
        'MinimumProtocolVersion': 'TLSv1.2_2018',
    }

    if distribution_id:

        response = cf.get_distribution_config(Id=distribution_id)
        etag = response.get('ETag')
        config = response.get('DistributionConfig')
        config = dict_merge(config, DistributionConfig)

        if 'S3OriginConfig' in config['Origins']['Items'][0]: del config['Origins']['Items'][0]['S3OriginConfig']

        res = cf.update_distribution(
            DistributionConfig=config,
            Id=distribution_id,
            IfMatch=etag
        )
    else:
        DistributionConfig['CallerReference'] = 'cr%s' % hash(domain + '.' + (subdomain or ""))
        res = cf.create_distribution(
            DistributionConfig=DistributionConfig
        )


def update_route53_records():

    """
    The logic here is simple. The Route53 points to a temporary DNS provided by cloudfront, such as 
    dzivs8nzfxo1i.cloudfront.net. 
    
    Finally the Dst domain is one of our service end-point.

    This method only updates DNS.

    1. No DNS. Will create a temporary CNAME to maintenance page.
    2. Has DNS but points somewhere else. Find appropriate distribution with Status: Deployed and point to that.
    3. Has DNS and points to the right distribution - do nothing.

    Method is called twice. First at the beginning of the script.

    1. In case of failed previous run, will update DNS as it should be.
    2. Will create new DNS names with low TTL and point to maintenance page.

    Afterwards "update_certificates" will ensure we have certificates
    and "update_distribution" methods will adjust/create CloudFront distributions. When everything is done,
    this method is executed again:

    1. Will update all DNS to active distributions
    2. If any clients must be removed, will remove them
    """

    r53 = boto3.client('route53')

    for domain in this.clients:
        if this.clients[domain] is None: continue

        eprint("--[ Processing DNS for %s ]---------------\n" % domain)


        #zid = r53.list_hosted_zones_by_name(
            #DNSName=domain,
            #MaxItems="1"
        #)['HostedZones'][0]['Id']

        zone_domain = domain + this.sandbox_dot;

        while zone_domain:

            zid = r53.list_hosted_zones_by_name(
                DNSName=zone_domain,
                MaxItems="1"
            )['HostedZones'][0]

            if zid['Name'][:-1] == zone_domain: break

            # chop off the domain
            zone_domain = re.sub('^[^\.]*\.?', '', zone_domain)

        if zid['Name'][:-1] == zone_domain: 

            zid = zid['Id']

        eprint("  ZoneID: %s\n" % zid)

        # Fetch existing records, unless we have listed this zone already
        if zid not in this.zonecache:
            recs = [];
            for pag in r53.get_paginator('list_resource_record_sets').paginate(
                        HostedZoneId=zid
                    ):
                recs = recs + pag['ResourceRecordSets']

            this.zonecache[zid] = {}
            for r in recs:
                n = r['Name']
                if (r['Type'] not in ['A', 'CNAME']): continue
                this.zonecache[zid][r['Name']] = r

        subdomains=list(this.clients[domain].items())

        if 'www' in this.clients[domain] and 'redirect' in this.services:
            print("Found subdomain 'www', will also create DNS @ for 'redirect' on %s" % (domain+this.sandbox_dot));
            subdomains.append([False, {'service': 'redirect'}])

        for subdomain, cl in subdomains:

            name = subdomain

            nn = subdomain+'.'+domain+this.sandbox_dot+'.' if subdomain is not False else domain+this.sandbox_dot+'.'

            ## see if record exists, and we have maintenance dns
            fqdn=subdomain+'.'+domain if subdomain is not False else domain
            fqdn = fqdn+this.sandbox_dot

            if fqdn in this.cflink:

                actions = []
                if nn in this.zonecache[zid]:


                    if this.zonecache[zid][nn]['Type'] == 'A' and  \
                            'AliasTarget' in this.zonecache[zid][nn] and \
                            this.zonecache[zid][nn]['AliasTarget']['DNSName'] == this.cflink[fqdn]+'.':
                                continue

                    print ("EXISTS\n")
                    print (this.zonecache[zid][nn])

                    actions.append({ 
                        'Action': 'DELETE',
                        'ResourceRecordSet': this.zonecache[zid][nn]
                    })

                actions.append({ 
                    'Action': 'CREATE',
                    'ResourceRecordSet': {
                        'Name': nn,
                        'Type': 'A',
                        'AliasTarget': {
                            'HostedZoneId': 'Z2FDTNDATAQYW2',
                            'DNSName': this.cflink[fqdn]+'.',
                            'EvaluateTargetHealth': False,
                        } 
                    }
                })

                pprint(actions)

                if this.dry_run:
                    eprint("DRY_RUN:  %s -> cloudfront %s\n" % (fqdn, this.cflink[fqdn] ))
                    continue

                # Distribution exists!
                eprint("  %s -> cloudfront %s\n" % (fqdn, this.cflink[fqdn] ))
                res = r53.change_resource_record_sets(
                    HostedZoneId=zid,
                    ChangeBatch={
                        'Changes': actions
                    }
                )

            else:
                eprint("Skipping DNS for %s - distribution not ready yet\n" % ( fqdn + this.sandbox_dot ))
                this.rerun = True


def request_certificates():
    """
    For all the domains, this will request certificates. Each domain, one certificate.

    example.com will request certificate for example.com with additional name *.example.com and DNS validation.

    The certificate is then usable across all distributions.
    """

    # Get all existing certificates first
    acm=boto3.client('acm', region_name='us-east-1')
    eprint("==[ Fetching ACM data ]==============\n")

    paginator = acm.get_paginator('list_certificates')
    iterator = paginator.paginate(CertificateStatuses=['ISSUED'])

    for page in iterator:
        for cert in page['CertificateSummaryList']:
            this.certs[cert['DomainName']] = {
                'CertificateArn': cert['CertificateArn'],
                'Status': 'ISSUED'
            }

    iterator = paginator.paginate(CertificateStatuses=['PENDING_VALIDATION'])
    for page in iterator:
        for cert in page['CertificateSummaryList']:
            this.certs[cert['DomainName']] = {
                'CertificateArn': cert['CertificateArn'],
                'Status': 'PENDING_VALIDATION'
            }

    # See if we need to any new certificates for the clients
    for domain in this.clients:

        # Start by assuming that no validation is needed
        has_all_certs = True

        # next go through subdomains, check if we are missing certificates
        for subdomain in this.clients[domain]:
            # see if there is certificate for that
            # will request certificate or approve as necessary
            arn = get_cert_arn(domain, subdomain)

            if arn is None:
                has_all_certs = False
                break

            this.acm_arns[subdomain+'.'+domain+this.sandbox_dot]=arn


        if has_all_certs:
            arn = get_cert_arn(domain, None)

            if arn is None:
                has_all_certs = False
            else:
                this.acm_arns[domain+sandbox_dot]=arn

        if not has_all_certs:

            eprint("Missing SSL for %s. Must retry\n" % (domain + this.sandbox_dot))
            this.rerun = True
            this.clients[domain]=None


def get_cert_arn(domain, subdomain):
    # attempt to find good ARN for this subdomain


    if this.sandbox:
        domain = domain + sandbox_dot


    acm=boto3.client('acm', region_name='us-east-1')

    fqdn=domain if subdomain is None else subdomain+'.'+domain

    # 1 best case scenario - we have $domain cert with *.$domain as additional name
    if domain in this.certs:


        # verify that certificate is retrieved
        if 'SubjectAlternativeNames' not in this.certs[domain]:
            # retrieve cert data and populate subdomains
            cert = acm.describe_certificate(
                CertificateArn=this.certs[domain]['CertificateArn']
            )

            this.certs[domain] = cert['Certificate']

            """
            cert_subdomains = {}
            for dom in cert['Certificate']['DomainValidationOptions']:
                cert_subdomains[dom['DomainName']] = dom['ValidationStatus']

            this.certs[domain]['subdomains'] = cert_subdomains
            """


        # verify that certificate is good for us
        if this.certs[domain]['Status'] == 'ISSUED' and subdomain is not None:
            if '*.'+domain in this.certs[domain]['SubjectAlternativeNames']:
                # can use this ARN
                #print('%s.%s found wildcard %s' % (subdomain, domain, this.certs[domain]['CertificateArn']));

                return this.certs[domain]['CertificateArn']

            if subdomain+'.'+domain in this.certs[domain]['SubjectAlternativeNames']:
                # can use this ARN
                #print('%s.%s found as alternative name for %s' % (subdomain, domain, this.certs[domain]['CertificateArn']));

                return this.certs[domain]['CertificateArn']


        # perhaps it's still pending
        if this.certs[domain]['Status'] == 'PENDING_VALIDATION':
            if '*.'+domain in this.certs[domain]['SubjectAlternativeNames']:
                print('%s.%s wildcard in PENDING state %s. Trying to approve' % (subdomain, domain, this.certs[domain]['CertificateArn']));

                approve_cert(domain)

                return None

    if subdomain is not None and subdomain+'.'+domain in this.certs:
        if this.certs[fqdn]['Status'] == 'ISSUED':
            #print('%s.%s subdomain found as individual cert %s' % (subdomain, domain, this.certs[fqdn]['CertificateArn']));
            return this.certs[fqdn]['CertificateArn']

    if subdomain is None and domain in this.certs:
        if this.certs[domain]['Status'] == 'ISSUED':
            #print('%s found as individual cert %s' % (domain, this.certs[domain]['CertificateArn']));
            return this.certs[domain]['CertificateArn']

    request_cert(domain)

    return None


def approve_cert(domain):

    if '_approved' in this.certs[domain]: 
        print("Already approved cert for this domain")
        return

    if 'DomainValidationOptions' not in this.certs[domain]:
        # retrieve cert data and populate subdomains
        cert = acm.describe_certificate(
            CertificateArn=this.certs[domain]['CertificateArn']
        )
        print("refetching")

        this.certs[domain] = cert['Certificate']

    val=this.certs[domain]['DomainValidationOptions'][0]
    if 'ResourceRecord' not in val:
        pprint(this.certs[domain])
        this.rerun=True
        eprint("ResourceRecord is not provided for certificate (%s). Probably just requested.\n", this.certs[domain]['CertificateArn'])
        return

    r53=boto3.client('route53')

    zid = None

    zone_domain = domain;

    while zone_domain:

        zid = r53.list_hosted_zones_by_name(
            DNSName=zone_domain,
            MaxItems="1"
        )['HostedZones'][0]

        if zid['Name'][:-1] == zone_domain: break

        # chop off the domain
        zone_domain = re.sub('^[^\.]*\.?', '', zone_domain)


    if not zone_domain:
        die ("Zone for domain %s is not in Route53\n" % domain)

    if domain != zone_domain:
        eprint("Could not find Route53 zone %s so added into %s instead\n" % (domain, zone_domain))
    
    zid = zid['Id']

    if this.dry_run: 
        eprint("DRY_RUN: About to DNS record %s to verify domain %s\n" % ( val['ResourceRecord']['Name'], domain ))
        return

    res = r53.change_resource_record_sets(
        HostedZoneId=zid,
        ChangeBatch={
            'Changes': [ { 
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': val['ResourceRecord']['Name'],
                    'Type': val['ResourceRecord']['Type'],
                    'TTL': 300,
                    'ResourceRecords': [ {
                        'Value': val['ResourceRecord']['Value']
                    } ]
                }
            } ]
        }
    )

    this.certs[domain]['_approved'] = True


def request_cert(domain):

    eprint('No suitable certificate for %s. Requesting.\n' % domain)
    if this.dry_run: 
        eprint("DRY_RUN: Planning request certificate for *.%s\n" % ( domain ))
        return


    acm=boto3.client('acm', region_name='us-east-1')
    res = acm.request_certificate(
        DomainName=domain,
        ValidationMethod='DNS',
        SubjectAlternativeNames=[
            '*.'+domain,
        ],
    )

    cert = acm.describe_certificate(
        CertificateArn=res['CertificateArn']
    )

    this.certs[domain] = cert['Certificate']
    if cert['Certificate']['Status'] == 'PENDING_VALIDATION':
        approve_cert(domain)


def fullfill_api_gateways():

    """
    Go through API gateway setup, add missing domains and set up assotiations between
    them and correct stage of the API

    E.G. if you are deploying infra "ms-qa" and wish to use domain api.example.com then
    this domain will be registered and association will be set up to
    https://api-id.execute-api.region.amazonaws.com/msqa
    """

    eprint("==[ Setting up gateways ]==============\n")

    apigw = boto3.client('apigateway');

    for domain in this.clients:

        if this.clients[domain] is None: continue

        # TODO - if delete, then find all matching distributions and schedule them
        # for deletion

        subdomains=list(this.clients[domain].items())

        for subdomain, client in subdomains:
            fqdn = subdomain + "." + domain if subdomain is not False else domain
            fqdn = fqdn + this.sandbox_dot

            existing = 0

            # skip
            if 'type' not in this.services[client['service']]: continue

            url = urlparse(this.services[client['service']]['url'])

            apiid = url.netloc.split('.')[0]
            stage = url.path.split('/')[1]

            # lookup if this domain exists

            eprint("Checking API association for %s.. " % fqdn);

            try:
                res = apigw.get_domain_name(domainName=fqdn);
                eprint('exists, ')

                try:
                    res2 = apigw.get_base_path_mapping(domainName=fqdn, basePath="(none)");
                    #eprint("yep\nstage=%s" % res2['stage'])

                    if res2['stage'] == stage:
                        eprint("and mapped correctly to %s\n" % res2['stage'])

                    else:

                        if this.dry_run:
                            eprint("DRY RUN: will fix mapping\n%s ---> %s.." % (res2['stage'], stage))
                            continue

                        eprint("but mapped incorrectly\n%s ---> %s.." % (res2['stage'], stage))

                        apigw.delete_base_path_mapping(domainName=fqdn, basePath="(none)");
                        apigw.create_base_path_mapping(
                            domainName=fqdn,
                            basePath='',
                            restApiId=apiid,
                            stage=stage
                        )
                        eprint("done\n")
                        
                except:
                    if this.dry_run:
                        eprint("DRY RUN: no mapping. Will add!\n")
                        continue

                    eprint('but no mapping. Mapping\n')
                    apigw.create_base_path_mapping(
                        domainName=fqdn,
                        basePath='',
                        restApiId=apiid,
                        stage=stage
                    )

            except:
                eprint('CREATING endpoint and mapping.. ')

                if this.dry_run:
                    eprint("DRY RUN: no endpoint. will create..")
                    continue

                try:
                    res = apigw.create_domain_name(
                        domainName=fqdn,
                        certificateArn = this.acm_arns[fqdn],
                        endpointConfiguration={
                            'types': [
                                'EDGE',
                            ]
                        }
                    )


                    apigw.create_base_path_mapping(
                        domainName=fqdn,
                        basePath='',
                        restApiId=apiid,
                        stage=stage
                    )
                    eprint('OK\n')
                except:
                    failprint('ERROR.. \n')

                    eprint('Distribution or DNS record may be interfering with API gateway.. ')
                    eprint('Delete domain in Route53 manually: %s' % fqdn)


            this.cflink[fqdn] = res['distributionDomainName']


def lookup_sandbox_zone():

    """ 
    Will go and look for the most appropriate zone for sandbox
    """


def main():
    """huhh"""


    if this.dry_run:
        eprint('DRY RUN ENGAGED.......\n')

    try:
        yaml=read_yaml_config('service-config.yml')
        discover_services(yaml.get('ServiceConfig', yaml.get('serviceconfig')))
    except TypeError:
        failprint('Problem in service-config.yml file\n')
        raise

    try:
        yaml=read_yaml_config('client-config.yml')
        discover_clients(yaml.get('ClientConfig', yaml.get('clientconfig')))
    except TypeError:
        failprint('Problem in client-config.yml file\n')
        raise


    lookup_sandbox_zone()

    build_distribution_cache()

    request_certificates()

    fullfill_api_gateways()

    update_route53_records()

    validate_distributions()



    #update_route53_records()

    #discover_services(read_services_config('service-config.yml'))


    if this.rerun:
        eprint('ALL DONE BUT MUST RE-RUN!!\n')
        sys.exit(2)
    else:
        eprint('ALL DONE\n')
        sys.exit(0)

