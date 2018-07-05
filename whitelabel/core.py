# -*- coding:utf-8 -*-

# from . import helpers

from __future__ import print_function, division, unicode_literals

from pprint import pprint
import sys
from ruamel.yaml import YAML
from urllib.parse import urlparse
import json
import boto3

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

this.cfcache = {}

this.cflink = {}

# This will be set to DNS name, which we will use as CNAME
# destination 
this.maintenance_dns = "maintenance.romdev4.infrastructure.mymedsleuth.com"

# Set this to the Route53 Zone if you wish to
# create all domain names there (for testing) instead
# of using corresponding client zones
this.sandbox = ""
this.sandbox_dot = ""

this.sandbox_zone = None

this.zonecache = {}

this.certs = {}

this.acm_arns = {}

this.log_bucket = os.environ['LOG_BUCKET'] #"ms-qa-logs.s3.amazonaws.com"

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
        
        this.clients[client['domain']] = {}

        for subdomain in client['subdomains']:

            this.clients[client['domain']][subdomain['name']] = subdomain


def build_distribution_cache():
    """
    Creates local cache for all current cloudfront distributions
    """

    eprint("==[ Reading distributions ]==============\n")

    cf = boto3.client('cloudfront');
    pag = cf.get_paginator('list_distributions').paginate()
    this.cfcache = {}

    for page in pag:
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
        origin['DomainName']=service_parsed.netloc+this.sandbox
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

def validate_distributions(fix=False):

    """
    Will go through client configuration, and verify if existing distribution (in cache)
    are set up correctly, or would need some alteration. If 'fix' is set, will also
    perform necessary update/create/delete operations
    """

    for domain in this.clients:

        if this.clients[domain] is None: continue

        # TODO - if delete, then find all matching distributions and schedule them
        # for deletion

        eprint("--[ Validating Distributions for: %s ]---------------\n" % domain)

        subdomains=list(this.clients[domain].items())

        if 'www' in this.clients[domain] and 'redirect' in this.services:
            print("Found subdomain 'www', will also create 'redirect' to it from %s" % domain);
            subdomains.append([False, {'service': 'redirect'}])

        for subdomain, client in subdomains:

            fqdn = subdomain + "." + domain if subdomain is not False else domain

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
                        eprint("old: ", json.dumps(cf['Origin'], sort_keys=True), "\n")
                        eprint("new: ", json.dumps(cf_new, sort_keys=True), "\n")

                        existing = -1
                        break



                    #eprint("old: ", json.dumps(cf['Origin'], sort_keys=True), "\n")
                    #eprint("new: ", json.dumps(cf_new, sort_keys=True), "\n")

                    if not fix: continue

                    eprint("Updating distribution: %s -> %s -> %s\n" % (fqdn, cfdns, cf['DomainNameDst']))

                    if schema == 's3': 
                        create_distribution_s3(domain, subdomain, cf['Id'])
                    else:
                        create_distribution_custom(domain, subdomain, cf['Id'])

                    # TODO: update distribution here to match, but in case there are multiple distributions,
                    # delete them

            # Something went wrong, so skip this subdomain entirely
            if existing < 0: 
                eprint("!! Skipping %s\n" % fqdn)
                continue

            # If some suitable records were found, GOOD!
            if existing: continue

            if not fix: 
                eprint("Missing distribution %s -> %s\n" % (fqdn, this.services[client['service']] ))
                continue

            eprint("Creating new distribution %s -> %s\n" % (fqdn, this.services[client['service']] ))


            if schema == 's3': 
                create_distribution_s3(domain, subdomain)
            else:
                create_distribution_custom(domain, subdomain)

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

def create_distribution_s3(domain, subdomain, distribution_id=None):
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
                    "Headers": {
                        "Quantity": 0,
                        'Items': []
                    },
                    'Cookies': { 'Forward': 'none' },
                },
                'AllowedMethods': {
                    'Quantity': 2,
                    'Items': ['HEAD','GET'],
                },
                'Compress': True,
                'ViewerProtocolPolicy': 'allow-all',
            },
            'Logging': {
                'Enabled': True,
                'Bucket': this.log_bucket,
                'Prefix': "%s/" % fqdn,
                'IncludeCookies': False,
            }
        }

    # if ssl
    DistributionConfig['ViewerCertificate']={
        'ACMCertificateArn': this.acm_arns[fqdn],
        'CloudFrontDefaultCertificate': False,
        'SSLSupportMethod': 'sni-only',
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


def create_distribution_custom(domain, subdomain, distribution_id=None):
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

    # if ssl
    DistributionConfig['ViewerCertificate']={
        'ACMCertificateArn': this.acm_arns[fqdn],
        'CloudFrontDefaultCertificate': False,
        'SSLSupportMethod': 'sni-only',
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
    dzivs8nzfxo1i.cloudfront.net. This cloudfront distribution has Source and DST domain:


    'dzivs8nzfxo1i.cloudfront.net': {'Alias': 'www.legacylivingkidneydonor.org.ms-qa.mymedsleuth.com',
                                  'DomainNameDst': 'ms-qa-static.s3.amazonaws.com',
                                  'DomainNameSrc': 'dzivs8nzfxo1i.cloudfront.net',
                                  'Id': 'E2I4NKMFXV8WTM',
                                  'Status': 'Deployed',
                                  'ViewerCertificate': {'CertificateSource': 'cloudfront',
                                                        'CloudFrontDefaultCertificate': True,
                                                        'MinimumProtocolVersion': 'TLSv1'}}}

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


        zid = r53.list_hosted_zones_by_name(
            DNSName=domain,
            MaxItems="1"
        )['HostedZones'][0]['Id']

        eprint("  ZoneID: %s\n" % zid)

        # Fetch existing records, unless we have listed this zone already
        if zid not in this.zonecache:
            recs = r53.list_resource_record_sets(
                HostedZoneId=zid
            )['ResourceRecordSets']

            this.zonecache[zid] = {}
            for r in recs:
                n = r['Name']
                if (r['Type'] not in ['A', 'CNAME']): continue
                this.zonecache[zid][r['Name']] = r


        subdomains=list(this.clients[domain].items())

        if 'www' in this.clients[domain] and 'redirect' in this.services:
            print("Found subdomain 'www', will also create DNS @ for 'redirect' on %s" % domain);
            subdomains.append([False, {'service': 'redirect'}])

        for subdomain, cl in subdomains:

            name = subdomain

            nn = subdomain+'.'+domain+'.'+this.sandbox if subdomain is not False else domain+'.'+this.sandbox

            ## see if record exists, and we have maintenance dns
            fqdn=subdomain+'.'+domain if subdomain is not False else domain

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

                # Distribution exists!
                eprint("  %s -> cloudfront %s\n" % (fqdn, this.cflink[fqdn] ))
                res = r53.change_resource_record_sets(
                    HostedZoneId=zid,
                    ChangeBatch={
                        'Changes': actions
                    }
                )


            elif nn not in this.zonecache[zid]:
                # Create maintenance record (temporarily)

                # TODO - if distribution exists for this domain and is configured correctly, we should update DNS
                # to that distribution



                if this.maintenance_dns:

                    eprint("  %s -> maintenance (while cloudfront is being set-up)\n" % (fqdn ))


                    res = r53.change_resource_record_sets(
                        HostedZoneId=zid,
                        ChangeBatch={
                            'Changes': [ { 
                                'Action': 'CREATE',
                                'ResourceRecordSet': {
                                    'Name': nn,
                                    'Type': 'CNAME',
                                    'TTL': 300,
                                    'ResourceRecords': [ {
                                        'Value': this.maintenance_dns
                                    } ]
                                }
                            } ]
                        }
                    )

    
    #.describe_load_balancers(
    #client.list_hosted_zones_by_name

def request_certificates():
    """
    For all the domains, this will request certificates. Each domain, one certificate.

    example.com will request certificate for example.com with additional name *.example.com and DNS validation.

    The certificate is then usable across all distributions.
    """

    # Get all existing certificates first
    acm=boto3.client('acm', region_name='us-east-1')
    eprint("==[ Fetching ACM data ]==============\n")

    valid_certs = acm.list_certificates(CertificateStatuses=['ISSUED'])['CertificateSummaryList']
    for cert in valid_certs:
        this.certs[cert['DomainName']] = {
            'CertificateArn': cert['CertificateArn'],
            'Status': 'ISSUED'
        }

    pending_certs = acm.list_certificates(CertificateStatuses=['PENDING_VALIDATION'])['CertificateSummaryList']
    for cert in pending_certs:
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

            this.acm_arns[subdomain+'.'+domain]=arn


        if has_all_certs:
            arn = get_cert_arn(domain, None)

            if arn is None:
                has_all_certs = False
            else:
                this.acm_arns[domain]=arn

        if not has_all_certs:

            failprint("%s missing SSL certs. Maybe next time\n" % domain)
            this.clients[domain]=None


def get_cert_arn(domain, subdomain):
    # attempt to find good ARN for this subdomain


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
                print('%s.%s found wildcard %s' % (subdomain, domain, this.certs[domain]['CertificateArn']));

                return this.certs[domain]['CertificateArn']

            if subdomain+'.'+domain in this.certs[domain]['SubjectAlternativeNames']:
                # can use this ARN
                print('%s.%s found as alternative name for %s' % (subdomain, domain, this.certs[domain]['CertificateArn']));

                return this.certs[domain]['CertificateArn']


        # perhaps it's still pending
        if this.certs[domain]['Status'] == 'PENDING_VALIDATION':
            if '*.'+domain in this.certs[domain]['SubjectAlternativeNames']:
                print('%s.%s wildcard in PENDING state %s. Trying to approve' % (subdomain, domain, this.certs[domain]['CertificateArn']));

                approve_cert(domain)

                return None

    if subdomain is not None and subdomain+'.'+domain in this.certs:
        if this.certs[fqdn]['Status'] == 'ISSUED':
            print('%s.%s subdomain found as individual cert %s' % (subdomain, domain, this.certs[fqdn]['CertificateArn']));
            return this.certs[fqdn]['CertificateArn']

    if subdomain is None and domain in this.certs:
        if this.certs[domain]['Status'] == 'ISSUED':
            print('%s found as individual cert %s' % (domain, this.certs[domain]['CertificateArn']));
            return this.certs[domain]['CertificateArn']

    failprint('No suitable certificate for %s. Requesting.\n' % fqdn)
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
        failprint("ResourceRecord is not provided for certificate (%s). Maybe it must be verified through email?", this.certs[domain]['CertificateArn'])
        return

    r53=boto3.client('route53')

    zid = r53.list_hosted_zones_by_name(
        DNSName=domain,
        MaxItems="1"
    )['HostedZones'][0]

    if zid['Name'][:-1] != domain:
        die ("Zone for domain %s is not in Route53\n" % domain)
    
    
    zid = zid['Id']

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

    acm=boto3.client('acm')
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
                eprint('exists\n')
            except:
                eprint('CREATING.. ')

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



def main():
    """huhh"""

    # first discover service end-points
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

    build_distribution_cache()


    request_certificates()

    fullfill_api_gateways()

    update_route53_records()

    validate_distributions(True)


    #update_route53_records()

    #discover_services(read_services_config('service-config.yml'))


    eprint('ALL DONE\n')

