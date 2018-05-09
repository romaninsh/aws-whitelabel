# -*- coding:utf-8 -*-

# from . import helpers

from __future__ import print_function

from pprint import pprint
import sys
from ruamel.yaml import YAML
from urllib.parse import urlparse
import boto3


this = sys.modules[__name__]

# Set up local valiables
this.services = {}

# Will be set to client Yaml
this.clients = {}

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

this.log_bucket = "ms-qa-logs.s3.amazonaws.com"

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, end="", **kwargs)

def die(*args, **kwargs):
    eprint(*args, **kwargs)
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
            url = ([item for item in l if item['OutputKey'] == 'ServiceEndpoint'][0]['OutputValue'])+"/"+service['function']

            this.services[service['name']] = url


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
    res = cf.list_distributions(

    )
    if res['DistributionList']['IsTruncated']:
        die("Too many distributions. Please implement paginator!")

    res = res['DistributionList']['Items']


    this.cfcache = {}
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

def get_expected_origin(domain, subdomain):
    """
    Given the subdomain definition, figure out how the distribution origin record would
    look like
    """

    c = this.clients[domain][subdomain]

    service = this.services[c['service']]

    service = service.replace('{$domain}', domain).replace('{$subdomain}', subdomain)

    service_parsed = urlparse(service)

    origin = {}
    origin['CustomHeaders'] = {'Quantity':0}

    if service_parsed.scheme == 's3':
        # Create origin for S3

        origin['DomainName']=service_parsed.netloc+".s3.amazonaws.com"
        origin['Id']='MyS3Origin'
        origin['OriginPath'] = service_parsed.path
        origin['S3OriginConfig'] = {'OriginAccessIdentity': ''}

        return origin

    if service_parsed.scheme == 'http' or service_parsed.scheme == 'https':
        origin['DomainName']=service_parsed.netloc+this.sandbox
        origin['Id']='MyOrigin'
        origin['CustomOriginConfig'] = {
            'OriginProtocolPolicy': 'http-only',
            'HTTPPort': 80
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

        # TODO - if delete, then find all matching distributions and schedule them
        # for deletion

        eprint("--[ Validating Distributions for: %s ]---------------\n" % domain)

        for subdomain, client in this.clients[domain].items():

            fqdn = subdomain + "." + domain

            existing = 0

            origin = get_expected_origin(domain, subdomain)


            for cfdns, cf in this.cfcache.items():

                # Skip records that dont match
                if cf['DomainNameSrc'] != fqdn:
                    continue

                if cf['Status'] != 'Deployed':
                    eprint("Found distribution but Status=%s\n" % cf['Status'])
                    existing = -1
                    break

                exitsing+=1

                # matching certificate found. Lets compare Origin with ExpectedOrigin

                if origin != cf['Origin']:
                    eprint(" Update-able distribution: %s -> %s -> %s\n" % (fqdn, cfdns, cf['DomainNameDns']))
                    eprint("old: ", cf['Origin'])
                    eprint("new: ", origin)

                    if not fix: continue

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


            if client['service'] != 'static': 
                eprint("Not sure how to create distribution %s -> %s\n" % (fqdn, this.services[client['service']] ))
                continue

            create_distribution_s3(domain, subdomain)


def create_distribution_s3(domain, subdomain):
    """
    Will create CloudFront distribution for a static site. Destination will be calculated
    according to the config.
    """

    fqdn = (subdomain+'.'+domain+this.sandbox_dot)

    print(get_expected_origin(domain, subdomain))

    cf = boto3.client('cloudfront');
    DistributionConfig = { 
            'CallerReference': 'cr%s' % hash(domain + '.' + subdomain),
            'Comment':"Generated for client %s by V3 (service: %s)" % (domain, subdomain),
            'Aliases':{ 'Items': [fqdn], 'Quantity':1 },
            'Origins':{ 'Items': [ get_expected_origin(domain, subdomain) ], 'Quantity':1 },
            'Enabled':False,
            'DefaultRootObject':"index.html",
            'PriceClass':'PriceClass_100',
            'DefaultCacheBehavior': {
                'TargetOriginId': 'MyS3Origin',
                'TrustedSigners': {'Enabled': False, 'Quantity': 0},
                'MinTTL': 0,
                'ForwardedValues': { 
                    'QueryString': False,
                    'Cookies': { 'Forward': 'none' },
                },
                'ViewerProtocolPolicy': 'allow-all',
            },
            'Logging': {
                'Enabled': True,
                'Bucket': this.log_bucket,
                'Prefix': "%s/" % fqdn,
                'IncludeCookies': False,
            }
        }

    pprint(DistributionConfig)

    """
'Origins': {'Items': [{'CustomHeaders': {'Quantity': 0},
                        'DomainName': 'ms-qa-static.s3.amazonaws.com',
                        'Id': 'MyS3Origin',
                        'OriginPath': '/www.romdev3.mymedsleuth.com',
                        'S3OriginConfig': {'OriginAccessIdentity': ''}}],
             'Quantity': 1}

'Origins': {'Items': [{'CustomHeaders': {'Quantity': 0},
                         'DomainName': 'ms-qa-static.s3.amazonaws.com',
                         'Id': 'myS3Origin',
                         'OriginPath': '/www.livingdonorvm.org',
                         'S3OriginConfig': {'OriginAccessIdentity': ''}}],
              'Quantity': 1},
    """

    res = cf.create_distribution(
        DistributionConfig=DistributionConfig
    )

    pprint(res)
    sys.exit(1)



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
                this.zonecache[zid][r['Name']] = r



        for subdomain in this.clients[domain]:

            name = subdomain

            nn = subdomain+'.'+domain+'.'+this.sandbox

            ## see if record exists, and we have maintenance dns
            if nn not in this.zonecache[zid]:
                # Create maintenance record (temporarily)

                # TODO - if distribution exists for this domain and is configured correctly, we should update DNS
                # to that distribution



                if this.maintenance_dns:

                    eprint("  %s.%s -> maintenance (while cloudfront is being set-up)\n" % (domain, subdomain ))


                    res = r53.change_resource_record_sets(
                        HostedZoneId=zid,
                        ChangeBatch={
                            'Changes': [ { 
                                'Action': 'CREATE',
                                'ResourceRecordSet': {
                                    'Name': nn,
                                    'Type': 'CNAME',
                                    'TTL': 900,
                                    'ResourceRecords': [ {
                                        'Value': this.maintenance_dns
                                    } ]
                                }
                            } ]
                        }
                    )

    
    
    #.describe_load_balancers(
    #client.list_hosted_zones_by_name


def main():
    """huhh"""

    # first discover service end-points
    discover_services(read_yaml_config('service-config.yml')['ServiceConfig'])

    discover_clients(read_yaml_config('client-config.yml')['ClientConfig'])

    # now 


    update_route53_records()

    build_distribution_cache()

    validate_distributions(True)

    #discover_services(read_services_config('service-config.yml'))


