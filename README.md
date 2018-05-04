# aws-whitelabel
Script to help you build infrastructure for white-labeling your services. Receive simple YAML file and automates creation of DNS, CloudFront, signed SSL certificates.

## Where is the problem?

If you run services on AWS either through ECS or Lambda - the process of asigning multiple DNS names to your service is always complex
and manual. For example, lets say you run an app that displays a "serivce status page". When you deploy your service, all requests
are handled by load-balancer. 

Now you need all your clients DNS names to be associated with your new service. You need:

 - create DNS records (and possibly DNS zones)
 - create SSL certificates
 - approve your SSL verification by email (or my creating DNS)
 - correcty associate your DNS record (LINK) with your service
 - create cloudfront distributions

If you try to automate the above, you can pretty much forget about CloudFormation. It will roll-back in case of error,
deleting your certificates and possibly hitting limits. CloudFront distributions, which primarily used for the task, take
up to 40 minutes, so must be created simultaniously. Yet there are rate-limits on the APIs, meaning that cloudfront will
fail unless you properly work-around the limits.

Then - if you are thinking about blue-green deployments, things become even more complex, especially if you wist to automate
your CI/CD and restrict access for those who are allowed to register client records or even integrate it with external
system.

## How is this solved

`aws-whitelabel` is a script which handles all the tasks listed above for you in a sustainable and safe way while trying
to preserve resources, do many things in parallel and handle errors gracefully. It also minimize down-time for the
clients.

# How does it work?

You need to provide 2 files to `aws-whitelabel`:

 - client-config.yml - file will contain list of your client domains and which services to configure
 - service-config.yml - contains configuration for your services
 
There are also some command-line options. It is recommended to run this script as a part of deploy pipeline. File
`client-config.yml` can be safely edited by your staff or can even be integrated with UI app or any other process.
 
## Configuring service
 
By adding structure like this inside your `service-config.yml`:
 
``` yaml
ServiceConfig:
 - Name: frontend-v2
   Endpoint: frontend-v2.yourloadbalancer.com
   
 - Name: frontend-v3
   Maintenance: true
   Endpoint: frontend-v3.yourloadbalancer.com
    
 - Name: maintenance
   Endpoint: maintenance.internaldomain.com
   
 - Name: redirect
   Endpoint: redirect.internaldomain.com

 - Name: api
   Lambda: lambda-name-abc

 - Name: static
   Bucket: com.your.static-bucket
   Folder: "static-sites/{$domain}" # can also use {$host}
```

The endpoint DNS names will not be exposed.

## Configuring Clients

The structure of `client-config.yml`:

``` yaml
ClientConfig:
 - Domain: example.com
   Subdomains:
    - Name: www
      Service: fronend-v2
      
    - Name: api
      Service: api

- Domain: example2.com
   Subdomains:
     - Name: www
       Service: static  # files from s3://com.your.static-bucket/static-sites/example2.com/

     - Name: www2
       Service: frontend-v3  # will actually show maintenance page. 
       
```

# Running

Make sure your `aws cli` is installed and both files are present in current folder. Run:

``` 
python3 aws-whitelabel
```

The script will run through the following stages:

 - validate config files.
 - create any missing DNS records pointing them to maintenance service (CNAME). Existing ones won't be touched.
 - create certificate requests with DNS validation.
 - follow-up on DNS validation creating extra DNS records.
 - periodically check for DNS completion. If not complete, continue on the next subdomain.
 - if any subdomain fails, leave it alone proceeding with the other ones.
 - create CloudFront distributions with SSL / DNS information.
 - update DNS records to point to respecitve CloudFront distribution.
 - if any errors occured, list them when exiting with status 2
 
 Re-running the script is possible at any time and all previous failures would be cleaned up.
 
 ## Command-line arguments
 
 ```
   --sandbox=testdomain.com  - will create www.example.com.testdomain.com.
   --create-zones            - will create Route53 zones if not found.
   --delete                  - delete removed clients. Use with caution!!
```

# Scenarios

Plase your client-config.yml inside a S3 bucket and create CloudPipeline which invokes this script.
It will provision all required records for you.

## Security

Use provided .role to make sure script can only do what it's supposed.

## Maintenance

I've included a simple Maintenance service along with Dockerfile and CloudFormation file for ECS cluster which you can deploy. This service will simply show one static page with an image. You can use this as a template when creating your own services.

## Redirect

This service will perform redirect from `example.com` to `www.example.com`. I am also including it for your convenience along with Dockerfile and CloudFormation template.



 
 
 
