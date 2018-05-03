# xml-to-ansible

Python script to convert XML file to Ansible playbook.  Supports tags, Address-Groups, Addresses, Security Policy and Nat Policy

Usage

python xml-to-ansbile.py -h

positional arguments

xpath - xpath for config file

config - path to config file
optional arguments

-h            show this help message and exit

-d DEBUG,             Enable debug level 0 to 3

-tags TAGS            Comma delimited tags. eg. linux,apache,server

python xml-to-ansbile.py "xpath" "configfile" -tag [taglist in csv format]

Example

python xml-to-ansbile "./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']" "test-config.xml"
-t dev-web-svrs
