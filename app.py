#!/usr/bin/env python

#############################
# Define Imported Libraries #
#############################

import requests
import argparse
from cmd2 import Cmd, with_argparser, Cmd2ArgumentParser
import cmd2
from aws_requests_auth.aws_auth import AWSRequestsAuth
import pandas as pd


###########################
# Define Global Variables #
###########################

loggedIn = False
auth = 0
role = ""
method = "https://"
url_sysadmin1 = "imbp521xa8.execute-api.us-west-2.amazonaws.com"
url_sysadmin2 = "fcfwijojda.execute-api.us-west-2.amazonaws.com"
url_analyst = "cs4pjw5qb9.execute-api.us-west-2.amazonaws.com"
url_engineer = "7va75w0cr7.execute-api.us-west-2.amazonaws.com"


###############################
# Define Parsers for Commands #
###############################

list_parser = Cmd2ArgumentParser()
list_subparsers = list_parser.add_subparsers(title='subcommands', help='subcommand help')

parser_computer = list_subparsers.add_parser('computers', help='computer help')
parser_computer.add_argument('-b', type=int, help="Business Unit ID number")
parser_computer.add_argument('-s','--severity', type=float, help="Vulnerability Severity score (1-10)")


parser_bu = list_subparsers.add_parser('business_units', help='business_unit help')
parser_bu.add_argument('-b', type=str, default='%', help='Business Unit name')
parser_vuln = list_subparsers.add_parser('vulns', help='vulnerability help')
parser_apps = list_subparsers.add_parser('apps', help='application help')
parser_cve = list_subparsers.add_parser('cve', help='cve help')
parser_users = list_subparsers.add_parser('users', help='users help')


create_parser = Cmd2ArgumentParser()
create_subparsers = create_parser.add_subparsers(title='subcommands', help='subcommand help')
parser_create_computer = create_subparsers.add_parser('computer', help='create a new computer')
parser_create_bu = create_subparsers.add_parser('business_unit', help='create a new business unit')
parser_create_user = create_subparsers.add_parser('user', help='create a new user')
parser_create_cve = create_subparsers.add_parser('cve', help='create a new CVE')


delete_parser = Cmd2ArgumentParser()
delete_subparsers = delete_parser.add_subparsers(title='subcommands', help='subcommand help')
parser_delete_computer = delete_subparsers.add_parser('computer', help='delete a computer')
parser_delete_bu = delete_subparsers.add_parser('business_unit', help='delete a business unit')
parser_delete_user = delete_subparsers.add_parser('user', help='delete a user')
parser_delete_cve = delete_subparsers.add_parser('cve', help='delete a cve')

update_parser = Cmd2ArgumentParser()
update_subparsers = update_parser.add_subparsers(title='subcommands', help='subcommand help')
parser_update_computer = update_subparsers.add_parser('computer', help='update a computer\'s information')
parser_update_bu = update_subparsers.add_parser('business_unit', help='update a business unit\'s information')
parser_update_user = update_subparsers.add_parser('user', help='update a user\'s information')
parser_update_cve = update_subparsers.add_parser('cve', help='update a cve\'s information')

######################################
# Define Class for interactive shell #
######################################

class cvetracker(Cmd):
    def __init__(self):
        super().__init__()
        del Cmd.do_shell
        del Cmd.do_alias
        del Cmd.do_macro
        del Cmd.do_run_pyscript
        del Cmd.do_set
        del Cmd.do_shortcuts
        del Cmd.do_edit
        del Cmd.do_run_script
        del Cmd.do_history

        self.prompt = 'Tracker> '
        """ A CVE tracking software. """

    def do_role(self, args):
        """Print the role of the user"""
        if loggedIn == False:
            self.poutput("Sorry, can't access the database. You are not logged in.")
        else:
            self.poutput(f'Your Role is {role.upper()}')

    def do_login(self, args):
        """Login to AWS account"""
        if( not loggedIn):
            print("Attempting to log you in")
            key = input("Please enter your key: ")
            secret = input("Please enter your secret key: ")
            awsLogin(key, secret)
        else:
            print("You're already logged in.")

    def do_logout(self, args):
        """Logout of AWS account"""
        global loggedIn
        global auth
        global role
        if(loggedIn):
            loggedIn = False
            auth = 0
            role = ""
            print("Successfully logged you out!")
        else:
            print("You aren't logged in.")



    ####################
    # do_list function #
    ####################


    @cmd2.with_argparser(list_parser)
    def do_list(self, args):
        """Test Help Menu"""
        func = getattr(args, 'func', None)
        if func is not None:
            func(self, args)
        else:
            if(loggedIn):
                self.do_help('list')
            else:
                self.poutput("Sorry, can't access the database. You are not logged in.")


    def list_computer(self, args):
        if(loggedIn):
            if role == 'sysadmin1':
                response = requests.get(method + url_sysadmin1 + "/sysadmin1_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                self.poutput(df.to_string())
                self.poutput('\n')
                b_id = input("Which Business Unit would you like to view? (ID NUMBER): ")
                try:
                    data = {'id': int(b_id)}
                    response = requests.get(method + url_sysadmin1 + '/sysadmin1_all_computers_in_one_bu', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['COMPUTER_NAME','COMPUTER_ID'],axis=1,inplace=True)
                    self.poutput('Here are the computers you requested:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except ValueError:
                    print("Please enter a valid integer")
                except KeyError:
                    print("You do not have access to that business unit")
                except IndexError:
                    print("The business unit you requested is empty.")
            elif role == 'sysadmin2':
                response = requests.get(method + url_sysadmin2 + "/sysadmin2_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                self.poutput(df.to_string())
                self.poutput('\n')
                b_id = input("Which Business Unit would you like to view? (ID NUMBER): ")
                try:
                    data = {'id': int(b_id)}
                    response = requests.get(method + url_sysadmin2 + '/sysadmin2_all_computers_in_one_bu', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['COMPUTER_NAME','COMPUTER_ID'],axis=1,inplace=True)
                    self.poutput(f'Here are the computers you requested:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except ValueError:
                    print("Please enter a valid integer")
                except KeyError:
                    print("You do not have access to that business unit")
                except IndexError:
                    print("The business unit you requested is empty.")
            elif role == 'analyst':
                sev = input("Please enter the severity level for CVEs on Computers in the organization (1-10): ")
                try:
                    data = {'values': int(sev)}
                    response = requests.get(method + url_analyst + '/analyst_list_all_info_by_severity', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['CVE', 'SEVERITY', 'COMPUTER_NAME', 'OS', 'OS_VERSION','BUSINESS_UNIT'],axis=1,inplace=True)
                    self.poutput('Here are the computers you requested:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except ValueError:
                    print("Please enter a valid integer")
                except IndexError:
                    print(f"There are no CVEs with severities above {sev}")
            elif role == 'engineer':
                strings = input("Please enter a computer name you'd like to see, or the first portion of the computer name, if you want to see multiple computers that share a common name(leave blank for all computers): ")
                if strings == '' or strings == '%':
                    strings = '%'
                else:
                    strings = strings + '%'
                try:
                    data = {'values': strings}
                    response = requests.get(method + url_engineer + '/engineer_access_computers', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['COMPUTER_NAME', 'OS', 'COMPUTER_ID', 'OS_VERSION', 'BUSINESS_UNIT_ID'],axis=1,inplace=True)
                    self.poutput('Here are the computers you requested:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except IndexError:
                    self.poutput("There are no computers that match that name, or that start with those characters.")
        else:
            self.poutput("You must log in to view this data.")
    parser_computer.set_defaults(func=list_computer)

    def list_bus(self, args):
        if(loggedIn):
            if role == 'sysadmin1':
                response = requests.get(method + url_sysadmin1 + "/sysadmin1_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                df.set_axis(['BUSINESS_UNIT', 'UNIT_ID'],axis=1,inplace=True)
                self.poutput(df.to_string())
                self.poutput('\n')
            elif role == 'sysadmin2':
                response = requests.get(method + url_sysadmin2 + "/sysadmin2_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                df.set_axis(['BUSINESS_UNIT', 'UNIT_ID'],axis=1,inplace=True)
                self.poutput(df.to_string())
                self.poutput('\n')
            elif role == 'analyst':
        # TODO: Enter the Vuln Count table here to see a list of all BUs with vulns
                response = requests.get(method + url_analyst + "/analyst_vuln_count_per_bu", auth=auth)
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                df.set_axis(['BUSINESS_UNIT', 'SEVERITY_(>5.0)'],axis=1,inplace=True)
                self.poutput("Here are the serious vulnerabilities in each business unit (severity > 5.0):")
                self.poutput(df.to_string())
                self.poutput('\n')
                try:
                    bus = input("Enter the Business Unit you'd like to see computers in: (leave blank for all): ")
                    if bus == '' or bus == '%':
                        bus = '%'
                    else:
                        bus = bus + '%'
                    data = {'values': bus}
                    response = requests.get(method + url_analyst + "/analyst_list_all_info_by_bu", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['CVE', 'SEVERITY', 'COMPUTER_NAME', 'OS', 'OS_VERSION', 'BUSINESS UNIT'],axis=1,inplace=True)
                    self.poutput("Here are the vulnerable computers in the business unit")
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except IndexError:
                    print("Either the business unit name is invalid, or the business unit is empty. Please check your entry and try again.")
            elif role == 'engineer':
                try:
                    bus = input("Enter the Business Unit you'd like to see [leave blank for all]: ")
                    if bus == '':
                        bus = '%'
                    data = {'values': bus}
                    response = requests.get(method + url_engineer + "/engineer_access_bus", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['BUSINESS_UNIT', 'BUSINESS_UNIT_ID', 'ADMIN_ID', 'BELONGS_TO'],axis=1,inplace=True)
                    self.poutput("Here are the Business Units you asked for:")
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except IndexError:
                    print("Please enter a valid Business Unit name.")
        else:
            self.poutput("You must log in to view this data.")
    parser_bu.set_defaults(func=list_bus)

    def list_vulns(self, args):
        if(loggedIn):
            if role == 'sysadmin1':
                response = requests.get(method + url_sysadmin1 + "/sysadmin1_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                self.poutput(df.to_string())
                self.poutput('\n')
                b_id = input("Which Business Unit's Vulnerabilities would you like to view? (ID NUMBER): ")
                try:
                    data = {'id': int(b_id)}
                    response = requests.get(method + url_sysadmin1 + '/sysadmin1_all_computer_vulns_by_bu', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['COMPUTER_NAME', 'OS','OS_VERSION','CVE', 'SEVERITY'],axis=1,inplace=True)
                    self.poutput('Here are the vulnerabilities in your business unit:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except ValueError:
                    print("Please enter a valid integer")
                except KeyError:
                    print("You do not have access to that business unit")
                except IndexError:
                    print("The business unit you requested is empty.")
            if role == 'sysadmin2':
                response = requests.get(method + url_sysadmin2 + "/sysadmin2_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                self.poutput(df.to_string())
                self.poutput('\n')
                b_id = input("Which Business Unit's Vulnerabilities would you like to view? (ID NUMBER): ")
                try:
                    data = {'id': int(b_id)}
                    response = requests.get(method + url_sysadmin2 + '/sysadmin2_all_computer_vulns_by_bu', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['COMPUTER_NAME', 'OS','OS_VERSION','CVE', 'SEVERITY'],axis=1,inplace=True)
                    self.poutput('Here are the vulnerabilities in your business unit:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except ValueError:
                    print("Please enter a valid integer")
                except KeyError:
                    print("You do not have access to that business unit")
                except IndexError:
                    print("The business unit you requested is empty.")
            if role == 'analyst':
                response = requests.get(method + url_analyst + "/analyst_vuln_count_per_bu", auth=auth)
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                df.set_axis(['BUSINESS_UNIT', 'SEVERITY_(>5.0)'],axis=1,inplace=True)
                self.poutput("Here are the serious vulnerabilities in each business unit (severity > 5.0):")
                self.poutput(df.to_string())
                self.poutput('\n')
        else:
            self.poutput("You must log in to view this data.")
    parser_vuln.set_defaults(func=list_vulns)

    def list_apps(self, args):
        if(loggedIn):
            if role == 'sysadmin1':
                response = requests.get(method + url_sysadmin1 + "/sysadmin1_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                self.poutput(df.to_string())
                self.poutput('\n')
                b_id = input("Which Business Unit's Computers would you like to view? (ID NUMBER): ")
                try:
                    data = {'id': int(b_id)}
                    response = requests.get(method + url_sysadmin1 + '/sysadmin1_all_computers_in_one_bu', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    self.poutput('Here are the computers in your business unit:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    c_id = input("Which Computer's Apps would you like to view? (ID NUMBER): ")
                    try:
                        data = {'id': int(c_id)}
                        response = requests.get(method + url_sysadmin1 + '/sysadmin1_all_apps_on_computers', auth=auth, json=data)
                        tabledata = response.json()
                        l1,l2 = len(tabledata), len(tabledata[0])
                        df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                        df.set_axis(['COMPUTER_NAME', 'APPLICATION', 'APP_VERSION', 'APP_ID'],axis=1,inplace=True)
                        self.poutput('Here are the computers in your business unit:')
                        self.poutput(df.to_string())
                        self.poutput('\n')
                    except ValueError:
                        print("Please enter a valid integer")
                    except KeyError:
                        print("You do not have access to that computer.")
                    except IndexError:
                        print("The computer you requested has no apps.")
                except ValueError:
                    print("Please enter a valid integer")
                except KeyError:
                    print("You do not have access to that business unit")
                except IndexError:
                    print("The business unit you requested is empty.")
            if role == 'sysadmin2':
                response = requests.get(method + url_sysadmin2 + "/sysadmin2_all_bus_user_manages", auth=auth)
                self.poutput("Here are the Business Units you manage:")
                tabledata = response.json()
                l1,l2 = len(tabledata), len(tabledata[0])
                df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                self.poutput(df.to_string())
                self.poutput('\n')
                b_id = input("Which Business Unit's Computers would you like to view? (ID NUMBER): ")
                try:
                    data = {'id': int(b_id)}
                    response = requests.get(method + url_sysadmin2 + '/sysadmin2_all_computers_in_one_bu', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    self.poutput('Here are the computers in your business unit:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    c_id = input("Which Computer's Apps would you like to view? (ID NUMBER): ")
                    try:
                        data = {'id': int(c_id)}
                        response = requests.get(method + url_sysadmin2 + '/sysadmin2_all_apps_on_computers', auth=auth, json=data)
                        tabledata = response.json()
                        l1,l2 = len(tabledata), len(tabledata[0])
                        df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                        df.set_axis(['COMPUTER_NAME', 'APPLICATION', 'APP_VERSION', 'APP_ID'],axis=1,inplace=True)
                        self.poutput('Here are the computers in your business unit:')
                        self.poutput(df.to_string())
                        self.poutput('\n')
                    except ValueError:
                        print("Please enter a valid integer")
                    except KeyError:
                        print("You do not have access to that computer.")
                    except IndexError:
                        print("The computer you requested has no apps.")
                except ValueError:
                    print("Please enter a valid integer")
                except KeyError:
                    print("You do not have access to that business unit")
                except IndexError:
                    print("The business unit you requested is empty.")
        else:
            self.poutput("You must log in to view this data.")
    parser_apps.set_defaults(func=list_apps)

    def list_cve(self, args):
        if(loggedIn):
            if role == 'analyst':
                try:
                    cves = input("Enter the CVE you'd like to search for (FORMAT = CVE-####-####) [leave blank for all]: ")
                    if cves == '' or cves == '%':
                        cves = '%'
                    else:
                        cves = cves + '%'
                    data = {'values': cves}
                    response = requests.get(method + url_analyst + "/analyst_list_all_info_by_cve", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['CVE', 'SEVERITY', 'COMPUTER_NAME', 'OS', 'OS_VERSION','BUSINESS_UNIT'],axis=1,inplace=True)
                    self.poutput('Here are the computers in your business unit:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except IndexError:
                    self.poutput("Either the CVE does not exist, or that is not a valid CVE.")
                    self.poutput("Please ensure you are using a proper CVE in the format CVE-{YEAR}-{CVEID} or CVE-{YEAR}")
                    self.poutput("If your format is correct, then no computer in your organization has that vulnerability.")
            elif role == 'engineer':
                try:
                    cves = input("Enter the CVE you'd like to search for (FORMAT = CVE-####-####) [leave blank for all]: ")
                    if cves == '' or cves == '%':
                        cves = '%'
                    else:
                        cves = cves + '%'
                    data = {'values': cves}
                    response = requests.get(method + url_engineer + "/engineer_access_cves", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['CVE', 'SEVERITY','VULN_ID'],axis=1,inplace=True)
                    self.poutput('Here are the CVEs in your business unit:')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except IndexError:
                    self.poutput("Either the CVE does not exist, or that is not a valid CVE.")
                    self.poutput("Please ensure you are using a proper CVE in the format CVE-{YEAR}-{CVEID} or CVE-{YEAR}")
                    self.poutput("If your format is correct, then no computer in your organization has that vulnerability.")

            else:
                self.poutput("Your role does not have access to this data.")
        else:
            self.poutput("You must log in to view this data.")
    parser_cve.set_defaults(func=list_cve)

    def list_users(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    user = input('Enter the username whose info you\'d like to see [leave blank for all]: ')
                    if user == '':
                        user = '%'
                    data = {'values': user}
                    response = requests.get(method + url_engineer + '/engineer_access_users', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['USERNAME', 'ROLE', 'FIRST_NAMe', 'LAST_NAME', 'USER_ID'], axis=1,inplace=True)
                    self.poutput('Here are the users in your organization: ')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                except IndexError:
                    self.poutput('That username does not exist. Please enter a valid username.')
            else:
                self.poutput("Your role does not have access to this data.")
        else:
            self.poutput("You must log in to view this data.")
    parser_users.set_defaults(func=list_users)


    ######################
    # do_create function #
    ######################

    @cmd2.with_argparser(create_parser)
    def do_create(self, args):
        """Test Help Menu"""
        func = getattr(args, 'func', None)
        if func is not None:
            func(self, args)
        else:
            if(loggedIn):
                self.do_help('create')
            else:
                self.poutput("Sorry, can't access the database. You are not logged in.")

    def create_computer(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    name = input("Enter the computer's name: ")
                    os = input("Enter the computer's operating system: ")
                    vers = input("Enter the operating system version: ")

                    data = {'values': '%'}
                    response = requests.get(method + url_engineer + "/engineer_access_bus", auth=auth, json=data)
                    self.poutput("Here are the Business Units in your organization::")
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['BUSINESS_UNIT', 'BUSINESS_UNIT_ID', 'ADMIN_ID', 'BELONGS_TO'],axis=1,inplace=True)
                    self.poutput(df.to_string())
                    self.poutput('\n')

                    unitid = input("Please enter the Unit ID from the above table for the Business Unit in which the new computer resides: ")

                    data = {'name': name, 'operatingsystem': os, 'os_version': vers, 'unitid': int(unitid)}
                    response = requests.post(method + url_engineer + '/engineer_access_computers', auth=auth, json=data)
                    print(response.text)
                    self.poutput("Your computer is now added")
                except:
                    print("test")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to view this data.")
    parser_create_computer.set_defaults(func=create_computer)

    def create_business(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    data = {'values': '%'}
                    name = input('Enter the name for the new business unit: ')
                    response = requests.get(method + url_engineer + '/engineer_access_users', auth=auth, json=data)
                    tabledata = response.json()
                    userdatas = []
                    for i in tabledata:
                        userdatas.append(i[4])
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['USERNAME', 'ROLE', 'FIRST_NAME', 'LAST_NAME', 'USER_ID'], axis=1,inplace=True)
                    self.poutput('Here are the users in your organization: ')
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        user = input("Enter the User_ID for the admin to the new business unit: ")
                        if(int(user) not in userdatas):
                            print('That user doesn\'t exist. Please enter an existing user.')
                        else:
                            data = {'name': name, 'administrator': int(user)}
                            response = requests.post(method + url_engineer + '/engineer_access_bus', auth=auth, json=data)
                            self.poutput(response.text)
                            self.poutput('Your business unit is now added')
                    except ValueError:
                        self.poutput("Please enter a valid integer")
                except:
                    print('test2')
            else:
                self.poutput('Your role does not have access to this action')
        else:
            self.poutput("You must log in to view this data.")
    parser_create_bu.set_defaults(func=create_business)
            
    def create_user(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    data = {'values': '%'}
                    response = requests.get(method + url_engineer + '/engineer_access_users', auth=auth, json=data)
                    tabledata = response.json()
                    userdatas = []
                    for i in tabledata:
                        userdatas.append(i[0])
                    name = input("Enter the new user's username: ")
                    if name in userdatas:
                        self.poutput('That username already exists.')
                    else:
                        newrole = input('Enter the new user\'s role: ')
                        first = input('Enter the new user\'s First Name: ')
                        last = input('Enter the new user\'s Last Name: ')

                        data = {'username': name, 'role': newrole, 'firstname': first, 'lastname': last}
                        response = requests.post(method + url_engineer + '/engineer_access_users', auth=auth, json=data)
                        print(response.text)
                        self.poutput("Your user is now added")
                except:
                    print("test")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to view this data.")
    parser_create_user.set_defaults(func=create_user)

    def create_cve(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    cvename = input('Enter the name of the new CVE [Format: CVE-XXXX-XXXX]: ')
                    sev = input('Enter the severity of the CVE [Format: X.X]: ')
                    data = {'cve': cvename, 'severity': float(sev)}
                    response = requests.post(method + url_engineer + '/engineer_access_cves', auth=auth, json=data)
                    print(response.text)
                    self.poutput("Your CVE is now added")
                except ValueError:
                    print("Please enter a valid Float (Decimal point number) for the Severity")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to view this data.")
    parser_create_cve.set_defaults(func=create_cve)

    ######################
    # do_delete function #
    ######################

    @cmd2.with_argparser(delete_parser)
    def do_delete(self, args):
        """Test Help Menu"""
        func = getattr(args, 'func', None)
        if func is not None:
            func(self, args)
        else:
            if(loggedIn):
                self.do_help('delete')
            else:
                self.poutput("Sorry, can't access the database. You are not logged in.")

    def delete_computer(self, args):
        if(loggedIn):
            if role == 'engineer':
                strings = input("Enter a computer name, or the first portion of a computer name, if you want to see multiple computers that share a common name (leave blank for all computers): ")
                if strings == '' or strings == '%':
                    strings = '%'
                else:
                    strings = strings + '%'
                try:
                    data = {'values': strings}
                    response = requests.get(method + url_engineer + '/engineer_access_computers', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['COMPUTER_NAME', 'OS', 'COMPUTER_ID', 'OS_VERSION', 'BUSINESS_UNIT_ID'],axis=1,inplace=True)
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        delid = input("Enter the COMPUTER_ID from the above table of the computer you would like to delete: ")
                        data = {'id': int(delid)}
                        response = requests.delete(method + url_engineer + '/engineer_access_computers', auth=auth, json=data)
                        print(response.text)
                        self.poutput("Your computer is now deleted")
                    except:
                        print("That ID doesn't exist. Please try a different ID number.")
                except IndexError:
                    self.poutput("There are no computers that match that name, or that start with those characters.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_delete_computer.set_defaults(func=delete_computer)

    def delete_bu(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    self.poutput("Here are the Business Units in your organization: ")
                    bus = '%'
                    data = {'values': bus}
                    response = requests.get(method + url_engineer + "/engineer_access_bus", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['BUSINESS_UNIT', 'BUSINESS_UNIT_ID', 'ADMIN_ID', 'BELONGS_TO'],axis=1,inplace=True)
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        bus = input('Enter the Business Unit ID from the above table to delete: ')
                        data = {'id': int(bus)}
                        response = requests.delete(method + url_engineer + '/engineer_access_bus', auth=auth, json=data)
                        print(response.text)
                        self.poutput("Your business unit is now deleted")
                    except:
                        print("That ID doesn't exist. Please try a different ID number.")
                except IndexError:
                    print("Please enter a valid Business Unit name.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_delete_bu.set_defaults(func=delete_bu)
        
    def delete_user(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    userlist = '%'
                    data = {'values': userlist}
                    response = requests.get(method + url_engineer + "/engineer_access_users", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['USERNAME', 'ROLE', 'FIRST_NAME', 'LAST_NAME', 'USER_ID'], axis=1,inplace=True)
                    self.poutput("Here are the users in your organization: ")
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        bus = input('Enter the User ID from the above table to delete: ')
                        data = {'id': int(bus)}
                        response = requests.delete(method + url_engineer + '/engineer_access_users', auth=auth, json=data)
                        print(response.text)
                        self.poutput("The user is now deleted")
                    except:
                        print("That ID doesn't exist. Please try a different ID number.")
                except IndexError:
                    print("Please enter a valid ID number.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_delete_user.set_defaults(func=delete_user)

    def delete_cve(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    cvelist = '%'
                    data = {'values': cvelist}
                    response = requests.get(method + url_engineer + "/engineer_access_cves", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['CVE', 'SEVERITY','VULN_ID'],axis=1,inplace=True)
                    self.poutput("Here are the CVEs in your organization: ")
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        bus = input('Enter the VULN_ID from the above table to delete: ')
                        data = {'id': int(bus)}
                        response = requests.delete(method + url_engineer + '/engineer_access_cves', auth=auth, json=data)
                        print(response.text)
                        self.poutput("The CVE is now deleted")
                    except:
                        print("That ID doesn't exist. Please try a different ID number.")
                except IndexError:
                    print("Please enter a valid ID number.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_delete_cve.set_defaults(func=delete_cve)

    ######################
    # do_update function #
    ######################


    @cmd2.with_argparser(update_parser)
    def do_update(self, args):
        """Test Help Menu"""
        func = getattr(args, 'func', None)
        if func is not None:
            func(self, args)
        else:
            if(loggedIn):
                self.do_help('update')
            else:
                self.poutput("Sorry, can't access the database. You are not logged in.")

    def update_computer(self, args):
        if(loggedIn):
            if role == 'engineer':
                strings = input("Enter a computer name, or the first portion of a computer name, if you want to see multiple computers that share a common name (leave blank for all computers): ")
                if strings == '' or strings == '%':
                    strings = '%'
                else:
                    strings = strings + '%'
                try:
                    data = {'values': strings}
                    response = requests.get(method + url_engineer + '/engineer_access_computers', auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['COMPUTER_NAME', 'OS', 'COMPUTER_ID', 'OS_VERSION', 'BUSINESS_UNIT_ID'],axis=1,inplace=True)
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        delid = input("Enter the COMPUTER_ID from the above table of the computer you would like to update: ")
                        name = input('What is the computer\'s updated name? ')
                        os = input('What is the computer\'s updated OS? ')
                        vers = input("What is the computer's updated OS version? ")
                        unit = input("What is the computer's updated Business Unit ID? ")
                        data = {"name": name, "operatingsystem": os, "os_version": vers, "unitid": int(unit), 'id': int(delid)}
                        response = requests.put(method + url_engineer + '/engineer_access_computers', auth=auth, json=data)
                        print(response.text)
                        self.poutput("Your computer is now updated")
                    except:
                        print("Something unexpected occurred. Please try again.")
                except IndexError:
                    self.poutput("There are no computers that match that name, or that start with those characters.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_update_computer.set_defaults(func=update_computer)


    def update_bu(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    bus = '%'
                    data = {'values': bus}
                    response = requests.get(method + url_engineer + "/engineer_access_bus", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['BUSINESS_UNIT', 'BUSINESS_UNIT_ID', 'ADMIN_ID', 'BELONGS_TO'],axis=1,inplace=True)
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        bu_id = input('Enter the BUSINESS_UNIT_ID from the above table of the business unit you would like to update: ')
                        name = input('What is the business unit\'s updated name?: ')
                        admin = input('What is the updated business unit\'s administraotr\'s ID?: ')
                        data = {'name': name, 'administrator': int(admin), 'id': int(bu_id)}
                        response = requests.put(method + url_engineer + '/engineer_access_bus', auth=auth, json=data)
                        print(response.text)
                        self.poutput('Your business unit is now updated')
                    except:
                        print('Something unexpected occurred. Please try again.')
                except IndexError:
                    print("Please enter a valid Business Unit name.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_update_bu.set_defaults(func=update_bu)


    def update_user(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    users = '%'
                    data = {'values': users}
                    response = requests.get(method + url_engineer + "/engineer_access_users", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['USERNAME', 'ROLE', 'FIRST_NAME', 'LAST_NAME', 'USER_ID'], axis=1,inplace=True)
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        user_id = input('Enter the USER_ID from the above table of the user you would like to update: ')
                        name = input('What is the user\'s updated username?: ')
                        userdatas = []
                        for i in tabledata:
                            userdatas.append(i[0])
                        if name in userdatas:
                            self.poutput('That username already exists')
                        else:
                            newrole = input('What is the user\'s updated role?: ')
                            first = input('What is the user\'s First Name?: ')
                            last = input('What is the user\'s Last Name?: ')
                            data = {'username': name, 'role': newrole, 'firstname': first, 'lastname': last, 'id': int(user_id)}
                            response = requests.put(method + url_engineer + '/engineer_access_users', auth=auth, json=data)
                            print(response.text)
                            self.poutput('The user is now updated')
                    except:
                        print('Something unexpected occurred. Please try again.')
                except IndexError:
                    print("Please enter a valid Business Unit name.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_update_user.set_defaults(func=update_user)

    def update_cve(self, args):
        if(loggedIn):
            if role == 'engineer':
                try:
                    cves = '%'
                    data = {'values': cves}
                    response = requests.get(method + url_engineer + "/engineer_access_cves", auth=auth, json=data)
                    tabledata = response.json()
                    l1,l2 = len(tabledata), len(tabledata[0])
                    df = pd.DataFrame(tabledata, index=['']*l1, columns=['']*l2)
                    df.set_axis(['CVE', 'SEVERITY','VULN_ID'],axis=1,inplace=True)
                    self.poutput(df.to_string())
                    self.poutput('\n')
                    try:
                        vuln_id = input('Enter the VULN_ID from the above table of the CVE you would like to update: ')
                        name = input('What is the CVE\'s updated CVE name?: ')
                        userdatas = []
                        for i in tabledata:
                            userdatas.append(i[0])
                        if name in userdatas:
                            self.poutput('That CVE already exists')
                        else:
                            sev = input('What is the CVE\'s severity: ')
                            data = {'cve': name, 'severity': float(sev), 'id': int(vuln_id)}
                            response = requests.put(method + url_engineer + '/engineer_access_cves', auth=auth, json=data)
                            print(response.text)
                            self.poutput('The CVE is now updated')
                    except:
                        print('Something unexpected occurred. Please try again.')
                except IndexError:
                    print("Please enter a valid CVE name.")
            else:
                self.poutput("Your role does not have access to this action.")
        else:
            self.poutput("You must log in to complete this action.")
    parser_update_cve.set_defaults(func=update_cve)

#############################
# Define AWS Login function #
#############################

def awsLogin(key, secret):
    global loggedIn
    global auth
    global role


    login_list = [url_sysadmin1, url_sysadmin2, url_analyst, url_engineer]
    headers = {'testing': '123abc'}
    resulting_url = ''
    for i in login_list:
        auth = AWSRequestsAuth(aws_access_key=key,
                aws_secret_access_key=secret,
                #aws_host='to36jhw9b1.execute-api.us-west-2.amazonaws.com',
                aws_host=i,
                aws_region='us-west-2',
                aws_service='execute-api')
        response = requests.get(method + i + '/login', auth=auth, headers=headers)
        if response.status_code == requests.codes.ok:
            loggedIn = True
            print("You are now logged in!")
            resulting_url = i
            break
    if resulting_url == login_list[0]:
        role = "sysadmin1"
    elif resulting_url == login_list[1]:
        role = "sysadmin2"
    elif resulting_url == login_list[2]:
        role = "analyst"
    elif resulting_url == login_list[3]:
        role = "engineer"


###################
# Use to Run Code #
###################

if __name__ == '__main__':
    import sys
    c = cvetracker()
    sys.exit(c.cmdloop())
