#!/usr/bin/python
# Copyright (c) 2018
# Author: Matt Smith <msmith@paloaltonetworks.com>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import configparser
import logging
import os
import socket
import sys
import time
from logging.handlers import SysLogHandler
import xml.etree.ElementTree as ET

import requests
import urllib3

# Global Variables
__version__ = '1.0.0'

# Configure argparse
parser = argparse.ArgumentParser(
    description='Palo Alto Networks Automated Configuration Backup (Version: ' + __version__ + ')')
parser.add_argument('-c', '--config', help='Define the configuration file', required=True)
parser.add_argument('-l', '--log', help='Define the log file', required=True)
parser.add_argument('-v', '--verbose', help='Enable verbose logging output to the console and log file',
                    action="store_true")

# Map command line arguments
args = parser.parse_args()
api_config = args.config
api_log = args.log
api_verbose = args.verbose

# Create the global logging handler
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
system_fqdn = socket.getfqdn()
log_format = logging.Formatter('[%(asctime)s][%(process)d][%(funcName)s][%(levelname)s] %(message)s',
                               '%Y-%m-%d %H:%M:%S')

# Create the logging handler for writing to a log file
handler_file = logging.FileHandler(api_log)

if api_verbose is True:
    handler_file.setLevel(logging.DEBUG)
else:
    handler_file.setLevel(logging.INFO)

handler_file.setFormatter(log_format)

# Create the logging handler for writing to the console
handler_console = logging.StreamHandler(sys.stdout)

if api_verbose is True:
    handler_console.setLevel(logging.DEBUG)
else:
    handler_console.setLevel(logging.INFO)

handler_console.setFormatter(log_format)

# Add the logging handlers to the logger
log.addHandler(handler_file)
log.addHandler(handler_console)


def main():
    log.info('Palo Alto Networks Automated Configuration Backup (Version: ' + __version__ + ')')
    log.info('------------------------------------------------------------------')

    # Grab global time and format in NATO/ISO8601 format
    time_stamp = time.strftime("%Y%m%d-%H%M%S")

    # Parse and map our configuration files
    log.info('Preparing to read configuration file: ' + api_config)
    config = read_configuration(api_config)

    # Enable/Disable Syslog support
    if 'true' in config['syslog_enabled']:
        configure_syslog(config)
    else:
        log.warning('Syslog support is not enabled!')

    # Enable/Disable SSL/TLS verification
    if 'true' in config['system_verify']:
        log.info('SSL/TLS certification verification is enabled')
        tls_verify = True
    else:
        log.warning('SSL/TLS certification verification is disabled!')
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        tls_verify = False

    # Attempt to retrieve the serial number from the target device
    serial = get_serial(config['target_address'], config['target_key'], tls_verify)

    # Connect to the target device and export the raw XML
    xml = generate_xml(config['target_address'], config['target_key'], serial, config['backup_directory'], time_stamp,
                       tls_verify)

    if xml is True:
        log.info('Successfully retrieved the raw XML configuration')
        log.info('Preparing to export the device-state archive...')

        # Connect to the target device and export the Device State Archive
        dsa = generate_dsa(config['target_address'], config['target_key'], serial, config['backup_directory'], time_stamp,
                           tls_verify)

        if dsa is True:
            log.info('Successfully retrieved the device-state archive')
            log.info('Finished exporting all configuration from: ' + config['target_address'])
            sys.exit(0)

    else:
        log.error('Something went wrong, please consult the log file for more information.')
        sys.exit(1)

    return True


def read_configuration(configuration_file):
    log.debug('Function called with parameter: configuration_file = ' + configuration_file)

    # Create configuration parser handler
    config = configparser.ConfigParser(allow_no_value=True)

    # Check if the configuration file exists, if it does, read the configuration file
    file = os.path.isfile(configuration_file)

    if file is True:
        log.info('Configuration file exists check passed, reading configuration file...')
        config.read(configuration_file)
        log.info('Configuration file read, parsing configuration values...')
    else:
        log.error('Configuration file defined does not exist, exiting...')
        sys.exit(1)

    # Setup our Python dictionary to store configuration values
    conf = {}

    # Map configuration values for the target device
    conf['target_address'] = config.get('target', 'address')
    conf['target_key'] = config.get('target', 'key')
    conf['target_mode'] = config.get('target', 'mode')

    # Map configuration values for the backup configuration
    conf['backup_directory'] = config.get('backup', 'directory')

    # Map configuration values for general system behaviour
    conf['system_version'] = __version__
    conf['system_timeout'] = config.get('system', 'timeout')
    conf['system_verify'] = config.get('system', 'verify')

    # Map configuration values for syslog support
    conf['syslog_enabled'] = config.get('syslog', 'enabled')
    conf['syslog_address'] = config.get('syslog', 'address')
    conf['syslog_port'] = config.get('syslog', 'port')
    conf['syslog_protocol'] = config.get('syslog', 'protocol')
    conf['syslog_facility'] = config.get('syslog', 'facility')

    # Output mapping results to the command line
    log.info(' [Target] Address         = ' + conf['target_address'])
    log.debug('[Target] Key             = ' + conf['target_key'])
    log.info(' [Target] Mode            = ' + conf['target_mode'])
    log.info(' [Backup] Directory       = ' + conf['backup_directory'])
    log.info(' [System] Version         = ' + conf['system_version'])
    log.info(' [System] Timeout         = ' + conf['system_timeout'])
    log.info(' [System] SSL/TLS Verify  = ' + conf['system_verify'])
    log.info(' [Syslog] Enabled         = ' + conf['syslog_enabled'])
    log.info(' [Syslog] Address         = ' + conf['syslog_address'])
    log.info(' [Syslog] Port            = ' + conf['syslog_port'])
    log.info(' [Syslog] Protocol        = ' + conf['syslog_protocol'])
    log.info(' [Syslog] Facility        = ' + conf['syslog_facility'])

    # Return configuration dictionary to main()
    return conf


def generate_xml(target, key, serial, directory, time_stamp, tls_verify):
    log.debug(
        'Function called with parameters: [target = ' + target + ' | key = ' + key + ' | serial = ' + serial + ' | directory = ' + directory + ' | time = ' + time_stamp + ']')
    log.info('Attempting to retrieve the running configuration from: ' + target)

    check = check_directory(directory)

    if check is True:
        log.info('Received true from check_directory() function, continuing...')
    else:
        log.error('Received false from check_directory() function, exiting...')
        sys.exit(1)

    # Set the output filename to reflect [directory]-[time]-[serial]-running-config.xml
    running_config = directory + time_stamp + '-' + serial + '-running-config.xml'
    log.info('Output target: ' + running_config)

    # Construct the API call
    url = 'https://' + target + '/api/?type=export&category=configuration&key=' + key
    log.debug('Constructed URL: ' + url)
    log.info('Preparing to download running configuration from target: ' + target)

    # Execute
    response = requests.get(url, stream=True, verify=tls_verify)

    if response.status_code is '403':
        xml = ET.fromstring(response.content)
        log.debug('XML Response Status: ' + xml.attrib['status'])
        log.debug('XML Response Debug: ' + response.text)
        log.error(xml.find('./result/msg').text)
        log.debug(xml)
        sys.exit(1)
    else:
        log.debug('Got status code back from api: ' + str(response.status_code))

    # Write file to disk
    with open(running_config, 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)

    # Validate if the download was successfully written to disk
    if os.path.isfile(running_config):
        log.info('Successfully downloaded running configuration from: ' + target)
        log.info('Path: ' + running_config)
        return True
    else:
        log.error(running_config + ' was not found')
        return False


def generate_dsa(target, key, serial, directory, time_stamp, tls_verify):
    log.debug(
        'Function called with parameters: [target = ' + target + ' | key = ' + key + ' | serial = ' + serial + ' | directory = ' + directory + ' | time = ' + time_stamp + ']')
    log.info('Attempting to retrieve the device-state archive from: ' + target)

    check = check_directory(directory)

    if check is True:
        log.info('Received true from check_directory() function, continuing...')
    else:
        log.error('Received false from check_directory() function, exiting...')
        sys.exit(1)

    # Set the output filename to reflect [directory]-[time]-[serial]-device-state-archive.tar.gz
    device_state = directory + time_stamp + '-' + serial + '-device-state-archive.tar.gz'
    log.info('Output target: ' + device_state)

    # Construct the API call
    url = 'https://' + target + '/api/?type=export&category=device-state&key=' + key
    log.debug('Constructed URL: ' + url)
    log.info('Preparing to download device-state archive from target: ' + target)

    # Execute
    response = requests.get(url, stream=True, verify=tls_verify)

    if response.status_code is '403':
        xml = ET.fromstring(response.content)
        log.debug('XML Response Status: ' + xml.attrib['status'])
        log.debug('XML Response Debug: ' + response.text)
        log.error(xml.find('./result/msg').text)
        log.debug(xml)
        sys.exit(1)
    else:
        log.debug('Got status code back from api: ' + str(response.status_code))

    # Write file to disk
    with open(device_state, 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)

    # Validate if the download was successfully written to disk
    if os.path.isfile(device_state):
        log.info('Successfully downloaded device-state archive from: ' + target)
        return True
    else:
        log.error(device_state + ' was not found')
        return False


def get_serial(target, key, tls_verify):
    log.debug('Function called with parameters:')
    log.debug('target = ' + target)
    log.debug('key    = ' + key)

    # Retrieve the serial number of the target device
    log.info('Attempting to retrieve the serial number from target: ' + target)
    url = 'https://' + target + '/api/?type=version&key=' + key
    log.debug('Constructed URL: ' + url)

    # Run the API request against the target
    response = requests.get(url, verify=tls_verify)
    log.debug(response.text)

    # Check if the API returned a 200 "success" status code
    if response.status_code is 200:
        log.info('Status code 200 received, validating response...')

        # Parse XML response
        xml = ET.fromstring(response.content)

        # Determine is an error was encountered
        if 'error' in xml.attrib['status']:
            log.debug('XML Response Status: ' + xml.attrib['status'])
            log.debug('XML Response Debug: ' + response.text)
            log.error(xml.find('./result/msg').text)
            log.debug(xml)
            sys.exit(1)
        else:
            # No error detected in XML response, proceed...
            log.debug('XML Response Status: ' + xml.attrib['status'])

            # Retrieve serial number from XML
            serial = xml.find('./result/serial').text
            log.info('Retrieved serial number: ' + serial)

            return serial
    else:
        # Generate an error log
        log.error('Unable to initiate statistics dump generation on target: ' + target)

        # Parse XML response
        xml = ET.fromstring(response.content)

        # Output the error message from the API and exit
        log.error(xml.find('./result/msg').text)
        log.debug(response.text)
        sys.exit(1)


def check_directory(directory):
    log.debug('Function called with parameters: [directory = ' + directory + ']')

    # Perform an initial check to see if the target directory exists
    target = os.path.isdir(directory)

    if target is True:
        log.info('Specified directory check passed for: ' + directory)
        return True
    else:
        log.warning('Specified directory does not exist: ' + directory)
        log.warning('Attempting to create directory...')

        # Attempt to create the directory and check again
        os.makedirs(directory)
        check = os.path.isdir(directory)

        if check is True:
            log.warning('Successfully created directory: ' + directory)
            return True
        else:
            log.error('Could not create directory: ' + directory)
            return False


def configure_syslog(config):
    log.info('Syslog support enabled, configuring...')

    if 'udp' in config['syslog_protocol']:
        sock_type = socket.SOCK_DGRAM
    elif 'tcp' in config['syslog_protocol']:
        sock_type = socket.SOCK_STREAM
    else:
        log.error('Unknown protocol type for syslog, valid types are: udp, tcp')
        sys.exit(1)

    syslog_address = (config['syslog_address'], int(config['syslog_port']))
    handler_syslog = SysLogHandler(address=syslog_address, facility=config['syslog_facility'], socktype=sock_type)

    syslog_format = logging.Formatter(
        'hostname=' + system_fqdn + ', recvtime=%(asctime)s, proc=%(process)d, target=' + config[
            'target_address'] + ', function=%(funcName)s, severity=%(levelname)s, message=%(message)s',
        '%Y-%m-%d-%H:%M:%S')

    handler_syslog.setFormatter(syslog_format)

    if api_verbose is True:
        handler_syslog.setLevel(logging.DEBUG)
    else:
        handler_syslog.setLevel(logging.INFO)

    # Add syslog configuration to the logging handler
    log.addHandler(handler_syslog)
    log.debug(
        'Syslog configured to forward to: ' + config['syslog_address'] + ':' + config['syslog_port'] + '/' +
        config['syslog_protocol'])

    pid = str(os.getpid())
    log.info('Syslog support enabled for process: ' + pid + ' for target: ' + config['target_address'])

    return True


if __name__ == '__main__':
    main()
